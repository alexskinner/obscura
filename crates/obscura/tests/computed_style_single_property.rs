// getComputedStyle used to build all 114 properties, serialise ~2.7KB of JSON
// and hand it to JS to parse -- to answer `.display`. That was ~160us per
// distinct element against Chrome's ~0.001ms, and it is the single largest
// gap on real pages, where framework code reads one or two properties across
// thousands of elements.
//
// Reading one property now computes one property. These tests pin the
// behaviour that makes that safe: the fast path must agree with the full walk,
// and enumerating the declaration must still work after a single-property read
// (the two share a cache, and an early version returned an empty declaration
// in exactly that order).

use std::io::{Read, Write};

use obscura::Browser;

fn spawn_server() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else { continue };
            std::thread::spawn(move || {
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request);
                let body = r#"<!doctype html><html><head><title>fixture</title>
<style>#set{color:rgb(0,0,255);font-style:italic;width:120px;float:left}</style>
</head><body style="margin:0">
<div id="set">x</div><div id="plain">y</div>
<table id="t"><tr><td id="td">c</td></tr></table>
</body></html>"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body,
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.shutdown(std::net::Shutdown::Both);
            });
        }
    });
    format!("http://{}", addr)
}

#[cfg(feature = "render")]
#[tokio::test(flavor = "current_thread")]
async fn single_property_reads_agree_with_the_whole_declaration() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    let base = spawn_server();
    let browser = Browser::new().unwrap();
    let mut page = browser.new_page().await.unwrap();
    page.goto(&base).await.unwrap();

    let probes = page.evaluate(
        r#"(function () {
            var set = document.getElementById('set');
            var plain = document.getElementById('plain');
            var td = document.getElementById('td');

            // Single-property reads FIRST, so the full enumeration below runs
            // against a cache primed only with individual properties.
            var single = {
              color: getComputedStyle(set).color,
              fontStyle: getComputedStyle(set).fontStyle,
              float: getComputedStyle(set).getPropertyValue('float'),
              display_td: getComputedStyle(td).display,
              display_plain: getComputedStyle(plain).display
            };

            // Now enumerate. This must not come back empty.
            var cs = getComputedStyle(set);
            var length = cs.length;
            var names = [];
            for (var i = 0; i < Math.min(length, 500); i++) names.push(cs.item(i));

            // ... and every enumerated property must equal what a fresh
            // single read returns.
            var mismatches = [];
            for (var j = 0; j < names.length; j++) {
              var n = names[j];
              if (!n) continue;
              var whole = cs.getPropertyValue(n);
              var one = getComputedStyle(document.getElementById('set')).getPropertyValue(n);
              if (whole !== one) mismatches.push(n + ': ' + whole + ' != ' + one);
            }

            // A mutation must invalidate: the memo is per element per epoch.
            set.style.color = 'rgb(255, 0, 0)';
            var afterMutation = getComputedStyle(set).color;

            return { single: single, length: length, names: names.length,
                     mismatches: mismatches.slice(0, 5), afterMutation: afterMutation };
        })()"#,
    );

    assert_eq!(probes["single"]["color"], "rgb(0, 0, 255)");
    assert_eq!(probes["single"]["fontStyle"], "italic");
    assert_eq!(probes["single"]["float"], "left");
    assert_eq!(probes["single"]["display_td"], "table-cell");
    assert_eq!(probes["single"]["display_plain"], "block");

    // The regression that the shared cache invites: enumeration after a
    // single-property read.
    assert!(
        probes["length"].as_u64().unwrap_or(0) > 50,
        "declaration enumerated {} properties after single-property reads",
        probes["length"]
    );
    assert_eq!(
        probes["mismatches"].as_array().map(Vec::len),
        Some(0),
        "single reads disagree with the enumerated declaration: {:?}",
        probes["mismatches"]
    );

    // Stale-after-mutation is the other way this cache can be wrong.
    assert_eq!(probes["afterMutation"], "rgb(255, 0, 0)");
}
