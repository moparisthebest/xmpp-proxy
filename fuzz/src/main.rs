#[macro_use]
extern crate afl;
extern crate xmpp_proxy;

use std::io;
use std::io::Cursor;

use tokio::runtime::Runtime;

use xmpp_proxy::{StanzaFilter, StanzaReader};

fn main_gen_test_cases() {
    fuzz!(|data: &[u8]| {
        let rt = Runtime::new().unwrap();

        rt.block_on(async {
            let mut filter = StanzaFilter::new(262_144);
            let mut stanza_reader = StanzaReader(Cursor::new(data));
            while let Ok(Some(stanza)) = stanza_reader.next(&mut filter).await {
                use rxml::EventRead;
                let mut fp = rxml::FeedParser::new();
                let stanza_vec = &stanza.to_vec();
                fp.feed(stanza_vec);
                fp.feed_eof();
                let result = fp.read_all_eof(|_ev| {
                    //println!("got event: {:?}", ev);
                });
                // true indicates eof
                if let Ok(result) = result {
                    if result {
                        // wow, afl generated us valid XML, lets output it as a test case
                        let fname = sha256::digest_bytes(&stanza);
                        std::fs::create_dir_all("/tmp/afl_test_gen/").unwrap();
                        std::fs::write("/tmp/afl_test_gen/".to_owned() + &fname, &stanza).unwrap();
                    } else {
                        // more data is required, stanzafilter should never let this happen, let's panic
                        panic!("more data required?");
                    }
                }
            }
        })
    });
}

fn main() {
    fuzz!(|data: &[u8]| {
        let rt = Runtime::new().unwrap();

        rt.block_on(async {
            let mut filter = StanzaFilter::new(262_144);
            let mut stanza_reader = StanzaReader(Cursor::new(data));
            while let Ok(Some(_stanza)) = stanza_reader.next(&mut filter).await {
                //ret.push(to_str(stanza).to_string());
            }
        })
    });
}
