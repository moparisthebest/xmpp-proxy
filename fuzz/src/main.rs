use std::io::{Cursor, Write};
use tokio::runtime::Runtime;
use xmpp_proxy::stanzafilter::{StanzaFilter, StanzaReader};

fn main() {
    std::fs::create_dir_all("/tmp/afl_test_gen/").unwrap();
    afl::fuzz!(|data: &[u8]| {
        let rt = Runtime::new().unwrap();

        rt.block_on(async {
            let mut filter = StanzaFilter::new(262_144);
            let mut stanza_reader = StanzaReader(Cursor::new(data));
            while let Ok(Some(stanza)) = stanza_reader.next(&mut filter).await {
                let mut fp = rxml::FeedParser::default();
                let result = rxml::as_eof_flag(fp.parse_all(&mut &stanza[..], true, |_ev| {
                    //println!("got event: {:?}", ev);
                }));
                // true indicates eof
                if let Ok(result) = result {
                    if result {
                        // wow, afl generated us valid XML, lets output it as a test case
                        let fname = sha256::digest(stanza);
                        if let Ok(mut file) = std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create_new(true)
                            .open("/tmp/afl_test_gen/".to_owned() + fname.as_str())
                        {
                            file.write_all(stanza).unwrap();
                            file.sync_all().unwrap();
                        }
                    } else {
                        // more data is required, stanzafilter should never let this happen, let's panic
                        panic!("more data required?");
                    }
                }
            }
        })
    });
}
