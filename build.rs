use std::{env, fs::File, io::Write, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("version.rs");

    let mut w = File::create(dest_path).unwrap();

    let allowed_features = [
        "c2s-incoming",
        "c2s-outgoing",
        "s2s-incoming",
        "s2s-outgoing",
        "tls",
        "quic",
        "websocket",
        "tls-ca-roots-native",
        "tls-ca-roots-bundled",
    ];
    let optional_deps = [
        "rustls",
        "tokio-rustls",
        "rustls-pemfile",
        "quinn",
        "tokio-tungstenite",
        "futures-util",
        "trust-dns-resolver",
        "reqwest",
        "lazy-static",
        "rustls-native-certs",
        "webpki-roots",
        "env-logger",
        "rand",
    ];
    let mut features = Vec::new();
    let mut optional = Vec::new();
    for (mut key, value) in env::vars() {
        //writeln!(&mut w, "{key}: {value}", ).unwrap();
        if value == "1" && key.starts_with("CARGO_FEATURE_") {
            let mut key = key.split_off(14).replace('_', "-");
            key.make_ascii_lowercase();
            if allowed_features.contains(&key.as_str()) {
                features.push(key);
            } else if optional_deps.contains(&key.as_str()) {
                optional.push(key);
            }
        }
    }
    features.sort_by(|a, b| {
        allowed_features
            .iter()
            .position(|&r| r == a)
            .unwrap()
            .partial_cmp(&allowed_features.iter().position(|&r| r == b).unwrap())
            .unwrap()
    });
    optional.sort_by(|a, b| {
        optional_deps
            .iter()
            .position(|&r| r == a)
            .unwrap()
            .partial_cmp(&optional_deps.iter().position(|&r| r == b).unwrap())
            .unwrap()
    });
    let features = features.join(",");
    let optional = optional.join(",");

    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");

    let target = env::var("TARGET").unwrap();

    writeln!(
        &mut w,
        "{{println!(
\"{name} {version} ({target})
Features: {features}
Optional crates: {optional}\");}}"
    )
    .unwrap();
}
