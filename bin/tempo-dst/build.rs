use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=TEMPO_DST_VALIDATORS");
    let count: u8 = env::var("TEMPO_DST_VALIDATORS")
        .unwrap_or_else(|_| "4".into())
        .parse()
        .expect("TEMPO_DST_VALIDATORS must be a number");
    assert!(
        (1..=20).contains(&count),
        "TEMPO_DST_VALIDATORS must be 1-20"
    );
    let mut source = format!("pub const VALIDATORS: u8 = {count};\n");
    for (name, value) in [
        ("RPC_URLS", "http://10.89.77.{}:8545"),
        ("METRICS_URLS", "http://10.89.77.{}:8002/metrics"),
        ("CONTAINERS", "v{}"),
    ] {
        source.push_str(&format!("const {name}: [&str; {count}] = [\n"));
        for node in 1..=count {
            let number = if name == "CONTAINERS" {
                node
            } else {
                10 + node
            };
            source.push_str(&format!(
                "    \"{}\",\n",
                value.replace("{}", &number.to_string())
            ));
        }
        source.push_str("];\n");
    }
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("cluster_nodes.rs"),
        source,
    )
    .unwrap();
}
