fn main() {
    if std::process::Command::new("protoc")
        .arg("--version")
        .output()
        .is_ok()
    {
        prost_build::compile_protos(&["proto/arxia.proto"], &["proto/"])
            .expect("Failed to compile protobuf definitions");
    } else {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let dest_path = std::path::Path::new(&out_dir).join("arxia.rs");
        std::fs::write(&dest_path, "// protoc not found - stub generated\n").unwrap();
        println!("cargo:warning=protoc not found, using stub protobuf module");
    }
}
