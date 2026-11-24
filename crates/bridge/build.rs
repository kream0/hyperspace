// TEMPORARY: prints the workspace Cargo.lock as resolved by CI so it can be
// committed from a machine without a Rust toolchain. Removed before merge.
fn main() {
    let lock = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock.display());
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    if let Ok(text) = std::fs::read_to_string(&lock) {
        for (n, line) in text.lines().enumerate() {
            println!("cargo:warning=LOCK|{n}|{line}|");
        }
        println!("cargo:warning=LOCKEND|{}|", text.lines().count());
    }
}
