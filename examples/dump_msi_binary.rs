//! Extract every stream from an MSI's Binary table to disk — the
//! place CustomActions of type 1 / 257 / 3073 store their referenced
//! DLLs (`QTInstallCode.dll`, `QTMSISupport.dll` for QuickTime).
use std::env;
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let path = &args[1];
    let outdir = &args[2];
    std::fs::create_dir_all(outdir)?;
    let bytes = std::fs::read(path)?;
    let cursor = std::io::Cursor::new(&bytes[..]);
    let mut pkg = msi::Package::open(cursor)?;
    if !pkg.has_table("Binary") {
        println!("no Binary table");
        return Ok(());
    }
    let q = msi::Select::table("Binary");
    let names: Vec<String> = pkg
        .select_rows(q)?
        .filter_map(|r| {
            if let msi::Value::Str(name) = &r[0] {
                Some(name.clone())
            } else {
                None
            }
        })
        .collect();
    println!("Binary entries: {}", names.len());
    for name in &names {
        let stream_name = format!("Binary.{name}");
        if let Ok(mut s) = pkg.read_stream(&stream_name) {
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?;
            let out = std::path::Path::new(outdir).join(name);
            std::fs::write(&out, &buf)?;
            println!("  {name}: {} bytes -> {}", buf.len(), out.display());
        } else {
            println!("  {name}: stream missing");
        }
    }
    Ok(())
}
