use std::env;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let path = &args[1];
    let bytes = std::fs::read(path)?;
    let cursor = std::io::Cursor::new(&bytes[..]);
    let mut pkg = msi::Package::open(cursor)?;
    let q = msi::Select::table("Registry");
    let rows: Vec<_> = pkg.select_rows(q)?.collect();
    eprintln!("Registry rows: {}", rows.len());
    let mut codec_related = Vec::new();
    for r in rows.iter() {
        let mut fields = Vec::new();
        for i in 0..r.len() {
            let v = match &r[i] {
                msi::Value::Null => "NULL".to_string(),
                msi::Value::Int(n) => n.to_string(),
                msi::Value::Str(s) => s.clone(),
                _ => "<bin>".to_string(),
            };
            fields.push(v);
        }
        let joined = fields.join("|");
        if joined.contains("Component")
            || joined.contains("Codec")
            || joined.contains("Apple\\Components")
            || joined.contains(".qtx")
            || joined.contains("QTSystem")
        {
            codec_related.push(joined);
        }
    }
    eprintln!("Codec-related registry rows: {}", codec_related.len());
    for r in codec_related.iter().take(40) {
        println!("{r}");
    }
    Ok(())
}
