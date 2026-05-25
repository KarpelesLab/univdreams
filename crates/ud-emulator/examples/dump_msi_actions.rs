use std::env;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let path = &args[1];
    let bytes = std::fs::read(path)?;
    let cursor = std::io::Cursor::new(&bytes[..]);
    let mut pkg = msi::Package::open(cursor)?;
    for table_name in [
        "CustomAction",
        "InstallExecuteSequence",
        "InstallUISequence",
    ] {
        if !pkg.has_table(table_name) {
            println!("table {table_name}: ABSENT");
            continue;
        }
        let q = msi::Select::table(table_name);
        let rows: Vec<_> = pkg.select_rows(q)?.collect();
        println!("=== {table_name}: {} rows ===", rows.len());
        for r in rows.iter().take(80) {
            let mut fields = Vec::new();
            for i in 0..r.len() {
                let v = match &r[i] {
                    msi::Value::Null => "NULL".to_string(),
                    msi::Value::Int(n) => n.to_string(),
                    msi::Value::Str(s) => format!("{s:?}"),
                    _ => "<binary>".to_string(),
                };
                fields.push(v);
            }
            println!("  {}", fields.join("  |  "));
        }
    }
    Ok(())
}
