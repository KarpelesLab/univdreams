//! Dump MSI Directory table — top-down folder hierarchy.
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let path = &args[1];
    let bytes = std::fs::read(path)?;
    let cursor = std::io::Cursor::new(&bytes[..]);
    let mut pkg = msi::Package::open(cursor)?;
    let q = msi::Select::table("Directory");
    let rows: Vec<_> = pkg.select_rows(q)?.collect();
    println!("Directory rows: {}", rows.len());
    let filter = args.get(2).map(String::as_str).unwrap_or("");
    for r in &rows {
        let id = r[0].as_str().unwrap_or("");
        let parent = r[1].as_str().unwrap_or("");
        let default = r[2].as_str().unwrap_or("");
        if filter.is_empty()
            || id.to_lowercase().contains(&filter.to_lowercase())
            || parent.to_lowercase().contains(&filter.to_lowercase())
            || default.to_lowercase().contains(&filter.to_lowercase())
        {
            println!("  {id:40} parent={parent:30} default={default}");
        }
    }
    Ok(())
}
