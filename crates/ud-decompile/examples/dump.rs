fn main() {
    let path = std::env::args().nth(1).expect("usage: dump <bin>");
    let bytes = std::fs::read(&path).expect("read");
    let elf = ud_format_elf::Elf64File::parse(&bytes).expect("parse");
    let out = ud_decompile::decompile_to_text(&elf).expect("decompile");
    print!("{out}");
}
