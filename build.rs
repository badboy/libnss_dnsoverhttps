extern crate cc;

fn main() {
    cc::Build::new()
        .file("src/write_addr.c")
        .compile("write_addr");
}
