use cxx_build::CFG;

fn main() {
    CFG.include_prefix = "vodozemac";
    cxx_build::bridge("src/lib.rs")
        .std("c++20")
        .compile("vodozemac");
}
