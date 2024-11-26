use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

mod ncm;

#[derive(Serialize, Deserialize, Debug, Parser)]
#[command(author, version, about, long_about = None)]
enum Cli {
    Unboxing(Unboxing),
}

#[derive(Serialize, Deserialize, Debug, Parser)]
struct Unboxing {
    input: String,

    output: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    match cli {
        Cli::Unboxing(unboxing) => {
            let f = |output| ncm::apply(unboxing.input.clone(), output);
            if unboxing.output.is_none() {
                let output = PathBuf::from(&unboxing.input)
                    .parent()
                    .and_then(Path::to_str)
                    .map(|s| s.to_string())
                    .expect("error input path");
                f(output);
            } else {
                f(unboxing.output.unwrap());
            }
        }
    }
}
#[test]
fn test() {
    ncm::apply(".../xxx.ncm".to_string(), ".../".to_string());
}
