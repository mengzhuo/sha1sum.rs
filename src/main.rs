extern crate crypto;

use std::io::Read;
use std::{env,fs,io};
use crypto::sha1::Sha1;
use crypto::digest::Digest;

static HELP_MSG: &'static str = "Usage: sha1sum [OPTION]... [FILE]...
Print or check SHA1 (160-bit) checksums.

With no FILE, or when FILE is -, read standard input.

      --help     display this help and exit
";

fn main() {

    let mut files = Vec::new();

    for arg in env::args().skip(1) {
        match arg.as_ref() {
        "--help" => {
            eprintln!("{}", HELP_MSG);
            return
        },
        _ =>  files.push(arg)
        }
    }

    if files.is_empty() {
        files.push(String::from("-"))
    }

    for fp in files {
        match handle_file(&fp) {
            Ok(hex)=> println!("{}  {}", hex, fp),
            Err(err)=> eprintln!("sha1sum: {}: {}", fp, err),
        }
    }
}

fn handle_file(fp: &String) -> Result<String, io::Error> {
    let mut hasher = Sha1::new();

    let mut f:Box<io::Read> = match fp.as_ref() {
        "-" => Box::new(io::stdin()),
        _ => {
            let fd = fs::File::open(fp)?;
            Box::new(fd)
        },
    };

    let mut buf: [u8; 2048] = [0; 2048];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.input(&buf[..n]);
    }
    let hex = hasher.result_str();
    Ok(hex)
}
