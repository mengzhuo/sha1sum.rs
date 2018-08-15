extern crate crypto;

use std::io::{Read, BufReader, BufRead};
use std::{env,fs,io,string,process};
use crypto::sha1::Sha1;
use crypto::digest::Digest;

static QUIET_HELP: &'static str = "sha1sum: the --quiet option is meaningful only when verifying checksums
Try 'sha1sum --help' for more information.";

static HELP_MSG: &'static str = "Usage: sha1sum [OPTION]... [FILE]...
Print or check SHA1 (160-bit) checksums.

With no FILE, or when FILE is -, read standard input.

        --help      display this help and exit
    -c, --check     read SHA1 sums from the FILEs and check them

The following five options are useful only when verifying checksums:

    --quiet          don't print OK for each successfully verified file
";

fn main() {

    let mut files = Vec::new();
    let mut check = false;
    let mut quiet = false;

    for arg in env::args().skip(1) {
        match arg.as_ref() {
        "--help" => {
            eprintln!("{}", HELP_MSG);
            return
        },
        "-c" | "--check" => {
            check = true;
        },
        "--quiet" => {
            quiet = true;
        },
        _ =>  files.push(arg)
        }
    }

    if check && !files.is_empty(){
        check_files(files, quiet);
        return;
    }

    if quiet {
        eprintln!("{}", QUIET_HELP);
        process::exit(1);
    }

    if files.is_empty() {
        files.push(String::from("-"))
    }


    for fp in files {
        match sha1sum(&fp) {
            Ok(hex)=> println!("{}  {}", hex, fp),
            Err(err)=> eprintln!("sha1sum: {}: {}", fp, err),
        }
    }
}

fn parse_checksum_file(fp: &String) -> Result<(Vec<string::String>, Vec<string::String>), io::Error> {
        let fd = fs::File::open(fp)?;
        let mut rdr = BufReader::new(fd);
        let mut lines = Vec::new();

        let mut success = Vec::new();
        let mut failed = Vec::new();

        loop {
            let mut line = String::new();
            let n = rdr.read_line(&mut line)?;
            if n == 0 {
                break;
            }
            lines.push(line);
        }

        for line in lines {
            let items:Vec<&str> = line.split_whitespace().collect();
            if items.len() < 2 {
                eprintln!("sha1sum: failed to parse {}", line);
                continue
            }

            let (sha_checksum, sha_file) = (items[0], items[1]);
            let cal_checksum = sha1sum(&String::from(sha_file))?;

            if cal_checksum != sha_checksum {
                failed.push(format!("{}: FAILED", sha_file));
                continue
            }
            success.push(format!("{}: OK", sha_file));
        }

        Ok((success, failed))
}

fn check_files(files: Vec<String>, quiet: bool) {
    for fp in files {
       match  parse_checksum_file(&fp) {
        Ok(result) => {
            let (success, failed) = result;
            if quiet && !failed.is_empty() {
                process::exit(1);
            }

            for line in success {
                println!("{}", line)
            }
            for line in failed {
                println!("{}", line)
            }
        },
        Err(err)=> eprintln!("sha1sum: {}: {}", fp, err),
       }
    }
}

fn sha1sum(fp: &String) -> Result<String, io::Error> {
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
