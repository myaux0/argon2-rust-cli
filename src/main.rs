use argon2_rust::params::{Memory, TagLen};
use argon2_rust::{Algorithm, Argon2, Params, Version};
use clap::{ArgGroup, Parser};
use rand_core::RngCore;
use std::io::{self, IsTerminal, Read, Write};
use zeroize::Zeroizing;

// Usage:  argon2-rust-cli [-h] salt [-i|-d|-id] [-t iterations] [-m log2(memory in KiB) | -k memory in KiB] [-p parallelism] [-l hash length] [-e|-r] [-v (10|13)]
#[derive(Parser, Debug)]
#[command(
    name = "argon2-rust-cli",
    about = "(Rust implementation using argon2-rust)",
    disable_help_flag = false
)]
#[command(group(ArgGroup::new("variant").args(&["i", "d", "id"])))]
#[command(group(ArgGroup::new("memory").args(&["m", "k"])))]
#[command(group(ArgGroup::new("output_format").args(&["e", "r"])))]
struct Args {
    /// The salt to use (optional, a random salt is generated if omitted; minimum 8 characters)
    salt: Option<String>,

    /// Use Argon2i (this is the default)
    #[arg(short = 'i', long, default_value_t = false)]
    i: bool,

    /// Use Argon2d instead of Argon2i
    #[arg(short = 'd', long, default_value_t = false)]
    d: bool,

    /// Use Argon2id instead of Argon2i
    #[arg(long = "id", default_value_t = false)]
    id: bool,

    /// Sets the number of iterations to N (default = 3)
    #[arg(short = 't', default_value_t = 3)]
    t: u32,

    /// Sets the memory usage of 2^N KiB (default 12)
    #[arg(short = 'm', default_value_t = 12)]
    m: u32,

    /// Sets the memory usage of N KiB (default 4096)
    #[arg(short = 'k')]
    k: Option<u32>,

    /// Sets parallelism to N threads (default 1)
    #[arg(short = 'p', default_value_t = 1)]
    p: u32,

    /// Sets hash output length to N bytes (default 32)
    #[arg(short = 'l', default_value_t = 32)]
    l: u32,

    /// Output only encoded hash
    #[arg(short = 'e', default_value_t = false)]
    e: bool,

    /// Output only the raw bytes of the hash
    #[arg(short = 'r', default_value_t = false)]
    r: bool,

    /// Argon2 version (10 or 13, default: 13)
    #[arg(short = 'v', default_value_t = 13)]
    v: u32,
}

fn get_input() -> io::Result<Zeroizing<Vec<u8>>> {
    let stdin = io::stdin();

    if stdin.is_terminal() {
        print!("Enter password: ");
        io::stdout().flush()?;

        let mut input = Zeroizing::new(String::new());
        stdin.read_line(&mut input)?;
        // Strip only the newline from pressing Enter, keep other whitespace
        while input.ends_with('\n') || input.ends_with('\r') {
            input.pop();
        }
        Ok(Zeroizing::new(input.as_bytes().to_vec()))
    } else {
        // Read stdin verbatim (including any trailing newline) to match the reference implementation
        let mut input = Zeroizing::new(Vec::new());
        stdin.lock().read_to_end(&mut input)?;
        Ok(input)
    }
}

fn validate_salt(salt: &str) -> Result<(), String> {
    if salt.len() < 8 {
        return Err("Invalid salt: minimum length is 8 characters".to_string());
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Handle the non-standard `-id` flag which conflicts with clap's short flag clustering
    let args_env = std::env::args();
    let new_args: Vec<String> = args_env
        .map(|arg| {
            if arg == "-id" {
                "--id".to_string()
            } else {
                arg
            }
        })
        .collect();

    let args = Args::parse_from(new_args);

    let salt = match &args.salt {
        Some(salt) => {
            validate_salt(salt)?;
            salt.as_bytes().to_vec()
        }
        None => {
            let mut salt = vec![0u8; argon2_rust::RANDOM_SALT_LEN];
            rand_core::OsRng.fill_bytes(&mut salt);
            salt
        }
    };

    let password = get_input().map_err(|e| format!("Error reading input: {}", e))?;

    // Select algorithm variant
    let algorithm = if args.d {
        Algorithm::Argon2d
    } else if args.id {
        Algorithm::Argon2id
    } else {
        Algorithm::Argon2i
    };

    // Calculate memory cost
    let memory_kib = if let Some(k) = args.k { k } else { 1 << args.m };

    let params = Params::builder()
        .memory(Memory::kib(memory_kib as u64))
        .passes(args.t)
        .lanes(args.p)
        .tag_len(TagLen::bytes(args.l as u64))
        .build()
        .map_err(|e| format!("Invalid parameters: {}", e))?;

    let version = match args.v {
        10 => Version::V0x10,
        13 => Version::V0x13,
        _ => return Err(format!("Invalid version: {} (expected 10 or 13)", args.v).into()),
    };

    let argon2 = Argon2::new(algorithm, version, params);

    let start = std::time::Instant::now();

    let mut hash = Zeroizing::new(vec![0u8; args.l as usize]);
    argon2
        .hash_into(&password, &salt, &mut hash)
        .map_err(|e| format!("Hashing failed: {}", e))?;

    let password_hash = argon2_rust::encode_string_alloc(algorithm, version, &params, &salt, &hash)
        .map_err(|e| format!("Encoding failed: {}", e))?;

    let duration = start.elapsed();

    // Generate output based on flags
    if args.e {
        println!("{}", password_hash);
    } else if args.r {
        println!("{}", hex::encode(hash.as_slice()));
    } else {
        println!("Type:           {:?}", algorithm);
        println!("Iterations:     {}", args.t);
        println!("Memory:         {} KiB", memory_kib);
        println!("Parallelism:    {}", args.p);

        println!("Hash:           {}", hex::encode(hash.as_slice()));
        println!("Encoded:        {}", password_hash);

        println!("{:.3} seconds", duration.as_secs_f64());

        Argon2::verify_encoded(&password_hash, &password, algorithm)
            .map_err(|e| format!("Verification failed: {}", e))?;
        println!("Verification ok");
    }

    Ok(())
}
