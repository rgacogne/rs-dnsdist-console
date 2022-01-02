use std::env;
use std::process;

fn main() {
    sodiumoxide::init().unwrap();

    let mut args = env::args();
    let name = args
        .next()
        .unwrap_or_else(|| "rs-dnsdist-console".to_string());

    let host = args.next().unwrap_or_else(|| {
        println!("usage: {} HOST KEY PORT COMMAND", name);
        process::exit(1);
    });
    let key_b64 = args.next().unwrap_or_else(|| {
        println!("usage: {} HOST KEY PORT COMMAND", name);
        process::exit(1);
    });
    let mut key: [u8; sodiumoxide::crypto::secretbox::KEYBYTES] =
        [0; sodiumoxide::crypto::secretbox::KEYBYTES];
    base64::decode_config_slice(key_b64, base64::STANDARD, &mut key).unwrap_or_else(|error| {
        eprintln!("Unable to decode key: {}", error.to_string());
        process::exit(1);
    });
    let port = args
        .next()
        .unwrap_or_else(|| {
            println!("usage: {} HOST KEY PORT COMMAND", name);
            process::exit(1);
        })
        .parse::<u16>()
        .unwrap_or(5900);
    let command = args.next().unwrap_or_else(|| {
        println!("usage: {} HOST KEY PORT COMMAND", name);
        process::exit(1);
    });

    let content = lib_rs_dnsdist_console::execute_command(host, port, key, command).unwrap();
    println!("{}", content);
}
