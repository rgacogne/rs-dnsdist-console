use std::convert::TryInto;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use thiserror::Error;

/// DnsdistConsoleError enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum DnsdistConsoleError {
    #[error(transparent)]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error("connection eror: `{0}`")]
    TransportError(String),

    /// Represents all other cases of `std::io::Error`.
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

/// Connects to a remote dnsdist console and executes a command
///
/// # Arguments
///
/// * `host` - A string holding the network address of the dnsdist server (IPv4 or IPv6)
/// * `port` - The port of the console on the remote server
/// * `key` - An array of `sodiumoxide::crypto::secretbox::KEYBYTES` bytes holding the pre-shared key used to encrypt exchanges with the server
/// * `command` - A string holding the command to execute
pub fn execute_command(
    host: String,
    port: u16,
    key: [u8; sodiumoxide::crypto::secretbox::KEYBYTES],
    command: String,
) -> Result<String, DnsdistConsoleError> {
    let addr = SocketAddr::new(host.as_str().parse()?, port);
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(stream) => stream,
        Err(err) => return Err(DnsdistConsoleError::IOError(err)),
    };
    stream.set_nodelay(true)?;

    let mut our_nonce: [u8; sodiumoxide::crypto::secretbox::NONCEBYTES] =
        [0; sodiumoxide::crypto::secretbox::NONCEBYTES];
    sodiumoxide::randombytes::randombytes_into(&mut our_nonce);
    stream.write_all(&our_nonce)?;

    let mut remote_nonce: [u8; sodiumoxide::crypto::secretbox::NONCEBYTES] =
        [0; sodiumoxide::crypto::secretbox::NONCEBYTES];
    match stream.read_exact(&mut remote_nonce) {
        Ok(usize) => usize,
        Err(e) => {
            return Err(DnsdistConsoleError::TransportError(format!(
                "Error reading nonce: {}",
                e.to_string()
            )))
        }
    };
    let mut reading_nonce_buf: [u8; sodiumoxide::crypto::secretbox::NONCEBYTES] =
        [0; sodiumoxide::crypto::secretbox::NONCEBYTES];
    reading_nonce_buf[..sodiumoxide::crypto::secretbox::NONCEBYTES / 2]
        .copy_from_slice(&our_nonce[0..sodiumoxide::crypto::secretbox::NONCEBYTES / 2]);
    reading_nonce_buf[sodiumoxide::crypto::secretbox::NONCEBYTES / 2..].copy_from_slice(
        &remote_nonce[sodiumoxide::crypto::secretbox::NONCEBYTES / 2
            ..sodiumoxide::crypto::secretbox::NONCEBYTES],
    );

    let reading_nonce = sodiumoxide::crypto::secretbox::Nonce(reading_nonce_buf);

    let mut writing_nonce_buf: [u8; sodiumoxide::crypto::secretbox::NONCEBYTES] =
        [0; sodiumoxide::crypto::secretbox::NONCEBYTES];
    writing_nonce_buf[..sodiumoxide::crypto::secretbox::NONCEBYTES / 2]
        .copy_from_slice(&remote_nonce[0..sodiumoxide::crypto::secretbox::NONCEBYTES / 2]);
    writing_nonce_buf[sodiumoxide::crypto::secretbox::NONCEBYTES / 2..].copy_from_slice(
        &our_nonce[sodiumoxide::crypto::secretbox::NONCEBYTES / 2
            ..sodiumoxide::crypto::secretbox::NONCEBYTES],
    );

    let writing_nonce = sodiumoxide::crypto::secretbox::Nonce(writing_nonce_buf);

    let secret_key = sodiumoxide::crypto::secretbox::xsalsa20poly1305::Key(key);
    let ciphertext =
        sodiumoxide::crypto::secretbox::seal(command.as_bytes(), &writing_nonce, &secret_key);

    let mut data_size: u32 = ciphertext.len().try_into().unwrap();

    match stream.write_all(&data_size.to_be_bytes()) {
        Ok(usize) => usize,
        Err(e) => {
            return Err(DnsdistConsoleError::TransportError(format!(
                "Error writing command size: {}",
                e.to_string()
            )))
        }
    };
    match stream.write_all(&ciphertext) {
        Ok(usize) => usize,
        Err(e) => {
            return Err(DnsdistConsoleError::TransportError(format!(
                "Error writing command: {}",
                e.to_string()
            )))
        }
    };

    let mut len_buffer: [u8; 4] = [0; 4];
    match stream.read_exact(&mut len_buffer) {
        Ok(usize) => usize,
        Err(e) => {
            return Err(DnsdistConsoleError::TransportError(format!(
                "Error reading response size: {}",
                e.to_string()
            )))
        }
    };

    data_size = u32::from_be_bytes(len_buffer);

    let mut reading_buffer = vec![0_u8; data_size.try_into().unwrap()];

    match stream.read_exact(&mut reading_buffer) {
        Ok(usize) => usize,
        Err(e) => {
            return Err(DnsdistConsoleError::TransportError(format!(
                "Error reading response: {}",
                e.to_string()
            )))
        }
    };
    let cleartext =
        sodiumoxide::crypto::secretbox::open(&reading_buffer, &reading_nonce, &secret_key);

    Ok(String::from_utf8(cleartext.unwrap()).unwrap())
}
