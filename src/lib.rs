use std::convert::TryInto;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use thiserror::Error;

/// DNSDistConsoleError enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum DNSDistConsoleError {
    #[error(transparent)]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error("connection eror: `{0}`")]
    TransportError(String),

    /// Represents all other cases of `std::io::Error`.
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

/// An encrypted connection to a dnsdist console
pub struct DNSDistConsole {
    stream: TcpStream,
    writing_nonce: sodiumoxide::crypto::secretbox::Nonce,
    reading_nonce: sodiumoxide::crypto::secretbox::Nonce,
    secret_key: sodiumoxide::crypto::secretbox::xsalsa20poly1305::Key
}

impl DNSDistConsole {
    /// Connects to a remote DNSDist console over an encrypted connection and returns a DNSDistConsole object
    ///
    /// # Arguments
    ///
    /// * `host` - A string holding the network address of the DNSDist server (IPv4 or IPv6)
    /// * `port` - The port of the console on the remote server
    /// * `key` - An array of `sodiumoxide::crypto::secretbox::KEYBYTES` bytes holding the pre-shared key used to encrypt exchanges with the server
    pub fn new(
        host: String,
        port: u16,
        key: [u8; sodiumoxide::crypto::secretbox::KEYBYTES]
    ) -> Result<DNSDistConsole, DNSDistConsoleError> {

        let addr = SocketAddr::new(host.as_str().parse()?, port);
        let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(stream) => stream,
            Err(err) => return Err(DNSDistConsoleError::IOError(err)),
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
                return Err(DNSDistConsoleError::TransportError(format!(
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

        let mut writing_nonce_buf: [u8; sodiumoxide::crypto::secretbox::NONCEBYTES] =
            [0; sodiumoxide::crypto::secretbox::NONCEBYTES];
        writing_nonce_buf[..sodiumoxide::crypto::secretbox::NONCEBYTES / 2]
            .copy_from_slice(&remote_nonce[0..sodiumoxide::crypto::secretbox::NONCEBYTES / 2]);
        writing_nonce_buf[sodiumoxide::crypto::secretbox::NONCEBYTES / 2..].copy_from_slice(
            &our_nonce[sodiumoxide::crypto::secretbox::NONCEBYTES / 2
                ..sodiumoxide::crypto::secretbox::NONCEBYTES],
        );

        Ok(DNSDistConsole {
            stream,
            writing_nonce: sodiumoxide::crypto::secretbox::Nonce(writing_nonce_buf),
            reading_nonce: sodiumoxide::crypto::secretbox::Nonce(reading_nonce_buf),
            secret_key: sodiumoxide::crypto::secretbox::xsalsa20poly1305::Key(key)
        })
    }

    /// Sends a command to a dnsdist server over an existing encrypted connection
    ///
    /// # Arguments
    ///
    /// * `command` - A string holding the command to execute
    pub fn send(
        &mut self,
        command: String
    ) -> Result<(), DNSDistConsoleError> {
            let ciphertext =
                sodiumoxide::crypto::secretbox::seal(command.as_bytes(), &self.writing_nonce, &self.secret_key);

            let data_size: u32 = ciphertext.len().try_into().unwrap();

            match self.stream.write_all(&data_size.to_be_bytes()) {
                Ok(usize) => usize,
                Err(e) => {
                    return Err(DNSDistConsoleError::TransportError(format!(
                        "Error writing command size: {}",
                        e.to_string()
                    )))
                }
            };
            match self.stream.write_all(&ciphertext) {
                Ok(usize) => usize,
                Err(e) => {
                    return Err(DNSDistConsoleError::TransportError(format!(
                        "Error writing command: {}",
                        e.to_string()
                    )))
                }
            };
            DNSDistConsole::increment_nonce_inplace(&mut self.writing_nonce.0);

            Ok(())
        }

    /// Receives a response from a dnsdist server over an existing encrypted connection
    pub fn receive(
        &mut self
    ) -> Result<String, DNSDistConsoleError> {
        let mut len_buffer: [u8; 4] = [0; 4];
        match self.stream.read_exact(&mut len_buffer) {
            Ok(usize) => usize,
            Err(e) => {
                return Err(DNSDistConsoleError::TransportError(format!(
                    "Error reading response size: {}",
                    e.to_string()
                )))
            }
        };

        let data_size = u32::from_be_bytes(len_buffer);

        let mut reading_buffer = vec![0_u8; data_size.try_into().unwrap()];

        match self.stream.read_exact(&mut reading_buffer) {
            Ok(usize) => usize,
            Err(e) => {
                return Err(DNSDistConsoleError::TransportError(format!(
                    "Error reading response: {}",
                    e.to_string()
                )))
            }
        };
        let cleartext =
            sodiumoxide::crypto::secretbox::open(&reading_buffer, &self.reading_nonce, &self.secret_key);
        DNSDistConsole::increment_nonce_inplace(&mut self.reading_nonce.0);

        Ok(String::from_utf8(cleartext.unwrap()).unwrap())
    }

    fn increment_nonce_inplace(nonce: &mut [u8]) {
        if nonce.len() < 4 {
            panic!("invalid nonce size");
        }
        let ptr : *mut u8 = nonce.as_mut_ptr();
        let ptr : *mut u32 = ptr as *mut u32;
        unsafe {
            let mut value = (*ptr).to_be();
            value += 1;
            *ptr = u32::from_be(value);
        }
    }
}

/// Connects to a remote DNSDist console and executes a command
///
/// # Arguments
///
/// * `host` - A string holding the network address of the DNSDist server (IPv4 or IPv6)
/// * `port` - The port of the console on the remote server
/// * `key` - An array of `sodiumoxide::crypto::secretbox::KEYBYTES` bytes holding the pre-shared key used to encrypt exchanges with the server
/// * `command` - A string holding the command to execute
pub fn execute_command(
    host: String,
    port: u16,
    key: [u8; sodiumoxide::crypto::secretbox::KEYBYTES],
    command: String,
) -> Result<String, DNSDistConsoleError> {
    let mut console: DNSDistConsole = DNSDistConsole::new(host, port, key)?;
    console.send(command)?;
    console.receive()
}
