# rs-dnsdist-console

A simple tool to use [dnsdist](https://dnsdist.org)'s console from the command-line,
written in Rust.

Run command
===========

```
$ rs-dnsdist-console 127.0.0.1 <base64-encoded console key> 5900 'showVersion()'
dnsdist 1.6.1
$
```

Use as a library
================

The library provides a simple `lib_rs_dnsdist_console::execute_command()` helper which
opens an encrypted TCP connection, executes a single command, reads the result and then
closes the connection.

It also provides a more complete `DNSDistConsole` object which allows executing several
commands over the same encrypted TCP connection:

```rust
let mut console: DNSDistConsole = DNSDistConsole::new(host, port, key)?;
console.send(command)?;
console.receive()
```
