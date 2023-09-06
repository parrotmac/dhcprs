# dhcprs

A partial, experimental DHCP client implementation in Rust

## Usage

From `client/` directory:

```bash
cargo run <interface>
```

For example:

```bash
cargo run eth0
```

## Status

This is a personal project, intended to learn about DHCP (and write some more Rust). I would love to see this become more feature-rich and stable, so contributions are welcome!

- [x] DHCPDISCOVER
- [x] DHCPOFFER
- [x] DHCPREQUEST
- [x] DHCPACK
- [x] DHCPDECLINE
- [ ] DHCPNAK
- [ ] DHCPRELEASE
- [ ] DHCPINFORM
- [ ] DHCPFORCERENEW
- [ ] DHCPLEASEQUERY
- [ ] DHCPLEASEUNASSIGNED
- [ ] DHCPLEASEUNKNOWN
- [ ] DHCPLEASEACTIVE
- [ ] DHCPBULKLEASEQUERY
- [ ] DHCPLEASEQUERYDONE
- [ ] DHCPACTIVELEASEQUERY
- [ ] DHCPLEASEQUERYSTATUS
- [ ] DHCPTLS


## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.

