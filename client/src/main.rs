extern crate core;

use dhcprs::dhcp_client;

use std::env;
use std::process::exit;
use anyhow::{Result};

fn main() -> Result<()> {
    let interface_name = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: {} <interface name>", env::args().next().unwrap());
        exit(1);
    });

    dhcp_client(interface_name.as_str())
}
