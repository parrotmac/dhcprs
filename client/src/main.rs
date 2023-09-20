extern crate core;

use dhcprs::dhcp_client;

use std::env;
use std::process::exit;

fn main() {
    let interface_name = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: {} <interface name>", env::args().next().unwrap());
        exit(1);
    });

    match dhcp_client(interface_name.as_str()) {
        Ok(assigned_ip) => println!("Assigned IP: {}", assigned_ip),
        Err(e) => eprintln!("Error: {}", e),
    }
}
