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
        Ok(response) => println!("Assigned IP: {} via {:?}", response.assigned_ip, response.gateways),
        Err(e) => eprintln!("Error: {}", e),
    }
}
