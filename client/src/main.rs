extern crate core;

use dhcprs::dhcp_client;

use std::env;
use std::net::Ipv4Addr;
use std::process::exit;

fn main() {
    let interface_name = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: {} <interface name>", env::args().next().unwrap());
        exit(1);
    });

    match dhcp_client(interface_name.as_str()) {
        Ok(response) => {
            let cidr_suffix = match response.subnet_mask {
                Some(subnet_mask) => calculate_cidr_suffix(&subnet_mask),
                None => 32, // No subnet mask, so assume /32.b
            };
            println!(" - IP Assignment: {}/{} via {:?}", response.assigned_ip, cidr_suffix, response.gateways);
            println!(" - DNS Servers: {:?}", response.dns_servers);
        },
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn calculate_cidr_suffix(subnet_mask: &Ipv4Addr) -> u32 {
    // Convert subnet mask to u32 and then to binary string.
    let binary_representation = format!("{:032b}", u32::from(*subnet_mask));

    // Count the number of '1' bits in the binary string.
    binary_representation.chars().filter(|&c| c == '1').count() as u32
}
