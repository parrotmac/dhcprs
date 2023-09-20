
use std::net::Ipv4Addr;
use anyhow::{Result};


use chrono::{DateTime, Utc};

use dhcproto::{v4, Encodable, Encoder, Decodable, Decoder};
use dhcproto::v4::{CLIENT_PORT, DhcpOption, OptionCode, SERVER_PORT};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::{datalink};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{Config, MacAddr, NetworkInterface};
use pnet::packet::{ipv4, Packet, udp};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocols};



const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const ETHERNET_HEADER_LEN: usize = 14;

struct MacAddress(MacAddr);

impl From<&[u8]> for MacAddress {
    fn from(bytes: &[u8]) -> Self {
        let mut octets = [0u8; 6];
        octets.copy_from_slice(bytes);
        MacAddress(MacAddr::new(octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]))
    }
}

impl From<MacAddress> for MacAddr {
    fn from(mac: MacAddress) -> Self {
        mac.0
    }
}


fn build_ipv4_header(packet: &mut [u8], offset: usize, payload_len: usize, ipv4_source: Ipv4Addr, ipv4_destination: Ipv4Addr) {
    let mut ip_header = MutableIpv4Packet::new(&mut packet[offset..]).expect("could not create MutableIpv4Packet");

    let total_len = (IPV4_HEADER_LEN + UDP_HEADER_LEN + payload_len) as u16;

    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(total_len);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_header.set_source(ipv4_source);
    ip_header.set_destination(ipv4_destination);
    let checksum = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(checksum);
}

fn build_udp_header(packet: &mut [u8], offset: usize, payload_len: usize, source_port: u16, destination_port: u16) {
    let mut udp_header = MutableUdpPacket::new(&mut packet[offset..]).expect("could not create MutableUdpPacket");

    udp_header.set_source(source_port);
    udp_header.set_destination(destination_port);
    udp_header.set_length((UDP_HEADER_LEN + payload_len) as u16);
}


fn build_udp4_packet(
    packet: &mut [u8],
    start: usize,
    msg: Vec<u8>,
    payload_size: usize,
    source: Ipv4Addr,
    dest: Ipv4Addr,
) {
    build_ipv4_header(packet, start, payload_size, source, dest);
    build_udp_header(packet, start + IPV4_HEADER_LEN, payload_size, CLIENT_PORT, SERVER_PORT);

    let data_start = start + IPV4_HEADER_LEN + UDP_HEADER_LEN;
    packet[data_start..(data_start + msg.len())].copy_from_slice(&msg[..]);

    let slice = &mut packet[(start + IPV4_HEADER_LEN)..];
    let checksum = udp::ipv4_checksum(&UdpPacket::new(slice).expect("could not create UdpPacket"), &source, &dest);
    MutableUdpPacket::new(slice).expect("could not create MutableUdpPacket").set_checksum(checksum);
}

fn build_eth_udp_packet(chaddr: MacAddress, payload: Vec<u8>) -> Vec<u8> {
    let payload_size = payload.len();
    let mut packet = vec![0u8; ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + payload_size];

    let mut ethernet_header = MutableEthernetPacket::new(&mut packet[..]).expect("failed to create MutableEthernetPacket");
    ethernet_header.set_source(chaddr.into());
    ethernet_header.set_ethertype(EtherTypes::Ipv4);
    ethernet_header.set_destination(MacAddr::broadcast());

    build_udp4_packet(
        &mut packet[..],
        ETHERNET_HEADER_LEN,
        payload,
        payload_size,
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::BROADCAST,
    );

    packet
}

fn eth_arp_packet(chaddr: MacAddress, target_ip: Ipv4Addr) -> [u8; ETHERNET_HEADER_LEN + 28] {
    let mut packet = [0u8; ETHERNET_HEADER_LEN + 28];
    let source_address: MacAddr = chaddr.into();

    let mut ethernet_header = MutableEthernetPacket::new(&mut packet[..]).unwrap();
    ethernet_header.set_source(source_address);
    ethernet_header.set_destination(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
    ethernet_header.set_ethertype(EtherTypes::Arp);

    let mut arp = MutableArpPacket::new(&mut packet[ETHERNET_HEADER_LEN..]).unwrap();
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);

    arp.set_sender_hw_addr(source_address);

    // Ordinarily this would be be set, but in the case of a DHCP ARP / ARP Probe request, we can't specify a reply address.
    arp.set_sender_proto_addr(Ipv4Addr::new(0, 0, 0, 0));

    // For the ARP request messages, this field is all Os because the sender does not know the physical address of the target.
    arp.set_target_hw_addr(MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x00));

    arp.set_target_proto_addr(target_ip);

    packet
}

pub fn dhcp_client(interface_name: &str) -> Result<Ipv4Addr> {
    let interface_names_match =
        |iface: &NetworkInterface| iface.name == interface_name;
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(interface_names_match)
        .unwrap();

    let mac = interface.mac.unwrap();
    let binding = mac.octets();
    let chaddr: &[u8] = binding.as_ref();


    let channel_cfg = Config{
        channel_type: datalink::ChannelType::Layer2,
        ..Default::default()
    };
    let (mut tx, mut rx) = match datalink::channel(&interface, channel_cfg) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    // now encode to bytes
    let mut dhcp_request_payload = vec![0];
    {
        let mut msg = v4::Message::default();
        msg.set_flags(v4::Flags::default().set_broadcast()) // set broadcast to true
            .set_chaddr(chaddr) // set chaddr
            .opts_mut()
            .insert(DhcpOption::MessageType(v4::MessageType::Discover)); // set msg type

        msg.opts_mut()
            .insert(v4::DhcpOption::ParameterRequestList(vec![
                OptionCode::SubnetMask,
                OptionCode::Router,
                OptionCode::DomainNameServer,
                OptionCode::DomainName,
            ]));
        msg.opts_mut()
            .insert(v4::DhcpOption::ClientIdentifier(chaddr.into()));

        let mut e = Encoder::new(&mut dhcp_request_payload);
        msg.encode(&mut e)?;
    }

    let packet = build_eth_udp_packet(chaddr.into(), dhcp_request_payload);

    tx.send_to(packet.as_slice(), Some(interface)).unwrap_or_else(|| {
        panic!("Could not send UDP packet!");
    }).unwrap_or_else(|e| {
        panic!("Could not send UDP packet: {}", e)
    });

    let mut received_address_assignment: Option<Ipv4Addr> = None;
    let mut arp_reply_timout: Option<(DateTime<Utc>, v4::Message)> = None;

    loop {

        if let Some((timeout, reply_packet)) = arp_reply_timout.clone() {
            if Utc::now() > timeout {
                println!("Did not receive an ARP reply for IP; Sending DHCP REQUEST");
                // Claim IP since we didn't get an ARP reply
                let mut buf = vec![0];
                let mut e = Encoder::new(&mut buf);
                reply_packet.encode(&mut e)?;

                let request_packet = build_eth_udp_packet(chaddr.into(), buf);

                tx.send_to(request_packet.as_slice(), None).unwrap_or_else(|| {
                    panic!("Could not send UDP packet!");
                }).unwrap_or_else(|e| {
                    panic!("Could not send UDP packet: {}", e)
                });

                arp_reply_timout = None;
            }
        }

        match rx.next() {
            Ok(pkt) => {
                let eth_frame = EthernetPacket::new(pkt).unwrap();
                if let  Some(ipv4_packet) = Ipv4Packet::new(eth_frame.payload()) {
                    if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                        if udp_packet.get_destination() == CLIENT_PORT {
                            match v4::Message::decode(&mut Decoder::new(udp_packet.payload())) {
                                Ok(dhcp_packet) => {
                                    match dhcp_packet.opts().msg_type().unwrap() {
                                        v4::MessageType::Offer => {
                                            let offer_packet = dhcp_packet;

                                            let server_identifier = offer_packet.opts().get(OptionCode::ServerIdentifier).expect("DHCP Offer packet did not include required Server Identifier field.");
                                            let domain_name = offer_packet.opts().get(OptionCode::DomainName);
                                            let your_ip = offer_packet.yiaddr();


                                            let mut msg = v4::Message::default();
                                            msg.set_flags(v4::Flags::default().set_broadcast()) // set broadcast to true
                                                .set_chaddr(chaddr) // set chaddr
                                                .opts_mut()
                                                .insert(DhcpOption::ClientIdentifier(chaddr.into()));
                                            if let Some(domain_name) = domain_name {
                                                msg.opts_mut()
                                                    .insert(domain_name.to_owned());
                                            }
                                            msg.opts_mut()
                                                .insert(DhcpOption::MessageType(v4::MessageType::Request));
                                            msg.opts_mut()
                                                .insert(server_identifier.to_owned());
                                            msg.opts_mut()
                                                .insert(DhcpOption::RequestedIpAddress(your_ip));

                                            received_address_assignment = Some(your_ip);
                                            let wait_duration = chrono::Duration::seconds(2);
                                            let wait_until = Utc::now() + wait_duration;
                                            arp_reply_timout = Some((wait_until, msg.clone()));

                                            let arp_probe_packet = eth_arp_packet(chaddr.into(), your_ip);
                                            println!("Received a DHCP Offer for IP: {}; Sending ARP Probe to check for existing clients (will wait {}ms)", your_ip, wait_duration.num_milliseconds());
                                            tx.send_to(arp_probe_packet.as_slice(), None).unwrap_or_else(|| {
                                                panic!("Could not send ARP packet!");
                                            }).unwrap_or_else(|e| {
                                                panic!("Could not send ARP packet: {}", e)
                                            });

                                        },
                                        v4::MessageType::Ack => {
                                            let ack_packet = dhcp_packet;
                                            let your_ip = ack_packet.yiaddr();
                                            println!("Received a DHCP Ack for IP: {}", your_ip);
                                            return Ok(your_ip);
                                        },
                                        _ => {}
                                    }

                                },
                                Err(e) => eprintln!("An error occurred while reading: {}", e),
                            }
                        }
                    }
                    if let Some(arp_packet) = ArpPacket::new(ipv4_packet.payload()) {
                        if arp_packet.get_operation() == ArpOperations::Reply {
                            let arp_reply = arp_packet;
                            if arp_reply.get_target_hw_addr() != MacAddr::new(chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]) {
                                // ARP reply is not for us
                                continue;
                            }
                            if let Some(received_address_assignment) = received_address_assignment {
                                if arp_reply.get_sender_proto_addr() != received_address_assignment {
                                    // ARP reply is not for the address we're trying to claim
                                    continue;
                                }
                            }

                            // ARP reply is for us
                            // Send a DHCP DECLINE

                            arp_reply_timout = None;

                            let mut msg = v4::Message::default();
                            msg.set_flags(v4::Flags::default().set_broadcast()) // set broadcast to true
                                .set_chaddr(chaddr) // set chaddr
                                .opts_mut()
                                .insert(DhcpOption::ClientIdentifier(chaddr.into()));
                            msg.opts_mut()
                                .insert(DhcpOption::MessageType(v4::MessageType::Decline));
                            msg.opts_mut()
                                .insert(DhcpOption::RequestedIpAddress(arp_reply.get_sender_proto_addr()));

                            let mut buf = vec![0];
                            let mut e = Encoder::new(&mut buf);
                            msg.encode(&mut e)?;

                            let packet = build_eth_udp_packet(chaddr.into(), buf);

                            tx.send_to(packet.as_slice(), None).unwrap_or_else(|| {
                                panic!("Could not send UDP packet!");
                            }).unwrap_or_else(|e| {
                                panic!("Could not send UDP packet: {}", e)
                            });
                        }
                    }
                }
            }
            Err(e) => eprintln!("An error occurred while reading: {}", e),
        }
    }
}
