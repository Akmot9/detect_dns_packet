use detect_dns_packet::DnsPacket;
use std::convert::TryFrom;

fn main() {
    println!("starting fuzz testing");
    if let Ok(data) = std::fs::read("crash.bin") {
        println!("data: {}", data.len());
        let hex_string: String = data.iter()
        .map(|byte| format!("{:02x}", byte))
        .collect();

        println!("Hexadecimal representation: {}", hex_string);

        match DnsPacket::try_from(data.as_slice()) {
            Ok(packet) => {
                println!("{:?}", packet);
            }
            Err(e) => {
                println!("Error parsing DNS packet: {}", e);
            }
        }
    }
}