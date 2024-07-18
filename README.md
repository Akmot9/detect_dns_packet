# detect_dns_packet

`detect_dns_packet` is a Rust library for parsing DNS packets. This library provides a way to decode DNS packets from raw bytes into structured data, enabling easy inspection and analysis of DNS packet contents.

## Features

- Parse DNS headers
- Parse DNS queries
- Parse DNS answers, authorities, and additional records (planned for future versions)

## Installation

Add `detect_dns_packet` to your `Cargo.toml`:

```toml
[dependencies]
detect_dns_packet = "0.1.0"
```

## Usage

Below is a basic example demonstrating how to parse a DNS packet using this library.

```rust
use detect_dns_packet::DnsPacket;
use std::convert::TryFrom;

fn main() {
    // Example DNS packet data in hex
    let data = hex::decode("002b81800001000f0006000202757304706f6f6c036e7470036f72670000010001c00c0001000100000d87000443814409c00c0001000100000d870004452c393cc00c0001000100000d870004cfead1b5c00c0001000100000d870004d184b004c00c0001000100000d870004d81bb92ac00c0001000100000d87000418224f2ac00c0001000100000d870004187bcae6c00c0001000100000d8700043fa43ef9c00c0001000100000d8700044070bd0bc00c0001000100000d870004417de9cec00c0001000100000d8700044221ce05c00c0001000100000d8700044221d80bc00c0001000100000d870004425c44f6c00c0001000100000d870004426f2ec8c00c0001000100000d8700044273880404504f4f4c036e7470036f72670000020001000010d60012036e7331086d61696c776f7278036e657400c11100020001000010d6000f067573656e6574036e6574026e7a00c11100020001000010d60014067a626173656c08666f72747974776f02636800c11100020001000010d60018086176656e747572610a62686d732d67726f6570026e6c00c11100020001000010d600110e736c617274696261727466617374c18bc11100020001000010d6000f0161026e73076d61646475636bc136c12900010001000272a500044501c844c1470001000100000daf0004ca313b06").expect("Invalid hex string");

    match DnsPacket::try_from(data.as_slice()) {
        Ok(packet) => {
            println!("{:?}", packet);
        }
        Err(e) => {
            println!("Error parsing DNS packet: {}", e);
        }
    }
}
```

## Modules

- `dns_header`: Contains the `DnsHeader` struct and related functionality.
- `dns_queries`: Contains the `DnsQueries` struct and related functionality.
- `utils`: Contains utility functions and types such as `DnsClass` and `DnsType`.

## Structs

- `DnsPacket`: Represents a DNS packet, containing the header, queries, answers, authorities, and additional records.
- `Answer`: Represents a DNS answer record.
- `AuthoritativeNameServer`: Represents an authoritative name server record.
- `AdditionalRecord`: Represents an additional record.

## Error Handling

The library uses Rust's standard `Result` and `Error` traits for error handling. Errors encountered during parsing will be returned as `Result::Err`.

## License

This project is licensed under the MIT or Apache-2.0 license.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue on GitHub.

## Tests

To run the tests, use the following command:

```sh
cargo test
```

## Future Work

- Implement parsing of DNS answer records
- Implement parsing of authoritative name server records
- Implement parsing of additional records

## Acknowledgements

Special thanks to the Rust community for their valuable resources and support.

## Contact

For any inquiries or feedback, please contact [Your Name](mailto:avicocyprien@yahoo.com).
