mod dns_types;
mod dns_class;
mod dns_flags;

use std::{error::Error, fmt};

use dns_types::DnsType;
use dns_class::DnsClass;
use dns_flags::verify_dns_flags;

struct DnsPacket {
    transaction_id: u16,
    flags: u16,
    questions: u16,
    answers_rr: u16,
    authorities_rr: u16,
    additionals_rr: u16,
    queries: Vec<Query>,
    answers: Option<Vec<Answer>>,       // List of answer records
    authorities: Option<Vec<AuthoritativeNameServer>>, // List of authority records
    additionals: Option<Vec<AdditionalRecord>>, // List of additional records

}

impl TryFrom<&[u8]> for DnsPacket {
    type Error = Box<dyn Error>;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        println!("bytes lenght: {:?}", bytes.len());
        if bytes.len() < 12 {
            println!("Too short to be a DNS packet {}", bytes.len());
            return Err("Too short to be a DNS packet".into());
        }

        let transaction_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        println!("transaction_id: {}", &transaction_id);
        let flags = verify_dns_flags(u16::from_be_bytes([bytes[2], bytes[3]]))?;
        println!("flags: {}", &flags);
        let questions = u16::from_be_bytes([bytes[4], bytes[5]]);
        println!("questions: {}", &questions);
        let answers_rr = u16::from_be_bytes([bytes[6], bytes[7]]);
        println!("answers_rr: {}", &answers_rr);
        let authorities_rr = u16::from_be_bytes([bytes[8], bytes[9]]);
        println!("authorities_rr: {}", &authorities_rr);
        let additionals_rr = u16::from_be_bytes([bytes[10], bytes[11]]);
        println!("additionals_rr: {}", &additionals_rr);

        // Placeholder for actual parsing logic for queries and other records
        let queries = Vec::new();
        let answers = None;
        let authorities = None;
        let additionals = None;

        Ok(DnsPacket {
            transaction_id,
            flags,
            questions,
            answers_rr,
            authorities_rr,
            additionals_rr,
            queries,
            answers,
            authorities,
            additionals,
        })
    }
}

impl fmt::Display for DnsPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DnsPacket {{ transaction_id: {}, flags: {}, questions: {}, answers_rr: {}, authorities_rr: {}, additionals_rr: {}",
            self.transaction_id,
            self.flags,
            self.questions,
            self.answers_rr,
            self.authorities_rr,
            self.additionals_rr,
        )?;
        write!(f, ", queries: [")?;
        for query in &self.queries {
            write!(f, "{}, ", query)?;
        }
        write!(f, "]")?;
        if let Some(ref answers) = self.answers {
            write!(f, ", answers: [")?;
            for answer in answers {
                write!(f, "{}, ", answer)?;
            }
            write!(f, "]")?;
        }
        if let Some(ref authorities) = self.authorities {
            write!(f, ", authorities: [")?;
            for authority in authorities {
                write!(f, "{}, ", authority)?;
            }
            write!(f, "]")?;
        }
        if let Some(ref additionals) = self.additionals {
            write!(f, ", additionals: [")?;
            for additional in additionals {
                write!(f, "{}, ", additional)?;
            }
            write!(f, "]")?;
        }
        write!(f, " }}")
    }
}

#[derive(Debug)]
struct Query {
    name: String,               // Domain name
    query_type: DnsType,            // Type of query (e.g., A, AAAA, MX, etc.)
    query_class: DnsClass,           // Class of query (typically IN for Internet)
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Query {{ name: {}, query_type: {:?}, query_class: {} }}", self.name, self.query_type, self.query_class)
    }
}

// more can be a list of this possible struct (those strcut may on may not be on the liste: "more"): 
#[derive(Debug)]
struct Answer {
    name: String,               // Domain name
    answer_type: DnsType,           // Type of record (e.g., A, AAAA, MX, etc.)
    answer_class: DnsClass,          // Class of record (typically IN for Internet)
    ttl: u32,                   // Time to live
    data_length: u16,           // Length of the data
    address: Vec<u8>,           // Address or other data (variable length)
}

impl fmt::Display for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Answer {{ name: {}, answer_type: {}, answer_class: {}, ttl: {}, data_length: {}, address: {:?} }}",
            self.name, self.answer_type, self.answer_class, self.ttl, self.data_length, self.address
        )
    }
}

#[derive(Debug)]
struct AuthoritativeNameServer {
    name: String,               // Domain name
    answer_type: DnsType,           // Type of record
    answer_class: DnsClass,          // Class of record
    ttl: u32,                   // Time to live
    data_length: u16,           // Length of the data
    address: Vec<u8>,           // Address or other data (variable length)
}

impl fmt::Display for AuthoritativeNameServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AuthoritativeNameServer {{ name: {}, answer_type: {}, answer_class: {}, ttl: {}, data_length: {}, address: {:?} }}",
            self.name, self.answer_type, self.answer_class, self.ttl, self.data_length, self.address
        )
    }
}

#[derive(Debug)]
struct AdditionalRecord {
    name: String,               // Domain name
    answer_type: DnsType,           // Type of record
    answer_class: DnsClass,          // Class of record
    ttl: u32,                   // Time to live
    data_length: u16,           // Length of the data
    address: Vec<u8>,           // Address or other data (variable length)
}

impl fmt::Display for AdditionalRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AdditionalRecord {{ name: {}, answer_type: {}, answer_class: {}, ttl: {}, data_length: {}, address: {:?} }}",
            self.name, self.answer_type, self.answer_class, self.ttl, self.data_length, self.address
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_packet_parsing() {
        // Example DNS packet data
        let data = hex::decode("002b81800001000f0006000202757304706f6f6c036e7470036f72670000010001c00c0001000100000d87000443814409c00c0001000100000d870004452c393cc00c0001000100000d870004cfead1b5c00c0001000100000d870004d184b004c00c0001000100000d870004d81bb92ac00c0001000100000d87000418224f2ac00c0001000100000d870004187bcae6c00c0001000100000d8700043fa43ef9c00c0001000100000d8700044070bd0bc00c0001000100000d870004417de9cec00c0001000100000d8700044221ce05c00c0001000100000d8700044221d80bc00c0001000100000d870004425c44f6c00c0001000100000d870004426f2ec8c00c0001000100000d8700044273880404504f4f4c036e7470036f72670000020001000010d60012036e7331086d61696c776f7278036e657400c11100020001000010d6000f067573656e6574036e6574026e7a00c11100020001000010d60014067a626173656c08666f72747974776f02636800c11100020001000010d60018086176656e747572610a62686d732d67726f6570026e6c00c11100020001000010d600110e736c617274696261727466617374c18bc11100020001000010d6000f0161026e73076d61646475636bc136c12900010001000272a500044501c844c1470001000100000daf0004ca313b06").expect("Invalid hex string");

        match DnsPacket::try_from(data.as_slice()) {
            Ok(packet) => {
                println!("{}", packet);
                assert_eq!(packet.transaction_id, 0x002b);
                assert_eq!(packet.flags, 0x8180);
                assert_eq!(packet.questions, 1);
                assert_eq!(packet.answers_rr, 15);
                assert_eq!(packet.authorities_rr, 6);
                assert_eq!(packet.additionals_rr, 2);
            },
            Err(e) => panic!("Error parsing DNS packet: {}", e),
        }
    }

    #[test]
    fn test_dns_packet_parsing_return_error() {
        // Example non-DNS packet data
        let data = hex::decode("1a030aee00001bf7000014ec51ae80b7c502034c8d0e66cbc50204ecec42ee92c50204ebcf4959e6c50204ebcf4c6e6d").expect("Invalid hex string");

        match DnsPacket::try_from(data.as_slice()) {
            Ok(_) => panic!("Expected error, but parsing succeeded"),
            Err(e) => assert!(e.to_string().contains("Invalid Z field, must be 0."), "Unexpected error: {}", e),
        }
    }
}