use std::{error::Error, fmt};

use crate::utils::{dns_class::DnsClass, dns_types::DnsType};

#[derive(Debug)]
pub struct DnsQuery {
    pub name: String,
    pub qtype: DnsType,
    pub qclass: DnsClass,
}

impl DnsQuery {
    pub fn from_bytes(bytes: &[u8], offset: &mut usize) -> Result<Self, Box<dyn Error>> {
        let (name, new_offset) = parse_name(bytes, *offset)?;
        *offset = new_offset;
        let qtype = DnsType::new(u16::from_be_bytes([bytes[*offset], bytes[*offset + 1]]));
        let qclass = DnsClass::new(u16::from_be_bytes([bytes[*offset + 2], bytes[*offset + 3]]));
        *offset += 4;

        Ok(DnsQuery {
            name,
            qtype,
            qclass,
        })
    }
}

impl fmt::Display for DnsQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DnsQuery {{ name: {}, qtype: {}, qclass: {} }}",
            self.name, self.qtype, self.qclass
        )
    }
}

#[derive(Debug)]
pub struct DnsQueries {
    pub queries: Vec<DnsQuery>,
}

impl DnsQueries {
    pub fn from_bytes(bytes: &[u8], count: u16) -> Result<Self, Box<dyn Error>> {
        let mut queries = Vec::with_capacity(count as usize);
        let mut offset = 0;
        for _ in 0..count {
            queries.push(DnsQuery::from_bytes(bytes, &mut offset)?);
        }
        Ok(DnsQueries { queries })
    }
}

impl fmt::Display for DnsQueries {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DnsQueries {{ queries: [")?;
        for query in &self.queries {
            write!(f, " {},", query)?;
        }
        write!(f, "] }}")
    }
}

fn parse_name(bytes: &[u8], mut offset: usize) -> Result<(String, usize), Box<dyn Error>> {
    let mut labels = Vec::new();
    //println!("Initial offset: {}", offset);
    loop {
        let len = bytes[offset] as usize;
        //println!("Length of next label: {}", len);
        if len == 0 {
            offset += 1;
            //println!("Encountered zero length, incremented offset to: {}", offset);
            break;
        }
        offset += 1;
        if offset + len > bytes.len() {
            return Err("Out of bound parse".into());
        }
        //println!("Reading label from offset: {} to {}", offset, offset + len);
        let label = String::from_utf8(bytes[offset..offset + len].to_vec())?;
        //println!("Parsed label: {}", label);
        labels.push(label);
        offset += len;
        //println!("Updated offset after reading label: {}", offset);
    }
    let name = labels.join(".");
    //println!("Final parsed name: {}", name);
    //println!("Final offset: {}", offset);
    Ok((name, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_name() {
        let data = vec![
            0x03, 0x77, 0x77, 0x77, // "www"
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // Null terminator of the domain name
        ];
        let (name, offset) = parse_name(&data, 0).unwrap();
        assert_eq!(name, "www.google.com");
        assert_eq!(offset, 16);
    }

    #[test]
    fn test_dns_query_from_bytes() {
        let data = vec![
            3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, 0,
            1, 0, 1,
        ];
        let mut offset = 0;
        let query = DnsQuery::from_bytes(&data, &mut offset).unwrap();
        assert_eq!(query.name, "www.google.com");
        assert_eq!(query.qtype, DnsType(1));
        assert_eq!(query.qclass, DnsClass(1));
        assert_eq!(offset, 20);
    }

    #[test]
    fn test_dns_queries_from_bytes() {
        let data = vec![
            3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, 0,
            1, 0, 1, 3, b'f', b'o', b'o', 3, b'b', b'a', b'r', 3, b'c', b'o', b'm', 0, 0, 2, 0, 1,
        ];
        let queries = DnsQueries::from_bytes(&data, 2).unwrap();
        assert_eq!(queries.queries.len(), 2);
        assert_eq!(queries.queries[0].name, "www.google.com");
        assert_eq!(queries.queries[0].qtype, DnsType(1));
        assert_eq!(queries.queries[0].qclass, DnsClass(1));
        assert_eq!(queries.queries[1].name, "foo.bar.com");
        assert_eq!(queries.queries[1].qtype, DnsType(2));
        assert_eq!(queries.queries[1].qclass, DnsClass(1));
    }
}
