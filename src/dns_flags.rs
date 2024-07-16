/// Verifies the consistency of DNS packet flags.
///
/// # Arguments
///
/// * `flags` - A u16 representing the `Flags` field of a DNS packet.
///
/// # Returns
///
/// * `Result<u16, &'static str>` - Ok(flags) if the flags are consistent, Err(message) otherwise.
pub fn verify_dns_flags(flags: u16) -> Result<u16, &'static str> {
    // Extract subfields from flags
    println!("flags: {{0x{:04x}}}", flags);
    let qr = (flags >> 15) & 0b1;
    println!("qr: {}", qr);
    let opcode = (flags >> 11) & 0b1111;
    println!("opcode: {}", opcode);
    let aa = (flags >> 10) & 0b1;
    println!("aa: {}", aa);
    let tc = (flags >> 9) & 0b1;
    println!("tc: {}", tc);
    let rd = (flags >> 8) & 0b1;
    println!("rd: {}", rd);
    let ra = (flags >> 7) & 0b1;
    println!("ra: {}", ra);
    let z = (flags >> 4) & 0b111;
    println!("z: {}", z);
    let rcode = flags & 0b1111;
    println!("rcode: {}", rcode);

    // Verify subfields
    // The Z field must always be 0
    if z != 0 {
        println!("Z field is not 0 but {:?}", z);
        return Err("Invalid Z field, must be 0. here it's: {:?}");
    }

    // Verify that the opcode is within valid values (0 to 5)
    if opcode > 5 {
        println!("Opcode is {} but must be between 0 and 5", opcode);
        return Err("Invalid Opcode, must be between 0 and 5.");
    }

    // Verify that the rcode is within valid values (0 to 5)
    if rcode > 5 {
        println!("RCode is {} but must be between 0 and 5", rcode);
        return Err("Invalid RCode, must be between 0 and 5.");
    }

    // If QR is 0 (query), RA must be 0 because RA is used only in responses
    if qr == 0 && ra != 0 {
        println!("RA must be 0 in queries {:?} {:?}", ra, qr);
        return Err("RA must be 0 in queries.");
    }

    // If QR is 1 (response), additional checks are necessary
    if qr == 1 {
        // If QR is 1 and Opcode is 2 (STATUS), AA and TC must be 0
        if opcode == 2 && (aa != 0 || tc != 0) {
            println!("AA and TC must be 0 in STATUS responses {:?} {:?}", aa, tc);
            return Err("AA and TC must be 0 in STATUS responses.");
        }

        // If QR is 1 and RCode is 2 (Server failure), check that AA is 0
        if rcode == 2 && aa != 0 {
            println!("AA must be 0 in Server failure responses {:?} {:?}", aa, rcode);
            return Err("AA must be 0 in Server failure responses.");
        }

        // If QR is 1 and RCode is 3 (Name Error), check that AA is 1
        if rcode == 3 && aa == 0 {
            println!("AA must be 1 in Name Error responses {:?} {:?}", aa, rcode);
            return Err("AA must be 1 in Name Error responses.");
        }

        // If QR is 1 and RCode is 5 (Refused), check that AA is 0
        if rcode == 5 && aa != 0 {
            println!("AA must be 0 in Refused responses {:?} {:?}", aa, rcode);
            return Err("AA must be 0 in Refused responses.");
        }
    }

    // If all checks pass, return the flags
    Ok(flags)
}

#[cfg(test)]
mod tests {
    use super::*;
// ==================tests added by me==================
    #[test]
    fn test_valid_flags_standard_query() {
        // Example of valid flags
        let flags: u16 = 0x0100; // QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=1, Z=0, RCode=0
        assert_eq!(verify_dns_flags(flags), Ok(flags));
    }

    #[test]
    fn test_valid_flags_response_no_such_name() {
        // Example of valid flags
        let flags: u16 = 0x8583; // QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=1, Z=0, RCode=0
        assert_eq!(verify_dns_flags(flags), Ok(flags));
    }

    #[test]
    fn test_valid_flags_response_no_error() {
        // Example of valid flags
        let flags: u16 = 0x8180; // QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=1, Z=0, RCode=0
        assert_eq!(verify_dns_flags(flags), Ok(flags));
    }

// ==================tests added by chat gpt==================
    #[test]
    fn test_valid_flags() {
        // Example of valid flags
        let flags: u16 = 0x8180; // QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=1, Z=0, RCode=0
        assert_eq!(verify_dns_flags(flags), Ok(flags));
    }

    #[test]
    fn test_invalid_z_field() {
        let flags: u16 = 0x8008; // Z field is not 0
        assert_eq!(verify_dns_flags(flags), Err("Invalid Z field, must be 0."));
    }

    #[test]
    fn test_invalid_opcode() {
        let flags: u16 = 0x8800; // Opcode is 8, which is invalid
        assert_eq!(verify_dns_flags(flags), Err("Invalid Opcode, must be between 0 and 5."));
    }

    #[test]
    fn test_invalid_rcode() {
        let flags: u16 = 0x8006; // RCode is 6, which is invalid
        assert_eq!(verify_dns_flags(flags), Err("Invalid RCode, must be between 0 and 5."));
    }

    #[test]
    fn test_ra_in_query() {
        let flags: u16 = 0x0080; // RA is 1 in a query
        assert_eq!(verify_dns_flags(flags), Err("RA must be 0 in queries."));
    }

    #[test]
    fn test_aa_tc_in_status_response() {
        let flags: u16 = 0x8410; // QR=1, Opcode=2 (STATUS), AA=1, TC=1, invalid
        assert_eq!(verify_dns_flags(flags), Err("AA and TC must be 0 in STATUS responses."));
    }

    #[test]
    fn test_aa_in_server_failure() {
        let flags: u16 = 0x8082; // QR=1, RCode=2 (Server failure), AA=1, invalid
        assert_eq!(verify_dns_flags(flags), Err("AA must be 0 in Server failure responses."));
    }

    #[test]
    fn test_aa_in_name_error() {
        let flags: u16 = 0x8183; // QR=1, RCode=3 (Name Error), AA=0, invalid
        assert_eq!(verify_dns_flags(flags), Err("AA must be 1 in Name Error responses."));
    }

    #[test]
    fn test_aa_in_refused() {
        let flags: u16 = 0x8185; // QR=1, RCode=5 (Refused), AA=1, invalid
        assert_eq!(verify_dns_flags(flags), Err("AA must be 0 in Refused responses."));
    }
}


