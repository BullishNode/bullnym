use crate::error::AppError;

pub fn derive_address(ct_descriptor: &str, index: u32) -> Result<String, AppError> {
    let desc: lwk_wollet::WolletDescriptor = ct_descriptor
        .parse()
        .map_err(|e| AppError::InvalidDescriptor(format!("{e}")))?;

    let addr = desc
        .address(index, &lwk_wollet::elements::AddressParams::LIQUID)
        .map_err(|e| AppError::InvalidDescriptor(format!("address derivation failed: {e}")))?;

    Ok(addr.to_string())
}

pub fn validate_descriptor(ct_descriptor: &str, max_len: usize) -> Result<(), AppError> {
    if ct_descriptor.len() > max_len {
        return Err(AppError::InvalidDescriptor(format!(
            "descriptor exceeds maximum length of {max_len}"
        )));
    }
    derive_address(ct_descriptor, 0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // CT descriptor using h-notation (required by lwk 0.14). Derived from "abandon...about" mnemonic.
    const TEST_CT_DESC: &str = "ct(slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023),elwpkh([73c5da0a/84h/1776h/0h]xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*))#y8jljyxl";

    #[test]
    fn derive_valid_address() {
        let addr = derive_address(TEST_CT_DESC, 0).expect("descriptor must parse");
        assert!(addr.starts_with("lq1qq"), "expected confidential address, got {addr}");
    }

    #[test]
    fn deterministic_derivation() {
        let a1 = derive_address(TEST_CT_DESC, 5).unwrap();
        let a2 = derive_address(TEST_CT_DESC, 5).unwrap();
        assert_eq!(a1, a2);
    }

    #[test]
    fn different_indices_different_addresses() {
        let a0 = derive_address(TEST_CT_DESC, 0).unwrap();
        let a1 = derive_address(TEST_CT_DESC, 1).unwrap();
        let a2 = derive_address(TEST_CT_DESC, 2).unwrap();
        assert_ne!(a0, a1);
        assert_ne!(a1, a2);
        assert_ne!(a0, a2);
    }

    #[test]
    fn invalid_descriptor_fails() {
        assert!(derive_address("not a descriptor", 0).is_err());
    }

    #[test]
    fn empty_descriptor_fails() {
        assert!(derive_address("", 0).is_err());
    }

    #[test]
    fn validate_too_long_descriptor() {
        assert!(validate_descriptor(TEST_CT_DESC, 10).is_err());
    }

    #[test]
    fn validate_invalid_descriptor() {
        assert!(validate_descriptor("garbage", 1000).is_err());
    }
}
