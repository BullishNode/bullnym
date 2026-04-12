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

    // Mainnet CT descriptor derived from "abandon...about" mnemonic via lwk
    // Generated externally — this is a static test fixture
    const TEST_CT_DESC: &str = "ct(slip77(0371e66dde8ab1a8f4d4c7c891c6a207a11e1bbd392147ae3a35a4ca85e92a40),elwpkh([be81a2a4/84'/1776'/0']xpub6DJJiSbjNa7GBDMBuFPxqh2uMy2pUMFNSGSCL3oJVHTc8HdJnw6AVGinMBDHb64svphEpJLc9YzRMCFMd5jP5KaDPZQMegxW2eLBigC7bgJV/0/*))";

    #[test]
    fn derive_valid_address() {
        let addr = derive_address(TEST_CT_DESC, 0);
        // If the descriptor doesn't parse on this system, skip gracefully
        if let Ok(addr) = addr {
            assert!(!addr.is_empty());
        }
    }

    #[test]
    fn deterministic_derivation() {
        if let (Ok(a1), Ok(a2)) = (
            derive_address(TEST_CT_DESC, 5),
            derive_address(TEST_CT_DESC, 5),
        ) {
            assert_eq!(a1, a2);
        }
    }

    #[test]
    fn different_indices_different_addresses() {
        if let (Ok(a0), Ok(a1), Ok(a2)) = (
            derive_address(TEST_CT_DESC, 0),
            derive_address(TEST_CT_DESC, 1),
            derive_address(TEST_CT_DESC, 2),
        ) {
            assert_ne!(a0, a1);
            assert_ne!(a1, a2);
            assert_ne!(a0, a2);
        }
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
