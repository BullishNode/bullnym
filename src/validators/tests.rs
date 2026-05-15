use super::*;

#[test]
fn btc_mainnet_p2pkh_accepted() {
    let addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    validate_btc_mainnet_address(addr).expect("mainnet P2PKH must validate");
}

#[test]
fn btc_mainnet_p2wpkh_accepted() {
    let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    validate_btc_mainnet_address(addr).expect("mainnet bech32 must validate");
}

#[test]
fn btc_mainnet_p2tr_accepted() {
    let addr = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    validate_btc_mainnet_address(addr).expect("mainnet taproot must validate");
}

#[test]
fn btc_testnet_rejected() {
    let addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let err = validate_btc_mainnet_address(addr).expect_err("testnet must be rejected");
    match err {
        AppError::InvalidAmount(msg) => {
            assert!(
                msg.contains("mainnet"),
                "error must mention mainnet, got: {msg}"
            );
        }
        other => panic!("expected InvalidAmount, got {other:?}"),
    }
}

#[test]
fn btc_regtest_rejected() {
    let addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    assert!(
        validate_btc_mainnet_address(addr).is_err(),
        "regtest must be rejected"
    );
}

#[test]
fn btc_garbage_rejected() {
    assert!(validate_btc_mainnet_address("").is_err());
    assert!(validate_btc_mainnet_address("not-a-bitcoin-address").is_err());
    assert!(validate_btc_mainnet_address("0xabc").is_err());
}

#[test]
fn liquid_mainnet_confidential_accepted() {
    let addr = crate::descriptor::derive_address(
        "ct(slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023),\
elwpkh([73c5da0a/84h/1776h/0h]xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*))#y8jljyxl",
        0,
    )
    .expect("descriptor must parse");
    validate_liquid_mainnet_address(&addr).expect("mainnet CT must validate");
}

#[test]
fn liquid_garbage_rejected() {
    assert!(validate_liquid_mainnet_address("").is_err());
    assert!(validate_liquid_mainnet_address("not-a-liquid-address").is_err());
    assert!(validate_liquid_mainnet_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_err());
}
