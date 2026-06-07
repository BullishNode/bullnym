use super::*;

#[test]
fn sniff_jpeg() {
    let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xE0];
    bytes.extend(std::iter::repeat_n(0, 20));
    assert_eq!(sniff_format(&bytes), Some(SniffedFormat::Jpeg));
}

#[test]
fn sniff_png() {
    let mut bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.extend(std::iter::repeat_n(0, 20));
    assert_eq!(sniff_format(&bytes), Some(SniffedFormat::Png));
}

#[test]
fn sniff_webp() {
    let mut bytes = b"RIFF".to_vec();
    bytes.extend([0, 0, 0, 0]);
    bytes.extend(b"WEBP");
    bytes.extend(std::iter::repeat_n(0, 20));
    assert_eq!(sniff_format(&bytes), Some(SniffedFormat::Webp));
}

#[test]
fn sniff_rejects_too_short() {
    assert_eq!(sniff_format(&[0xFF, 0xD8]), None);
}

#[test]
fn sniff_rejects_php_in_jpeg_jacket() {
    let bytes = b"<?php echo 'hi'; ?>".to_vec();
    assert_eq!(sniff_format(&bytes), None);
}

#[test]
fn image_kind_parse() {
    assert_eq!(ImageKind::parse("avatar"), Some(ImageKind::Avatar));
    assert_eq!(ImageKind::parse("og"), Some(ImageKind::Og));
    assert_eq!(ImageKind::parse("AVATAR"), None);
    assert_eq!(ImageKind::parse("../etc/passwd"), None);
}

#[test]
fn image_path_no_traversal() {
    let p = image_path("/tmp/imgs", "alice", ImageKind::Avatar);
    assert_eq!(p.to_str().unwrap(), "/tmp/imgs/alice/avatar.webp");
}

fn make_test_png(width: u32, height: u32) -> Vec<u8> {
    let img = image::RgbImage::new(width, height);
    let mut out = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(&mut out);
    image::ImageEncoder::write_image(
        encoder,
        img.as_raw(),
        width,
        height,
        image::ExtendedColorType::Rgb8,
    )
    .unwrap();
    out
}

fn default_cfg() -> PipelineConfig {
    PipelineConfig {
        max_bytes: 2 * 1024 * 1024,
        max_dimension: 10_000,
        max_pixels: 12_000_000,
        avatar_size: 256,
        og_width: 1200,
        og_height: 630,
    }
}

#[test]
fn process_resizes_avatar_to_square() {
    let png = make_test_png(800, 600);
    let result = process(&png, ImageKind::Avatar, &default_cfg()).unwrap();
    let img = image::load_from_memory(&result.bytes).unwrap();
    assert_eq!(img.width(), 256);
    assert_eq!(img.height(), 256);

    let mut h = Sha256::new();
    h.update(&png);
    assert_eq!(result.source_sha256, hex::encode(h.finalize()));
}

#[test]
fn process_resizes_og_to_1200x630() {
    let png = make_test_png(2400, 1260);
    let result = process(&png, ImageKind::Og, &default_cfg()).unwrap();
    let img = image::load_from_memory(&result.bytes).unwrap();
    assert_eq!(
        image::guess_format(&result.bytes).unwrap(),
        image::ImageFormat::Jpeg
    );
    assert_eq!(img.width(), 1200);
    assert_eq!(img.height(), 630);
}

#[test]
fn process_rejects_unrecognized_bytes() {
    let bytes = b"this is definitely not an image of any kind".repeat(2);
    let err = process(&bytes, ImageKind::Avatar, &default_cfg()).unwrap_err();
    assert!(matches!(err, AppError::ImageInvalid(_)));
}

#[test]
fn process_rejects_oversize_body() {
    let mut cfg = default_cfg();
    cfg.max_bytes = 100;
    let png = make_test_png(50, 50);
    assert!(png.len() > 100);
    let err = process(&png, ImageKind::Avatar, &cfg).unwrap_err();
    assert!(matches!(err, AppError::ImageInvalid(_)));
}

#[test]
fn process_rejects_huge_dimensions() {
    let mut cfg = default_cfg();
    cfg.max_dimension = 100;
    let png = make_test_png(200, 200);
    let err = process(&png, ImageKind::Avatar, &cfg).unwrap_err();
    assert!(matches!(err, AppError::ImageDimensionsTooLarge { .. }));
}

#[test]
fn process_rejects_huge_pixel_area() {
    let mut cfg = default_cfg();
    cfg.max_dimension = 1_000;
    cfg.max_pixels = 10_000;
    let png = make_test_png(200, 200);
    let err = process(&png, ImageKind::Avatar, &cfg).unwrap_err();
    assert!(matches!(err, AppError::ImagePixelsTooLarge { .. }));
}

#[test]
fn process_rejects_empty() {
    let err = process(&[], ImageKind::Avatar, &default_cfg()).unwrap_err();
    assert!(matches!(err, AppError::ImageInvalid(_)));
}

#[test]
fn atomic_write_creates_parent_and_renames() {
    let tmp = std::env::temp_dir().join(format!("pay-service-test-{}", uuid::Uuid::new_v4()));
    let target = tmp.join("alice").join("avatar.webp");
    atomic_write(&target, b"hello").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"hello");
    std::fs::remove_dir_all(&tmp).ok();
}
