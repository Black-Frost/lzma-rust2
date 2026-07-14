//! Regression check for the index-VLI DoS fix: unterminated 0x80 continuation
//! bytes in the XZ index must now be rejected promptly by XzStream, matching
//! the XzReader path, instead of being accepted with O(n^2) work.

use std::io::Write;
use std::time::Instant;

use lzma_rust2::{Action, XzOptions, XzStream, XzWriter};

fn build_malicious_input(filler_len: usize) -> Vec<u8> {
    let options = XzOptions::with_preset(6);
    let mut writer = XzWriter::new(Vec::new(), options).unwrap();
    writer.write_all(b"").unwrap();
    let compressed = writer.finish().unwrap();
    assert_eq!(compressed[12], 0x00, "expected index indicator at offset 12");

    let mut malicious = Vec::with_capacity(13 + filler_len);
    malicious.extend_from_slice(&compressed[..13]);
    malicious.extend(std::iter::repeat(0x80u8).take(filler_len));
    malicious
}

#[test]
fn index_vli_filler_is_rejected_promptly() {
    // A huge run that previously took many seconds and grew accum unbounded.
    let malicious = build_malicious_input(20_000_000);
    let mut decoder = XzStream::new(false);
    let mut output = [0u8; 4096];

    let start = Instant::now();
    let result = decoder.process(&malicious, &mut output, Action::Run);
    let elapsed = start.elapsed();
    eprintln!("20M-byte filler rejected in {elapsed:?}: {result:?}");

    let err = result.expect_err("filler must now be rejected");
    assert!(
        err.to_string().contains("XZ multibyte integer too long"),
        "unexpected error: {err}"
    );
    // Bounded work: rejection happens after ~9 accumulated bytes, so even 20M
    // bytes of filler must reject near-instantly.
    assert!(elapsed.as_millis() < 50, "took {elapsed:?}, expected near-instant");
}
