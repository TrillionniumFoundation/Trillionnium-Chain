//! Known-answer controls for the pinned SHA-2 backend, including padding and
//! streaming boundaries. Expected digests do not use a second local SHA path.
//! NIST worked examples:
//! https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
//! https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf

use sha2::{Digest, Sha256, Sha512};

#[test]
fn sha256_known_answers_preserve_single_and_multi_block_streams() {
    let cases: &[(&[u8], &str)] = &[
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    for (message, expected) in cases {
        assert_eq!(hex::encode(Sha256::digest(message)), *expected);
        for width in [1, 7, 31, 55, 56, 63, 64, 65] {
            let mut hash = Sha256::new();
            for chunk in message.chunks(width) {
                hash.update(chunk);
            }
            assert_eq!(hex::encode(hash.finalize()), *expected, "chunk {width}");
        }
    }
}

#[test]
fn sha512_known_answers_preserve_single_and_multi_block_streams() {
    let cases: &[(&[u8], &str)] = &[
        (
            b"",
            concat!(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0",
                "d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            ),
        ),
        (
            b"abc",
            concat!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
        ),
        (
            concat!(
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
                "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            )
            .as_bytes(),
            concat!(
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018",
                "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
            ),
        ),
    ];
    for (message, expected) in cases {
        assert_eq!(hex::encode(Sha512::digest(message)), *expected);
        for width in [1, 7, 63, 64, 111, 112, 127, 128, 129] {
            let mut hash = Sha512::new();
            for chunk in message.chunks(width) {
                hash.update(chunk);
            }
            assert_eq!(hex::encode(hash.finalize()), *expected, "chunk {width}");
        }
    }
}
