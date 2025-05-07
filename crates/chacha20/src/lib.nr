mod block;

/// Encrypts an arbitrary sized message by running chacha20.
/// The stream cipher of ChaCha20 is composed of running the block_function with an increasing counter,
/// which provides 64-bytes of keystream at a time.
pub fn ChaCha20<let N: u32>(
    key_bytes: [u8; 32],
    nonce_bytes: [u8; 12],
    counter: u32,
    plaintext: [u8; N],
) -> [u8; N] {
    let key = pack_bytes_to_u32_words_padded(key_bytes);
    let nonce = pack_bytes_to_u32_words_padded(nonce_bytes);

    let mut res = [0 as u8; N];
    for j in 0..N / 64 {
        let key_stream = block::chacha20_block(key, nonce, counter + j);
        let key_stream_bytes = unpack_u32_words_to_bytes(key_stream);
        for t in 0..64 {
            res[64 * j + t] = plaintext[64 * j + t] ^ key_stream_bytes[t];
        }
    }

    if (N % 64 != 0) {
        let j = N / 64;
        let key_stream = block::chacha20_block(key, nonce, counter + j);
        let key_stream_bytes = unpack_u32_words_to_bytes(key_stream);
        for t in 0..N % 64 {
            res[64 * j + t] = plaintext[64 * j + t] ^ key_stream_bytes[t];
        }
    }

    res
}

/// The test data of this function is from section 2.4.2 of RFC7539, except that it pads 2 extra 0 bytes
/// since, for now, the function operations on 4-byte words
#[test]
fn test_ChaCha20() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];

    let nonce = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];

    let counter = 1;

    let plaintext_words = [
        0x4c616469, 0x65732061, 0x6e642047, 0x656e746c, 0x656d656e, 0x206f6620, 0x74686520,
        0x636c6173, 0x73206f66, 0x20273939, 0x3a204966, 0x20492063, 0x6f756c64, 0x206f6666,
        0x65722079, 0x6f75206f, 0x6e6c7920, 0x6f6e6520, 0x74697020, 0x666f7220, 0x74686520,
        0x66757475, 0x72652c20, 0x73756e73, 0x63726565, 0x6e20776f, 0x756c6420, 0x62652069,
        0x742e0000,
    ];
    let plaintext = unpack_u32_words_to_bytes(plaintext_words);

    let expected_ciphertext_words = [
        0x6e2e359a, 0x2568f980, 0x41ba0728, 0xdd0d6981, 0xe97e7aec, 0x1d4360c2, 0x0a27afcc,
        0xfd9fae0b, 0xf91b65c5, 0x524733ab, 0x8f593dab, 0xcd62b357, 0x1639d624, 0xe65152ab,
        0x8f530c35, 0x9f0861d8, 0x07ca0dbf, 0x500d6a61, 0x56a38e08, 0x8a22b65e, 0x52bc514d,
        0x16ccf806, 0x818ce91a, 0xb7793736, 0x5af90bbf, 0x74a35be6, 0xb40b8eed, 0xf2785e42,
        0x874d7403,
    ];
    let expected_ciphertext = unpack_u32_words_to_bytes(expected_ciphertext_words);

    let ciphertext = ChaCha20(key, nonce, counter, plaintext);
    assert(ciphertext == expected_ciphertext, f"\n{ciphertext}\n == \n{expected_ciphertext}");

    let decrypted_plaintext = ChaCha20(key, nonce, counter, ciphertext);
    assert(decrypted_plaintext == plaintext, f"\n{decrypted_plaintext}\n == \n{plaintext}");
}

/// Converts a [u8] array to a [u32] array (little-endian), padding the end with 0s if needed
fn pack_bytes_to_u32_words_padded<let N: u32>(bytes: [u8; N]) -> [u32; (N + 3) / 4] {
    // NOTE: length calculation uses ceil division, so we round up if there is any remainder
    let mut padded = [0 as u8; ((N + 3) / 4) * 4];

    // Copy input into padded array
    for i in 0..N {
        padded[i] = bytes[i];
    }

    let mut out = [0 as u32; (N + 3) / 4];
    for i in 0..out.len() {
        out[i] = padded[i * 4] as u32
            | ((padded[i * 4 + 1] as u32) << 8)
            | ((padded[i * 4 + 2] as u32) << 16)
            | ((padded[i * 4 + 3] as u32) << 24);
    }

    out
}

/// Converts a [u32] array to a [u8] array (little-endian)
fn unpack_u32_words_to_bytes<let N: u32>(words: [u32; N]) -> [u8; N * 4] {
    let mut out = [0 as u8; N * 4];
    for i in 0..N {
        out[i * 4] = (words[i] & 0xff) as u8;
        out[i * 4 + 1] = ((words[i] >> 8) & 0xff) as u8;
        out[i * 4 + 2] = ((words[i] >> 16) & 0xff) as u8;
        out[i * 4 + 3] = ((words[i] >> 24) & 0xff) as u8;
    }
    out
}
