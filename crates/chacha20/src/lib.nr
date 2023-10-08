mod block;

/// Encrypts an arbitrary sized message by running chacha20.
/// The stream cipher of ChaCha20 is composed of running the block_function with an increasing counter,
/// which provides 64-bytes of keystream at a time.
fn ChaCha20<N>(key: [u32; 8], nonce: [u32; 3], counter: u32, plaintext: [u32; N]) -> [u32; N] {
    let mut res = [0; N];
    for j in 0..(N as u32/16) {
        let key_stream = block::chacha20_block(key, nonce, counter+j as u32);
        for t in 0..16 {
            res[16*j + t] = plaintext[16*j + t] ^ key_stream[t];
        }
    }

    if (N as u32 % 16 != 0) {
        let j = (N as u32 / 16) as Field;
        let key_stream = block::chacha20_block(key, nonce, counter+j as u32);
        for t in 0..((N as u32 % 16) as Field) {
            res[16*j + t] = plaintext[16 * j + t] ^ key_stream[t];
        }
    }

    res
}

/// The test data of this function is from section 2.4.2 of RFC7539, except that it pads 2 extra 0 bytes
/// since, for now, the function operations on 4-byte words
#[test]
fn test_ChaCha20() {
    let mut key = [0 as u32; 8];
    for i in 0..8 {
        key[i] = (4*i | (4*i + 1) << 8 | (4*i + 2) << 16 | (4*i + 3) << 24);
    }

    let mut nonce = [0; 3];
    nonce[1] = 0x4a000000;

    let counter = 1;

    let plaintext = [
        0x4c616469, 0x65732061, 0x6e642047, 0x656e746c,
        0x656d656e, 0x206f6620, 0x74686520, 0x636c6173,
        0x73206f66, 0x20273939, 0x3a204966, 0x20492063,
        0x6f756c64, 0x206f6666, 0x65722079, 0x6f75206f,
        0x6e6c7920, 0x6f6e6520, 0x74697020, 0x666f7220,
        0x74686520, 0x66757475, 0x72652c20, 0x73756e73,
        0x63726565, 0x6e20776f, 0x756c6420, 0x62652069,
        0x742e0000
    ];

    let ciphertext = ChaCha20(key, nonce, counter, plaintext);

    let expected_ciphertext = [
        0x6e2e359a, 0x2568f980, 0x41ba0728, 0xdd0d6981,
        0xe97e7aec, 0x1d4360c2, 0x0a27afcc, 0xfd9fae0b,
        0xf91b65c5, 0x524733ab, 0x8f593dab, 0xcd62b357,
        0x1639d624, 0xe65152ab, 0x8f530c35, 0x9f0861d8,
        0x07ca0dbf, 0x500d6a61, 0x56a38e08, 0x8a22b65e,
        0x52bc514d, 0x16ccf806, 0x818ce91a, 0xb7793736,
        0x5af90bbf, 0x74a35be6, 0xb40b8eed, 0xf2785e42,
        0x874d7403
    ];

    let decrypted_plaintext = ChaCha20(key, nonce, counter, ciphertext);

    for i in 0..plaintext.len() {
        assert(ciphertext[i] == expected_ciphertext[i]);
    }

    for i in 0..plaintext.len() {
        assert(decrypted_plaintext[i] == plaintext[i]);
    }
}