use dep::chacha20::ChaCha20;

fn main(key: [u8; 32], nonce: [u8; 12], counter: u32, plaintext: [u8; 116]) -> pub [u8; 116] {
    ChaCha20(key, nonce, counter, plaintext)
}
