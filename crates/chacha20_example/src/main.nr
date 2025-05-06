use dep::chacha20::ChaCha20;

fn main(key: [u8; 32], nonce: [u8; 12], counter: u32, plaintext: [u8; 16]) -> pub [u8; 16] {
    ChaCha20(key, nonce, counter, plaintext)
}
