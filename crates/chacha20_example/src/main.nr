use dep::chacha20::ChaCha20;

fn main(key: [u8; 32], nonce: [u8; 12], counter: u32, plaintext: [u32; 16]) -> pub [u32; 16] {
    ChaCha20(key, nonce, counter, plaintext)
}
