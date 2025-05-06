use dep::chacha20::ChaCha20;

fn main(key: [u8; 32], nonce: [u32; 3], counter: u32, plaintext: [u32; 16]) -> pub [u32; 16] {
    ChaCha20(key, nonce, counter, plaintext)
}
