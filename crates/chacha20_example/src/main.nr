use dep::chacha20::chacha20;

fn main(key: [u8; 32], nonce: [u8; 12], counter: u32, plaintext: [u8; 114]) -> pub [u8; 114] {
    chacha20(key, nonce, counter, plaintext)
}
