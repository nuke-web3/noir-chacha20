use dep::chacha20::ChaCha20;

fn main(key: [u32; 8], nonce: [u32; 3], counter: u32, plaintext: [u8; 128]) -> pub [u8; 128]  {
    ChaCha20(key, nonce, counter, plaintext)    
}