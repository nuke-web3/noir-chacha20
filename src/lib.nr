use dep::std;

struct ChaCha {
    state: [u32; 16]
}

/// Performs bitwise rotation. NOT safe for n > 32
fn left_rotation(x: &mut u32, n: u32) {
    *x = ( (*x << n) | (*x >> (32-n)) );
}

fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a += *b; *d ^= *a; left_rotation(d, 16);
    *c += *d; *b ^= *c; left_rotation(b, 12);
    *a += *b; *d ^= *a; left_rotation(d, 8);
    *c += *d; *b ^= *c; left_rotation(b, 7);
}

fn chacha20_block(key: [u32; 8], nonce: [u32; 3], counter: u32) -> [u8; 64] {
    let mut state = ChaCha::new(key, nonce, counter);
    let mut working_state = state.clone();

    for _i in 0..10 {
        working_state.inner_block();
    }

    state.add(working_state);
    state.to_le_bytes()
}

impl ChaCha {
    fn new(key: [u32; 8], nonce: [u32; 3], counter: u32) -> Self {
        Self {
            state: [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // Constants
                key[0], key[1],
                key[2], key[3],
                key[4], key[5],
                key[6], key[7],
                counter, nonce[0],
                nonce[1], nonce[2]
            ]
        }
    }

    fn clone(self) -> Self {
        let mut res = Self { state: [0; 16] };
        for i in 0..16 {
            res.state[i] = self.state[i];
        }

        res
    }

    fn add(&mut self, other: Self) {
        for i in 0..16 {
            self.state[i] += other.state[i];
        }
    }

    fn to_le_bytes(self) -> [u8; 64] {
        let mut res = [0; 64];
        for i in 0..16 {
            res[i*4] = (self.state[i] & 0xFF) as u8;
            res[i*4 + 1] = ((self.state[i] & 0xFF00) >> 8) as u8;
            res[i*4 + 2] = ((self.state[i] & 0xFF0000) >> 16) as u8;
            res[i*4 + 3] = ((self.state[i] & 0xFF000000) >> 24) as u8;
        }

        res
    }

    fn inner_block(&mut self) {
        let mut state_0 = self.state[0];
        let mut state_1 = self.state[1];
        let mut state_2 = self.state[2];
        let mut state_3 = self.state[3];
        let mut state_4 = self.state[4];
        let mut state_5 = self.state[5];
        let mut state_6 = self.state[6];
        let mut state_7 = self.state[7];
        let mut state_8 = self.state[8];
        let mut state_9 = self.state[9];
        let mut state_10 = self.state[10];
        let mut state_11 = self.state[11];
        let mut state_12 = self.state[12];
        let mut state_13 = self.state[13];
        let mut state_14 = self.state[14];
        let mut state_15 = self.state[15];

        quarter_round(&mut state_0, &mut state_4, &mut state_8, &mut state_12);
        quarter_round(&mut state_1, &mut state_5, &mut state_9, &mut state_13);
        quarter_round(&mut state_2, &mut state_6, &mut state_10, &mut state_14);
        quarter_round(&mut state_3, &mut state_7, &mut state_11, &mut state_15);
        quarter_round(&mut state_0, &mut state_5, &mut state_10, &mut state_15);
        quarter_round(&mut state_1, &mut state_6, &mut state_11, &mut state_12);
        quarter_round(&mut state_2, &mut state_7, &mut state_8, &mut state_13);
        quarter_round(&mut state_3, &mut state_4, &mut state_9, &mut state_14);

        self.state[0] = state_0;
        self.state[1] = state_1;
        self.state[2] = state_2;
        self.state[3] = state_3;
        self.state[4] = state_4;
        self.state[5] = state_5;
        self.state[6] = state_6;
        self.state[7] = state_7;
        self.state[8] = state_8;
        self.state[9] = state_9;
        self.state[10] = state_10;
        self.state[11] = state_11;
        self.state[12] = state_12;
        self.state[13] = state_13;
        self.state[14] = state_14;
        self.state[15] = state_15;
    
    }
}

// The test data of this function is from section 2.2.1 of RFC7539
#[test]
fn test_quarter_round() {
    let mut a = 0x11111111 as u32;
    let mut b = 0x01020304 as u32;
    let mut c = 0x9b8d6f43 as u32;
    let mut d = 0x01234567 as u32;

    quarter_round(&mut a, &mut b, &mut c, &mut d);

    assert(a == 0xea2a92f4);
    assert(b == 0xcb1cf8ce);
    assert(c == 0x4581472e);
    assert(d == 0x5881c4bb);
}

// The test data of this function is from section 2.3.2 of RFC7539
#[test]
fn test_block_function() {
    let mut key = [0 as u32; 8];
    for i in 0..8 {
        key[i] = (4*i | (4*i + 1) << 8 | (4*i + 2) << 16 | (4*i + 3) << 24);
    }

    let mut nonce = [0; 3];
    nonce[0] = 0x09000000;
    nonce[1] = 0x4a000000;

    let counter = 1;

    let result = chacha20_block(key, nonce, counter);

    let expected_result = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
    ];

    for i in 0..64 {
        assert(result[i] == expected_result[i]);
    }
}