/// Runs a 64-byte block of chacha20.
/// A new working state is instantiated with the key, nonce and counter.
/// Then run the `inner_block` function 10 times on the working state.
/// After the 10 rounds, the working state is added to the original state
///
/// Return: the serialized bytes of the working state (64 bytes)
pub fn chacha20_block(key: [u32; 8], nonce: [u32; 3], counter: u32) -> [u32; 16] {
    let mut state = ChaChaState::new(key, nonce, counter);
    let mut working_state = ChaChaState::new(key, nonce, counter);

    for _i in 0..10 {
        working_state.inner_block();
    }

    state.add(working_state);
    state.state
}

/// Structure that holds the chacha20 state
struct ChaChaState {
    state: [u32; 16],
}

impl ChaChaState {
    /// Instantiate a new chacha20 state with the require parameters
    fn new(key: [u32; 8], nonce: [u32; 3], counter: u32) -> Self {
        Self {
            state: [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // Constants
                key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], // Key
                counter, nonce[0], nonce[1], nonce[2],
            ],
        }
    }

    /// Return a copy of self
    fn clone(self) -> Self {
        let mut res = Self { state: [0; 16] };
        for i in 0..16 {
            res.state[i] = self.state[i];
        }

        res
    }

    /// Add two ChaChaState's together elementwise
    fn add(&mut self, other: Self) {
        for i in 0..16 {
            self.state[i] = std::wrapping_add(self.state[i], other.state[i]);
        }
    }

    /// Serializes the 16 4-byte word working state to 64 bytes (`u8`)
    fn to_le_bytes(self) -> [u8; 64] {
        let mut res = [0; 64];
        for i in 0..16 {
            res[i * 4] = (self.state[i] & 0xFF) as u8;
            res[i * 4 + 1] = ((self.state[i] & 0xFF00) >> 8) as u8;
            res[i * 4 + 2] = ((self.state[i] & 0xFF0000) >> 16) as u8;
            res[i * 4 + 3] = ((self.state[i] & 0xFF000000) >> 24) as u8;
        }

        res
    }

    /// Runs quarter round on the working state 8 times:
    /// 0 4 8 12
    /// 1 5 9 13
    /// 2 6 10 14
    /// 3 7 11 15
    /// 0 5 10 15
    /// 1 6 11 12
    /// 2 7 8 13
    /// 3 4 9 14
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

/// Performs a quarter round of chacha20 on 4 32-byte values.
fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = std::wrapping_add(*a, *b);
    *d ^= *a;
    left_rotation(d, 16);

    *c = std::wrapping_add(*c, *d);
    *b ^= *c;
    left_rotation(b, 12);

    *a = std::wrapping_add(*a, *b);
    *d ^= *a;
    left_rotation(d, 8);

    *c = std::wrapping_add(*c, *d);
    *b ^= *c;
    left_rotation(b, 7);
}

/// Performs bitwise rotation.
///
/// ### SAFETY
///
/// You *must* guarantee that `n <= 32` at runtime!
/// `32 - n` could underflow!
///
/// Consider using `assert(n < 32);`
fn left_rotation(x: &mut u32, n: u8) {
    *x = (*x << n) + (*x >> (32 - n));
}

// The test data of this function is from section 2.1.1 of RFC7539
#[test]
fn test_quarter_round() {
    let mut a = 0x11111111 as u32;
    let mut b = 0x01020304 as u32;
    let mut c = 0x9b8d6f43 as u32;
    let mut d = 0x01234567 as u32;

    quarter_round(&mut a, &mut b, &mut c, &mut d);

    assert(a == 0xea2a92f4, f"got {a}");
    assert(b == 0xcb1cf8ce, f"got {b}");
    assert(c == 0x4581472e, f"got {c}");
    assert(d == 0x5881c4bb, f"got {d}");
}

// The test data of this function is from section 2.3.2 of RFC7539
#[test]
fn test_block_function() {
    let mut key = [0 as u32; 8];
    for i in 0..8 {
        key[i] = (4 * i | (4 * i + 1) << 8 | (4 * i + 2) << 16 | (4 * i + 3) << 24);
    }

    let mut nonce = [0; 3];
    nonce[0] = 0x09000000;
    nonce[1] = 0x4a000000;

    let counter = 1;

    let result = chacha20_block(key, nonce, counter);

    let expected_result = [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
        0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
        0xe883d0cb, 0x4e3c50a2,
    ];

    assert(result == expected_result, f"\n{result}\n == \n{expected_result}");
}
