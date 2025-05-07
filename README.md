![Test workflow](https://github.com/sleepingshell/noir-chacha20/actions/workflows/ci.yaml/badge.svg)

# Noir-Chacha20

This is a Noir implementation of ChaCha20 as defined by [RFC7539](https://www.rfc-editor.org/rfc/rfc7539).

The [crates/chacha20_example](./crates/chacha20_example) provides a small binary implementation to measure circuit size.

```
+------------------+----------------------------+----------------------+--------------+-----------------+
| Package          | Function                   | Expression Width     | ACIR Opcodes | Brillig Opcodes |
+------------------+----------------------------+----------------------+--------------+-----------------+
| chacha20_example | main                       | Bounded { width: 4 } | 15930        | 17              |
+------------------+----------------------------+----------------------+--------------+-----------------+
| chacha20_example | directive_integer_quotient | N/A                  | N/A          | 8               |
+------------------+----------------------------+----------------------+--------------+-----------------+
| chacha20_example | directive_invert           | N/A                  | N/A          | 9               |
+------------------+----------------------------+----------------------+--------------+-----------------+
```

To time proving:

```sh
# build artifacts
nargo execute
# run Barretenberg prover
time bb prove -b ./target/chacha20_example.json -w ./target/chacha20_example.gz -o ./target
```

On a [AMD Ryzen 7 1800X](https://www.techpowerup.com/cpu-specs/ryzen-7-1800x.c1879), Barretenberg proving a single 116-byte message encryption took `TODO` seconds.
