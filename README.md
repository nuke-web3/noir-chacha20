![Test workflow](https://github.com/sleepingshell/noir-chacha20/actions/workflows/ci.yaml/badge.svg)
# Noir-Chacha20

This is a Noir implementation of ChaCha20 as defined by [RFC7539](https://www.rfc-editor.org/rfc/rfc7539).

The `crates/chacha20_example` provides a small binary implementation to measure circuit size.
```
+------------------+------------------------+--------------+----------------------+
| Package          | Language               | ACIR Opcodes | Backend Circuit Size |
+------------------+------------------------+--------------+----------------------+
| chacha20_example | PLONKCSat { width: 3 } | 23969        | 88105                |
+------------------+------------------------+--------------+----------------------+
```