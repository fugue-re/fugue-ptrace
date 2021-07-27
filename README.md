# fugue-ptrace

A ptrace wrapper based on the wonderful [ptrace-burrito].

## Building

For 32-bit:

```
cargo build --target=i686-unknown-linux-gnu --release
```

For 64-bit:

```
cargo build --target=x86_64-unknown-linux-gnu --release
```

[ptrace-burrito]: https://github.com/brainsmoke/ptrace-burrito
