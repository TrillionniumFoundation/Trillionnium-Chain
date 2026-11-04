# Maintained token-pasting compatibility facade

The package identity satisfies existing paste = 1 dependencies, while every
exported macro delegates to pastey = 0.2.3. No unmaintained paste source is
copied or executed. This is an implementation replacement, not an advisory
exception. The upstream migration documents the dependency alias and preserves
existing modifier behavior: https://docs.rs/pastey/0.2.3/pastey/ .

The frozen Cargo graph and actual RISC Zero proof controls must verify this
replacement before it can qualify. deny.toml remains unchanged.
