# Contributing

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-change`
3. Make changes and add tests
4. Run `cargo test --workspace` and `cargo clippy --workspace`
5. Submit a pull request

## Code Standards

- `#![deny(unsafe_code)]` in all crates (except `targets/esp32`)
- No `unwrap()` in production code (tests are fine)
- Use `tracing` for logging, not `println!`
- Run `cargo fmt` before committing
- All public items must have doc comments

## Pull Requests

- One logical change per PR
- Include tests for new functionality
- Update documentation if behavior changes
- Reference related issues

## Proposing Protocol Changes

Protocol changes require an AIP (Arxia Improvement Proposal):
1. Copy `docs/aips/TEMPLATE.md`
2. Fill in all sections
3. Submit as a PR for discussion

## License

By contributing, you agree that your contributions will be licensed under
the Apache-2.0 OR MIT dual license.
