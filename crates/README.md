# bonsai-ninja

Compiler-backed code navigation and security analysis for 20 languages, with
traceable source locations, stable evidence IDs, and source-to-sink flows.

This package is part of the
[bonsai-ninja workspace](https://github.com/gromhacks/bonsai-ninja). Its public
crates ship together: language adapters lower typed compiler facts, shared
analysis resolves relationships and dataflow, and the CLI and Rust SDK expose
the results.

![Python terminal walkthrough showing indexing, navigation, a compiler corridor, and a taint finding](https://raw.githubusercontent.com/gromhacks/bonsai-ninja/main/assets/bonsai-ninja-python-demo.gif)

## Use the CLI

```sh
cargo install bonsai-ninja --locked
bonsai-ninja --help
```

Prebuilt Linux, macOS, and Windows binaries for x64 and arm64 are available in
[GitHub releases](https://github.com/gromhacks/bonsai-ninja/releases).

## Documentation

- [Getting started](https://github.com/gromhacks/bonsai-ninja/blob/main/docs/getting-started.mdx)
- [CLI reference](https://github.com/gromhacks/bonsai-ninja/blob/main/docs/cli-reference.mdx)
- [Rust SDK guide](https://github.com/gromhacks/bonsai-ninja/blob/main/docs/contributing/sdk.mdx)
- [Output formats and completion metadata](https://github.com/gromhacks/bonsai-ninja/blob/main/docs/output-formats.mdx)
- [Native export schemas](https://github.com/gromhacks/bonsai-ninja/tree/main/schemas)
- [Security model and limitations](https://github.com/gromhacks/bonsai-ninja/blob/main/docs/security-spec.mdx)

Reports describe modeled static evidence, not a guarantee that all runtime
behavior or dependencies were understood. Check completion metadata, explicit
coverage warnings, and the cited code before drawing a security conclusion.

Licensed under the [MIT license](https://github.com/gromhacks/bonsai-ninja/blob/main/LICENSE).
