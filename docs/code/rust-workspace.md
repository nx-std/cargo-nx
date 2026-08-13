---
name: "rust-workspace"
description: "Flat member layout, alphabetical members, one-way binary-to-library dependency edge, shared dependency inheritance. Load when adding a workspace member or editing the root Cargo.toml"
type: "arch"
scope: "global"
---

# Workspace Layout

**MANDATORY for ALL workspace-level organization in the workspace**

The workspace is flat and small: every member is a directory at the repository root, and the dependency graph
has exactly one shape — the binary crate consumes the libraries, and nothing consumes the binary. A reader who
knows that can place a new crate without reading any manifest.

The contents of an individual `Cargo.toml` — section ordering, dependency ordering within a section, feature
naming — are owned by [rust-crates](rust-crates.md). This document owns where members live and which of them
may depend on which.

## 1. Members Live At The Repository Root

A workspace member is a directory at the root, named exactly as the package it contains. There is no
`crates/` or `bin/` directory to sort members into, and no prefix scheme: the package in `nx-netloader/` is
named `nx-netloader`, and its rule documents, its `-p` flag, and its directory all spell the same string.

A member that exists only to support another member's build nests under it, because it has no independent
reason to be found. Build-support crates are `publish = false`.

```toml
# ❌ Bad — invents a layer the repository does not have; `cargo build -p nx-netloader`
# still works, so nothing fails, and the paths silently disagree with every doc and script.
members = [
    "crates/nx-netloader",
    "bin/cargo-nx",
]
```

```toml
# ✅ Good — the directory, the package name, and the `-p` argument are one string, so a
# reader who has seen the member list can locate any crate without searching.
members = [
    "cargo-nx",
    "cargo-nx/gen",
    "nx-netloader",
]
```

## 2. The `members` Array Is Alphabetically Ordered

Entries are sorted alphabetically, which puts a nested build-support member directly under its parent
(`cargo-nx`, then `cargo-nx/gen`) without a second rule to say so.

The ordering is not cosmetic: two branches each adding a member conflict only when the names collide in the
sort, instead of both appending to the same last line.

## 3. Libraries Never Depend On The Binary

`cargo-nx` is the binary crate. It depends on `nx-netloader`; neither that library, nor any library added
later, may depend on `cargo-nx`. The edge points one way, always.

The reason is that the libraries are the reusable half. A library that reaches back into the binary drags the
whole CLI — its argument parser, its logging setup, its subcommand surface — into anything that wants only
the netload transfer, and the coupling is invisible until someone tries to use the library elsewhere.

A build-support member is the one exception, and it is not a counterexample: it depends on its parent as a
**build-dependency** to generate an artifact, not to be linked into it.

```toml
# ❌ Bad — a library reaching back into the CLI for one helper. The next consumer of
# nx-netloader now compiles clap to send an NRO over the network.
[package]
name = "nx-netloader"

[dependencies]
cargo-nx = { path = "../cargo-nx" }
```

```toml
# ✅ Good — the binary consumes the libraries and the libraries know nothing of it, so
# nx-netloader can be depended on without pulling in a command-line interface.
[package]
name = "cargo-nx"

[dependencies]
nx-netloader = { version = "0.1.0", path = "../nx-netloader" }
```

## 4. A Dependency Shared By Two Members Is Declared Once

A dependency that more than one member needs is declared in the root `[workspace.dependencies]`, and each
member inherits it with `.workspace = true`. A dependency only one member needs stays in that member's
manifest.

Declaring a shared version twice means the two copies drift on the next bump, and Cargo will happily build
both, so the divergence surfaces as a duplicated crate in the tree rather than as an error.

```toml
# ❌ Bad — two members pinning the same crate independently. A bump applied to one leaves
# the workspace compiling two incompatible thiserror versions with no warning.

# cargo-nx/Cargo.toml
[dependencies]
thiserror = "2.0"

# nx-netloader/Cargo.toml
[dependencies]
thiserror = "1.0"
```

```toml
# ✅ Good — one version, one place to bump it, and a member's manifest states only that it
# needs the crate rather than which version it happens to want.

# Cargo.toml
[workspace.dependencies]
thiserror = "2.0"

# cargo-nx/Cargo.toml
[dependencies]
thiserror.workspace = true
```

A member that needs different features from the shared version writes
`thiserror = { workspace = true, features = ["..."] }` rather than restating the version.

## Checklist

Before committing workspace changes, verify:

- [ ] A new member is a directory at the repository root, named exactly as its package
- [ ] A build-support member nests under the crate it serves and sets `publish = false`
- [ ] The root `members` array is alphabetically ordered
- [ ] No library member declares a dependency on `cargo-nx`
- [ ] A dependency needed by two or more members is declared in `[workspace.dependencies]`
- [ ] Members consuming a shared dependency use `<name>.workspace = true`, adding features but never a version

## References

- [rust-crates](rust-crates.md) - Related: Owns `Cargo.toml` section ordering, dependency ordering within a
  section, and feature-flag naming
- [rust-mods-graph](rust-mods-graph.md) - Foundation: Owns the same one-way rule one level down, between
  modules inside a crate
- [principle-information-hiding](principle-information-hiding.md) - Foundation: Why a library exposing itself
  to its consumer's consumer is a coupling defect
