# nx-tools

Tooling for Nintendo Switch Rust homebrew development.

## Tools

### cargo-nx

A cargo subcommand to simplify creating and building Nintendo Switch homebrew projects, avoiding the need for makefiles, scripts, or duplicated linker/target files across projects. Supports generating NRO and NSP formats after compilation.

#### Installation

1. If not already installed, install `rust-src`:

    ```bash
    rustup component add rust-src
    ```

2. Install `cargo-nx`:

    ```bash
    cargo install cargo-nx --git https://github.com/nx-std/tools
    ```

#### Usage

The program can be executed as `cargo-nx` or as a cargo subcommand (`cargo nx`), and provides the following subcommands:

**`new`** -- Create a new Rust project for the Nintendo Switch.

```
cargo nx new <path> [--name <name>] [--edition <2015|2018|2021>] [--type <lib|nro|nsp>]
```

**`build`** -- Build a Rust project for the Nintendo Switch.

```
cargo nx build [-r|--release] [-p <path>] [-t <triple>] [-v|--verbose]
```

Defaults to the `aarch64-nintendo-switch-freestanding` target triple.

**`link`** -- Send an NRO file to a Nintendo Switch running nx-hbmenu's netloader.

```
cargo nx link [options] <file.nro> [-- <nro args...>]
```

Options: `-a <ip>` (address), `-r <n>` (discovery retries), `-p <path>` (upload path), `-s` (start stdio server after transfer).

**Note:** This command provides the same functionality as the standalone `nxlink` tool from devkitPro.

#### Low-Level Tool Subcommands

`cargo-nx` also exposes the following low-level packaging and conversion tools, providing Rust implementations of utilities traditionally found in devkitPro's `switch-tools`:

**`elf2nro`** -- Convert an ELF executable to NRO (Nintendo Relocatable Object) format.

```
cargo nx elf2nro <elf-file> <nro-file> [options]
```

Options: `--icon=<iconpath>`, `--nacp=<control.nacp>`, `--romfs=<image>`, `--romfsdir=<directory>`, `--alignedheader`.

**`elf2nso`** -- Convert an ELF executable to NSO (Nintendo Shared Object) format.

```
cargo nx elf2nso <elf-file> <nso-file>
```

**`elf2kip`** -- Convert an ELF executable to KIP (Kernel Initial Process) format.

```
cargo nx elf2kip <elf-file> <json-file> <kip-file>
```

**`build_pfs0`** -- Build a PFS0 (Partition FileSystem) archive from a directory.

```
cargo nx build_pfs0 <in-directory> <out-pfs0-filepath>
```

**`build_romfs`** -- Build a RomFS (Read-Only Memory FileSystem) image from a directory.

```
cargo nx build_romfs <in-directory> <out-romfs-filepath>
```

**`nacptool`** -- Create NACP (Nintendo Application Control Property) metadata files.

```
cargo nx nacptool --create <name> <author> <version> <outfile> [options]
```

Options: `--titleid=<titleID>`.

**Note:** The `--titleid` option requires exactly 16 hexadecimal digits (e.g., `0100000000000000`). This is stricter than the original C implementation, which accepts variable-length hex strings.

**`npdmtool`** -- Generate NPDM (Nintendo Program Description Metadata) files from JSON specifications.

```
cargo nx npdmtool <json-file> <npdm-file>
```

**`hacbrewpack`** -- Pack a homebrew title into an installable NSP.

```
cargo nx tool hacbrewpack [options]
```

Reads `exefs/` and `control/` (and `romfs/`, `logo/` unless skipped), builds the program, control,
optional manual, and metadata NCAs, and writes `<titleid>.nsp`. Needs a keyset carrying `header_key`
and `key_area_key_application_XX`, taken from `--keyset` or from `./keys.dat`, `./keys.txt`,
`./keys.ini`, `./prod.keys`, or `$HOME/.switch/prod.keys`.

Options: `--keyset`, `--nspdir`, `--ncadir`, `--backupdir`, `--exefsdir`, `--romfsdir`, `--logodir`,
`--controldir`, `--htmldocdir`, `--legalinfodir`, `--noromfs`, `--nologo`, `--keygeneration`,
`--keyareakey`, `--sdkversion`, `--plaintext`, `--keepncadir`, `--nosignncasig2`, `--titleid`,
`--titlename`, `--titlepublisher`, `--nopatchnacplogo`.

**Note:** `main.npdm` and `control.nacp` are patched in place; the originals are copied into
`--backupdir` first.

**`hactool`** -- Read, verify, and extract an NCA, an NSP, or a KIP1.

```
cargo nx tool hactool [options] <file>
```

The read side of `hacbrewpack`. The container is detected from the file's contents unless
`--intype` names it. An NCA is encrypted throughout, so opening one needs the keyset it was sealed
with, taken from the same locations `hacbrewpack` searches; listing or extracting an NSP or a KIP1
needs no keys.

`--verify` reports each check separately: the header signature, every FS header hash, and every
section's contents against the PFS0 hash table or IVFC tree covering them. On a package it also
checks each archive against the content meta naming it, which needs the keyset.

Options: `--keyset`, `--intype`, `--verify`, `--plaintext`, `--outdir`, `--exefsdir`, `--romfsdir`,
`--section0dir`, `--section1dir`, `--section2dir`, `--section3dir`.

**Note:** Only the second of an NCA's two signatures is checkable. The first is verified against a
modulus that lives in the console, so a title packed by another toolchain reports an unverifiable
signature while every hash still passes. An archive packed by `hacbrewpack` other than the program
one carries no signature at all and is reported as `not signed` rather than failed.

#### Intentional Behavior Differences

The Rust implementations aim for practical compatibility with the original C tools from `switch-tools`, but include the following intentional differences:

- **`nacptool --titleid` validation**: Requires exactly 16 hexadecimal digits, rejecting shorter or invalid inputs that the C version would parse using `scanf`'s `%016llx` format specifier.
- **`hacbrewpack` builds in memory**: every intermediate is assembled in memory rather than staged through a temporary directory, so `--tempdir` is accepted for compatibility and ignored. Key derivation stops at the master keys: a keyset supplying only console-unique secrets is reported as missing the key it could not derive.
- **`hactool` reads what this workspace writes**: NCA, NSP, and KIP1 only. Gamecard images (XCI), boot packages, savedata, and update partitions are out of scope, because nothing here builds them. A package's own metadata archive is the one file a content meta cannot cover, since it would have to list itself, so no hash in the package verifies it.

For detailed package format documentation (NRO/NACP fields, NSP/NPDM configuration), see [`cargo-nx/README.md`](cargo-nx/README.md).

### nx-netloader

A Rust library implementing the nx-hbmenu netloader protocol for transferring NRO files to a Nintendo Switch over the network.

#### Protocol

The netloader protocol has three phases:

1. **Discovery** (UDP) -- The client broadcasts a `nxboot` ping to port 28280. The Switch responds with `bootnx` to port 28771, revealing its IP address.
2. **Transfer** (TCP) -- The client connects to port 28280, sends the file name and size, then streams the NRO data in zlib-compressed chunks. Command-line arguments for the NRO are sent after the file data.
3. **Stdio server** (TCP, optional) -- After transfer, the client can listen on port 28771 for stdout/stderr output redirected from the running NRO via libnx's nxlink stdio feature.
