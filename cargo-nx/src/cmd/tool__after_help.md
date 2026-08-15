Toolchain Utilities:
    `cargo nx tool` groups standalone reimplementations of the devkitPro and
    switch-tools post-processors. Each utility runs in-process — no external
    binaries are invoked — and can be used independently of a Cargo project.

Available Utilities:
    elf2nro      Convert an ELF file to an NRO container
    elf2nso      Convert an ELF file to an NSO container
    elf2kip      Convert an ELF file to a KIP container
    build_pfs0   Build a PFS0 archive from a directory
    build_romfs  Build a RomFS image from a directory
    npdmtool     Compile a JSON descriptor into an NPDM
    nacptool     Create or manipulate NACP control data
    bin2s        Convert binary files to GAS assembly source
    bin2c        Convert binary files to C source (alias: raw2c)
    hacbrewpack  Pack a homebrew title into an installable NSP

Examples:
    # Show the options for a specific utility
    cargo nx tool elf2nro --help

    # Convert an ELF to an NRO container
    cargo nx tool elf2nro app.elf app.nro
