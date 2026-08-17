What This Reads:
    An NCA (content archive) or an NSP (submission package, which is a PFS0
    holding archives). The kind is detected from the file's contents unless
    --intype names it. This is the read side of `hacbrewpack`: it opens what
    that command produces.

    Gamecard images (XCI), boot packages, savedata, and update partitions are
    not supported. Nothing in this workspace builds them.

Keys:
    An NCA is encrypted throughout, so reading one needs the keyset it was
    sealed with. --keyset names a file; without it, keys.dat, keys.txt,
    keys.ini and prod.keys are tried in the working directory, then
    ~/.switch/prod.keys. An NSP needs no keys to list or extract: only the
    archives inside it are encrypted.

    A wrong header key is reported as a malformed archive, because a header
    decrypted with the wrong key is indistinguishable from noise.

Verification:
    --verify checks three things and reports each separately: the header
    signature, each section's FS header hash, and each section's contents
    against the hash table or IVFC tree covering them.

    Only the second of an NCA's two signatures is checked. The first is
    verified against a modulus built into the console, which this tool does
    not have. A title packed with --nosignncasig2, or built by another
    toolchain, will report the signature check as failed while every hash
    still passes.

Examples:
    # Show what an archive holds
    cargo nx tool hactool title.nca

    # Check an archive this toolchain packed
    cargo nx tool hactool --verify title.nca

    # List the archives inside a package, then unpack them
    cargo nx tool hactool title.nsp
    cargo nx tool hactool --outdir ./unpacked title.nsp

    # Recover the executable partition and the filesystem
    cargo nx tool hactool --exefsdir ./exefs --romfsdir ./romfs program.nca

    # Round-trip a build: pack, unpack, and check what came back
    cargo nx tool hacbrewpack --keepncadir
    cargo nx tool hactool --outdir ./unpacked hacbrewpack_nsp/*.nsp
    cargo nx tool hactool --verify ./unpacked/*.nca

    # Write the decrypted archive for inspection with other tools
    cargo nx tool hactool --plaintext title.plain.nca title.nca
