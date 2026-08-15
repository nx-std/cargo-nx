EXAMPLES:
    Pack a title from the conventional directory layout:
        cargo nx tool hacbrewpack

    Pack without a read-only filesystem, keeping the individual NCAs:
        cargo nx tool hacbrewpack --noromfs --keepncadir

    Rename a title and stamp a different title ID into every archive:
        cargo nx tool hacbrewpack --titleid 0100000000001000 --titlename "My Homebrew"

DIRECTORY LAYOUT:
    exefs/      main.npdm and the executable          (required)
    control/    control.nacp and the icon             (required)
    romfs/      the title's read-only filesystem      (unless --noromfs)
    logo/       the logo shown while loading          (unless --nologo)

    The HTML manual and the legal information are packed only when --htmldocdir
    and --legalinfodir name a directory.

KEYSET:
    Two keys are needed: `header_key`, and `key_area_key_application_XX` for the
    generation given by --keygeneration, counted from zero. Either may be listed
    directly or derived from `master_key_XX` and the generation seeds beside it.

    With no --keyset, these are tried in order:
        ./keys.dat, ./keys.txt, ./keys.ini, ./prod.keys, $HOME/.switch/prod.keys

    Derivation stops at the master keys. A keyset that carries only the secure
    boot key and the TSEC key is not enough: those are console-unique, and the
    chain below the master keys is not reproduced here.

PATCHING:
    Unless --nosignncasig2 is given, the ACID public key in exefs/main.npdm is
    replaced with the key that signs the program NCA header, which is what makes
    the console's second signature check pass. --titleid rewrites the title ID in
    the descriptor, and --titlename, --titlepublisher, --titleid and the default
    logo handling rewrite control/control.nacp.

    Both files are edited in place, and the original is copied into --backupdir
    with a timestamped name before anything is written.

OUTPUT:
    The NSP is written to --nspdir as <titleid>.nsp. The individual NCAs are
    written to --ncadir only with --keepncadir, which first clears that directory
    so it holds this build and nothing carried over from an earlier one.

NOTES:
    Every intermediate is assembled in memory, so no temporary directory is used.
    --tempdir is accepted so existing invocations keep working, and is ignored.

    Builds are reproducible except for the program NCA header signature: the
    signature scheme the console checks is randomised, so that one archive — and
    the NSP containing it — differs between runs. Pass --nosignncasig2 for a
    byte-identical rebuild, at the cost of the second signature check.
