# Windhawk mod symbol cache

A repository that generates an online cache for mod symbols in Windhawk. Having
the online cache enables mods to quickly get the required offsets without having
to download and parse the full symbol files.

## Ported symbols

A binary whose PDB isn't on the Microsoft symbol server can't have its
symbols extracted. Given a copy of the binary, a symbol porter can find them
by matching the binary against builds which have a PDB, and its result can
be committed as `ported_symbols/<binary>/<arch>/<sha256>.<ext>.txt.zst`. The
cache uses it until the binary's own symbols are extracted:

- Only the ported symbols are listed, so the engine looks for any other
  symbol in the PDB, and fails if it isn't available. Symbols which are known
  not to exist are listed as missing. The second value of the cache files is
  tagged `_ported`.
- The PDB is looked for on every run, and once it's available, the binary's
  own symbols replace the ported ones.
- The status pages show 🟡 for the PDB of a binary with ported symbols.

A ported symbols file can be deleted once its binary's PDB is available.
