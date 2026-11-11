"""The symbols file which is kept for each binary in the binaries folder.

It holds the PE information of the binary as key=value lines, followed by the
output of windhawk-symbol-helper.exe, zstd compressed. The PE information comes
first so that it can be read without decompressing the symbols.

A ported symbols file has the same format. It holds symbols which a symbol
porter, kept outside of this repository, found by matching the binary against
builds with a PDB, for a binary whose PDB isn't on the symbol server.
Its PE information has a 'ported' entry, and it may list symbols known not to
exist, one per line after ABSENT_SYMBOL_PREFIX. Ported symbols files are kept
in PORTED_SYMBOLS_FOLDER, and are used until the binary's own symbols are
extracted.
"""

import re
from pathlib import Path

from compression import zstd

SYMBOLS_FILE_SUFFIX = '.txt.zst'

# The addresses which were found in a symbols file are kept next to it.
ADDRESSES_FILE_SUFFIX = '.addresses.json'

PORTED_SYMBOLS_FOLDER = Path(__file__).parent.parent / 'ported_symbols'

# A ported symbols file in the binaries folder, next to where the binary's own
# symbols file would be.
PORTED_SYMBOLS_FILE_SUFFIX = '.ported' + SYMBOLS_FILE_SUFFIX

ABSENT_SYMBOL_PREFIX = 'absent: '

# A file is written once and then read on every run. Higher levels barely make
# the files smaller and compress several times slower.
_COMPRESSION_LEVEL = 9

_PE_INFO_LINE_PATTERN = re.compile(rb'(\w+)=(.*)')


def write_symbols_file(path: Path, pe_info: dict[str, object], symbols: bytes):
    header = ''.join(f'{key}={value}\n' for key, value in pe_info.items())

    with zstd.open(path, 'wb', level=_COMPRESSION_LEVEL) as f:
        f.write(header.encode())
        f.write(symbols)


def read_symbols_file_pe_info(path: Path):
    pe_info: dict[str, str] = {}

    with zstd.open(path, 'rb') as f:
        for line in f:
            match = _PE_INFO_LINE_PATTERN.fullmatch(line.rstrip(b'\r\n'))
            if not match:
                break

            pe_info[match[1].decode()] = match[2].decode()

    return pe_info


def read_symbols_file_lines(path: Path):
    """Every line of the file, PE information included, without line breaks."""
    return zstd.decompress(path.read_bytes()).splitlines()


def addresses_file_path(symbols_file: Path) -> Path:
    return symbols_file.with_name(symbols_file.name.removesuffix(SYMBOLS_FILE_SUFFIX) + ADDRESSES_FILE_SUFFIX)


def binary_file_name(binary_name: str, hash: str) -> str:
    """The name under which a binary is kept, e.g. '<hash>.dll' for
    'taskbar.dll'."""
    return re.sub(r'^.*\.(.*)$', rf'{hash}.\g<1>', binary_name)


def ported_symbols_path(binary_name: str, arch: str, file_name: str) -> Path:
    """The committed ported symbols file of a binary, e.g. for 'taskbar.dll',
    'amd64' and '<hash>.dll'."""
    return PORTED_SYMBOLS_FOLDER / binary_name / arch / (file_name + SYMBOLS_FILE_SUFFIX)
