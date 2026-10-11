"""The symbols file which is kept for each binary in the binaries folder.

It holds the PE information of the binary as key=value lines, followed by the
output of windhawk-symbol-helper.exe, zstd compressed. The PE information comes
first so that it can be read without decompressing the symbols.
"""

import re
from pathlib import Path

from compression import zstd

SYMBOLS_FILE_SUFFIX = '.txt.zst'

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
