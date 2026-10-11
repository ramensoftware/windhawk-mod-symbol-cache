"""Converts the symbols files in a binaries folder from the uncompressed .txt
layout, where the PE information lines follow the symbols, to the layout of
symbols_file.py.
"""

import re
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from symbols_file import SYMBOLS_FILE_SUFFIX, write_symbols_file

_PE_INFO_LINE_PATTERN = re.compile(rb'(\w+)=(.*)')


def split_pe_info(data: bytes):
    """Split the trailing PE information lines off the symbols."""
    matches = []
    end = len(data)

    while end > 0:
        start = data.rfind(b'\n', 0, end - 1) + 1
        match = _PE_INFO_LINE_PATTERN.fullmatch(data[start:end].rstrip(b'\r\n'))
        if not match:
            break

        matches.append(match)
        end = start

    pe_info = {m[1].decode(): m[2].decode() for m in reversed(matches)}
    return data[:end], pe_info


def migrate_symbols_file(path: Path):
    symbols, pe_info = split_pe_info(path.read_bytes())
    target_path = path.with_name(path.name.removesuffix('.txt') + SYMBOLS_FILE_SUFFIX)
    write_symbols_file(target_path, pe_info, symbols)
    path.unlink()


def main():
    parser = ArgumentParser()
    parser.add_argument('binaries_folder', type=Path)
    args = parser.parse_args()

    paths = list(args.binaries_folder.rglob('*.txt'))

    with ThreadPoolExecutor() as executor:
        list(executor.map(migrate_symbols_file, paths))

    print(f'Migrated {len(paths)} symbols files')


if __name__ == '__main__':
    main()
