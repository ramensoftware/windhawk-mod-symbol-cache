import json
import re
from argparse import ArgumentParser
from enum import StrEnum
from pathlib import Path

from fast_import import FastImportFiles
from symbols_file import (ADDRESSES_FILE_SUFFIX, SYMBOLS_FILE_SUFFIX,
                          read_symbols_file_lines, read_symbols_file_pe_info)

# For Windhawk older than v1.5.
MOD_CACHE_LEGACY_SEPARATORS = {
    'taskbar-button-click': '@',
    'taskbar-clock-customization': '@',
    'taskbar-thumbnail-reorder': '@',
    'virtual-desktop-taskbar-order': '@',
}


class ArchPrefix(StrEnum):
    x86 = 'arch=x86\\'
    amd64 = 'arch=x64\\'
    arm64 = 'arch=ARM64\\'


def get_all_used_symbols_per_binary(extracted_symbols: dict[str, dict[str, dict[str, list[str]]]]):
    all_used_symbols_per_binary: dict[str, set[str]] = {}

    for archs in extracted_symbols.values():
        for binaries in archs.values():
            for binary_name, symbols in binaries.items():
                all_used_symbols_per_binary.setdefault(binary_name, set()).update(symbols)

    return all_used_symbols_per_binary


def create_mod_cache_file(
    files: FastImportFiles,
    cache_path: str,
    sep: str,
    val1: str,
    val2: str,
    mod_symbols: list[str],
    symbol_addresses: dict,
    arch_for_hybrid_pe: str,
):
    if sep in val1:
        raise Exception(f'Invalid value with separator {sep}: {val1}')

    if sep in val2:
        raise Exception(f'Invalid value with separator {sep}: {val2}')

    content = f'1{sep}{val1}{sep}{val2}'

    for symbol in mod_symbols:
        if sep in symbol:
            raise Exception(f'Invalid symbol with separator {sep}: {symbol}')

        address1 = symbol_addresses.get(symbol, '')
        if address1 is None:
            raise Exception(f'Duplicate symbol {symbol}')

        if arch_for_hybrid_pe and not re.match(r'arch=\w+\\', symbol):
            symbol_arch_prefix_mapping = {
                'x86': ArchPrefix.x86,
                'amd64': ArchPrefix.amd64,
                'arm64': ArchPrefix.arm64,
            }
            symbol_arch_prefix = symbol_arch_prefix_mapping[arch_for_hybrid_pe]
            address2 = symbol_addresses.get(symbol_arch_prefix + symbol, '')
            if address2 is None:
                raise Exception(f'Duplicate symbol {symbol}')

            if address1 and address2:
                raise Exception(f'Duplicate symbol {symbol}')

            address = address1 or address2
        else:
            address = address1

        content += f'{sep}{symbol}{sep}{address}'

    files.write(cache_path, content)


def find_symbol_addresses(symbols_file: Path, symbols: set[str]):
    """The address of each of the symbols in a symbols file, or None for one
    which appears more than once. A symbol without an arch prefix is also looked
    for with each of the prefixes."""
    symbols_bytes_with_prefix = set()
    for symbol in symbols:
        symbols_bytes_with_prefix.add(symbol.encode())
        if not re.match(r'arch=\w+\\', symbol):
            for arch_prefix in ArchPrefix:
                symbols_bytes_with_prefix.add((arch_prefix + symbol).encode())

    addresses: dict[str, int | None] = {}

    # This is a hot loop, keep it optimized.
    for line in read_symbols_file_lines(symbols_file):
        if line == b'':
            continue

        if line[0] == 91:  # '['
            assert line[9] == 93 and line[10] == 32  # '] '
            symbol = line[11:]
            if symbol in symbols_bytes_with_prefix:
                symbol = symbol.decode()
                address = int(line[1:9], 16)
                if symbol in addresses:
                    # Duplicate symbol.
                    addresses[symbol] = None
                else:
                    addresses[symbol] = address
            continue

        line = line.decode()

        # The PE information, which is read separately, and the symbol count.
        if not line.startswith(('machine=', 'timestamp=', 'image_size=',
                                'is_hybrid=', 'pdb_fingerprint=',
                                'pdb_filename=', 'Found ')):
            raise Exception(f'Unknown line: {line}')

    return addresses


def get_symbol_addresses(symbols_file: Path, symbols: set[str]):
    """find_symbol_addresses, with the result kept in an addresses file next to
    the symbols file. A symbols file never changes, so it's only scanned again
    for a symbol which it wasn't scanned for before."""
    addresses_file = symbols_file.with_name(
        symbols_file.name.removesuffix(SYMBOLS_FILE_SUFFIX) + ADDRESSES_FILE_SUFFIX)

    if addresses_file.exists():
        cached = json.loads(addresses_file.read_text(encoding='utf-8'))
        if symbols <= set(cached['symbols']):
            return cached['addresses']

    addresses = find_symbol_addresses(symbols_file, symbols)

    addresses_file.write_text(json.dumps({
        'symbols': sorted(symbols),
        'addresses': addresses,
    }), encoding='utf-8')

    return addresses


def create_mod_cache_for_symbols_file(
    files: FastImportFiles,
    extracted_symbols: dict,
    binary_name: str,
    arch: str,
    symbols_file: Path,
    all_used_symbols: set[str],
):
    pe_info = read_symbols_file_pe_info(symbols_file)
    timestamp = int(pe_info['timestamp'])
    image_size = int(pe_info['image_size'])
    is_hybrid = 'is_hybrid' in pe_info
    pdb_fingerprint = pe_info.get('pdb_fingerprint')

    # For now, only cache ARM64 hybrid symbols. Later, it's possible to add
    # other architectures for hybrid symbols, as well as other architectures
    # within the hybrid binaries:
    # * x86 -> x86, arm64
    # * amd64 -> amd64, arm64
    # * arm64 -> amd64, arm64
    if is_hybrid and arch != 'arm64':
        return

    symbols = get_symbol_addresses(symbols_file, all_used_symbols)

    for mod_name, mod_archs in extracted_symbols.items():
        if arch not in mod_archs:
            continue

        if binary_name not in mod_archs[arch]:
            continue

        # Legacy symbol cache.
        legacy_cache_key = None

        if not is_hybrid:
            if arch == 'amd64':
                legacy_cache_key = f'symbol-cache-{binary_name}'
            elif arch == 'x86':
                legacy_cache_key = f'symbol-{arch}-cache-{binary_name}'

        if legacy_cache_key:
            symbol_cache_file_path = f'{mod_name}/{legacy_cache_key}/{timestamp}-{image_size}.txt'

            sep = MOD_CACHE_LEGACY_SEPARATORS.get(mod_name, '#')

            create_mod_cache_file(
                files,
                symbol_cache_file_path,
                sep,
                str(timestamp),
                str(image_size),
                mod_archs[arch][binary_name],
                symbols,
                '',
            )

        # New symbol cache.
        arch_mapping = {
            'x86': 'x86',
            'amd64': 'x86-64',
            'arm64': 'arm64',
        }

        if pdb_fingerprint is None:
            cache_key = f'pe_{arch_mapping[arch]}_{timestamp}_{image_size}_{binary_name}'
            if is_hybrid:
                cache_key += f'_hybrid'
        else:
            cache_key = f'pdb_{pdb_fingerprint}'
            if is_hybrid:
                cache_key += f'_hybrid-{arch_mapping[arch]}'

        symbol_cache_file_path = f'{mod_name}/{cache_key}.txt'

        sep = ';' if is_hybrid else '#'

        create_mod_cache_file(
            files,
            symbol_cache_file_path,
            sep,
            binary_name.replace(sep, '_'),
            f'{arch_mapping[arch]}_{timestamp}_{image_size}',
            mod_archs[arch][binary_name],
            symbols,
            arch if is_hybrid else '',
        )


def create_mod_cache(binaries_folder: Path,
                     extracted_symbols_path: Path,
                     symbol_cache_path: Path):
    with extracted_symbols_path.open('r', encoding='utf-8') as f:
        extracted_symbols = json.load(f)

    all_used_symbols_per_binary = get_all_used_symbols_per_binary(extracted_symbols)

    with FastImportFiles(symbol_cache_path) as files:
        for binary_name in binaries_folder.glob('*'):
            if binary_name.is_file():
                continue

            for arch in binary_name.glob('*'):
                if arch.is_file():
                    continue

                for symbols_file in arch.glob('*' + SYMBOLS_FILE_SUFFIX):
                    if not symbols_file.is_file():
                        continue

                    try:
                        create_mod_cache_for_symbols_file(
                            files,
                            extracted_symbols,
                            binary_name.name,
                            arch.name,
                            symbols_file,
                            all_used_symbols_per_binary[binary_name.name],
                        )
                    except Exception as e:
                        print(f'Failed to create mod cache for {symbols_file}: {e}')
                        raise


def main():
    parser = ArgumentParser()
    parser.add_argument('binaries_folder', type=Path)
    parser.add_argument('extracted_symbols_path', type=Path)
    parser.add_argument('symbol_cache_path', type=Path)
    args = parser.parse_args()

    binaries_folder = args.binaries_folder
    extracted_symbols_path = args.extracted_symbols_path
    symbol_cache_path = args.symbol_cache_path

    create_mod_cache(binaries_folder, extracted_symbols_path, symbol_cache_path)


if __name__ == '__main__':
    main()
