import json
import mmap
import re
from argparse import ArgumentParser
from enum import StrEnum
from pathlib import Path

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
    cache_path: Path,
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

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with cache_path.open('w', encoding='utf-8') as f:
        f.write(f'1{sep}{val1}{sep}{val2}')

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

            f.write(f'{sep}{symbol}{sep}{address}')


def create_mod_cache_for_symbols_file(
    symbol_cache_path: Path,
    extracted_symbols: dict,
    binary_name: str,
    arch: str,
    symbols_file: Path,
    all_used_symbols: set[str],
):
    symbols = {}
    timestamp = None
    image_size = None
    is_hybrid = False
    pdb_fingerprint = None

    all_used_symbols_bytes_with_prefix = set()
    for symbol in all_used_symbols:
        all_used_symbols_bytes_with_prefix.add(symbol.encode())
        if not re.match(r'arch=\w+\\', symbol):
            for arch_prefix in ArchPrefix:
                all_used_symbols_bytes_with_prefix.add((arch_prefix + symbol).encode())

    with (
        symbols_file.open('r', encoding='utf-8') as f,
        mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m
    ):
        # This is a hot loop, keep it optimized.
        while line := m.readline():
            if line[-2:] == b'\r\n':
                line = line[:-2]
            elif line[-1:] == b'\n':
                line = line[:-1]

            if line == b'':
                continue

            if line[0] == ord('['):
                assert line[9] == ord(']') and line[10] == ord(' ')
                symbol = line[11:]
                if symbol in all_used_symbols_bytes_with_prefix:
                    symbol = symbol.decode()
                    address = int(line[1:9], 16)
                    if symbol in symbols:
                        # Duplicate symbol.
                        symbols[symbol] = None
                    else:
                        symbols[symbol] = address
                continue

            line = line.decode()

            if line.startswith(f'timestamp='):
                timestamp = int(line.split('=')[1])
                continue

            if line.startswith(f'image_size='):
                image_size = int(line.split('=')[1])
                continue

            if line.startswith(f'machine='):
                continue

            if line.startswith(f'is_hybrid='):
                assert line.split('=')[1] == 'True'
                is_hybrid = True
                continue

            if line.startswith(f'pdb_fingerprint='):
                pdb_fingerprint = line.split('=')[1]
                continue

            if line.startswith(f'pdb_filename='):
                continue

            if line.startswith(f'Found '):
                continue

            raise Exception(f'Unknown line: {line}')

    # For now, only cache ARM64 hybrid symbols. Later, it's possible to add
    # other architectures for hybrid symbols, as well as other architectures
    # within the hybrid binaries:
    # * x86 -> x86, arm64
    # * amd64 -> amd64, arm64
    # * arm64 -> amd64, arm64
    if is_hybrid and arch != 'arm64':
        return

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
            symbol_cache_file_path = symbol_cache_path / mod_name / legacy_cache_key / f'{timestamp}-{image_size}.txt'

            sep = MOD_CACHE_LEGACY_SEPARATORS.get(mod_name, '#')

            create_mod_cache_file(
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

        symbol_cache_file_path = symbol_cache_path / mod_name / f'{cache_key}.txt'

        sep = ';' if is_hybrid else '#'

        create_mod_cache_file(
            symbol_cache_file_path,
            sep,
            binary_name.replace(sep, '_'),
            f'{timestamp}-{image_size}',
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

    for binary_name in binaries_folder.glob('*'):
        if binary_name.is_file():
            continue

        for arch in binary_name.glob('*'):
            if arch.is_file():
                continue

            for symbols_file in arch.glob('*.txt'):
                if not symbols_file.is_file():
                    continue

                try:
                    create_mod_cache_for_symbols_file(
                        symbol_cache_path,
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
