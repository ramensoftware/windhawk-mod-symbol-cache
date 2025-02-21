import json
import re
from argparse import ArgumentParser
from pathlib import Path

MOD_CACHE_LEGACY_SEPARATORS = {
    'taskbar-button-click': '@',
    'taskbar-clock-customization': '@',
    'taskbar-thumbnail-reorder': '@',
    'virtual-desktop-taskbar-order': '@',
}


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
                    'x86': 'arch=x86\\',
                    'amd64': 'arch=x64\\',
                    'arm64': 'arch=ARM64\\',
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


def create_mod_cache_for_symbols_file(symbol_cache_path: Path,
                                      extracted_symbols: dict,
                                      binary_name: str,
                                      arch: str,
                                      symbols_file: Path):
    symbols = {}
    timestamp = None
    image_size = None
    is_hybrid = False
    pdb_fingerprint = None

    with symbols_file.open('r', encoding='utf-8') as f:
        while line := f.readline():
            line = line.rstrip('\n')

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

            if line.startswith(f'['):
                address, symbol = line[1:].split('] ', 1)
                address = int(address, 16)
                if symbol in symbols:
                    # Duplicate symbol.
                    symbols[symbol] = None
                else:
                    symbols[symbol] = address
                continue

            if line.startswith(f'Found '):
                continue

            raise Exception(f'Unknown line: {line}')

    # Use all relevant architectures for hybrid PEs.
    iter_archs = [arch]
    if is_hybrid:
        if arch == 'x86':
            # Likely to only be loaded in x86 processes with x86 mods.
            pass
        elif arch == 'amd64':
            iter_archs.append('arm64')
        elif arch == 'arm64':
            iter_archs.append('amd64')
        else:
            raise Exception(f'Unknown arch: {arch}')

    for iter_arch in iter_archs:
        for mod_name, mod_archs in extracted_symbols.items():
            if iter_arch not in mod_archs:
                continue

            if binary_name not in mod_archs[iter_arch]:
                continue

            # Legacy symbol cache.
            legacy_cache_key = None

            if not is_hybrid:
                if iter_arch == 'amd64':
                    legacy_cache_key = f'symbol-cache-{binary_name}'
                elif iter_arch == 'x86':
                    legacy_cache_key = f'symbol-{iter_arch}-cache-{binary_name}'

            if legacy_cache_key:
                symbol_cache_file_path = symbol_cache_path / mod_name / legacy_cache_key / f'{timestamp}-{image_size}.txt'

                sep = MOD_CACHE_LEGACY_SEPARATORS.get(mod_name, '#')

                create_mod_cache_file(
                    symbol_cache_file_path,
                    sep,
                    str(timestamp),
                    str(image_size),
                    mod_archs[iter_arch][binary_name],
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
                cache_key = f'pe_{arch_mapping[iter_arch]}_{timestamp}_{image_size}_{binary_name}'
                if is_hybrid:
                    cache_key += f'_hybrid'
            else:
                cache_key = f'pdb_{pdb_fingerprint}'
                if is_hybrid:
                    cache_key += f'_hybrid-{arch_mapping[iter_arch]}'

            symbol_cache_file_path = symbol_cache_path / mod_name / f'{cache_key}.txt'

            sep = ';' if is_hybrid else '#'

            create_mod_cache_file(
                symbol_cache_file_path,
                sep,
                binary_name.replace(sep, '_'),
                f'{timestamp}-{image_size}',
                mod_archs[iter_arch][binary_name],
                symbols,
                iter_arch if is_hybrid else '',
            )


def create_mod_cache(binaries_folder: Path,
                     extracted_symbols_path: Path,
                     symbol_cache_path: Path):
    with extracted_symbols_path.open('r', encoding='utf-8') as f:
        extracted_symbols = json.load(f)

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
