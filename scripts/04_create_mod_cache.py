import json
from argparse import ArgumentParser
from pathlib import Path

MOD_CACHE_SEPARATORS = {
    'taskbar-button-click': '@',
    'taskbar-clock-customization': '@',
    'taskbar-thumbnail-reorder': '@',
    'virtual-desktop-taskbar-order': '@',
}


def create_mod_cache_for_symbols_file(symbol_cache_path: Path,
                                      extracted_symbols: dict,
                                      binary_name: str,
                                      arch: str,
                                      symbols_file: Path):
    symbols = {}
    timestamp = None    
    image_size = None    

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

    for mod_name, mod_archs in extracted_symbols.items():
        if arch not in mod_archs:
            continue

        if binary_name not in mod_archs[arch]:
            continue

        if arch == 'x86-64':
            cache_key = f'symbol-cache-{binary_name}'
        else:
            cache_key = f'symbol-{arch}-cache-{binary_name}'

        symbol_cache_file_path = symbol_cache_path / mod_name / cache_key / f'{timestamp}-{image_size}.txt'

        symbol_cache_file_path.parent.mkdir(parents=True, exist_ok=True)
        with symbol_cache_file_path.open('w', encoding='utf-8') as f:
            sep = MOD_CACHE_SEPARATORS.get(mod_name, '#')

            f.write(f'1{sep}{timestamp}{sep}{image_size}')

            for symbol in mod_archs[arch][binary_name]:
                address = symbols.get(symbol, '')
                if address is None:
                    raise Exception(f'Duplicate symbol {symbol} in {symbols_file}')

                f.write(f'{sep}{symbol}{sep}{address}')


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

                create_mod_cache_for_symbols_file(symbol_cache_path,
                                                  extracted_symbols,
                                                  binary_name.name,
                                                  arch.name,
                                                  symbols_file)


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
