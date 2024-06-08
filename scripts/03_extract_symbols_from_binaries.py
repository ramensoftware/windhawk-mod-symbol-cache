import subprocess
from argparse import ArgumentParser
from itertools import repeat
from multiprocessing import Pool
from pathlib import Path
from struct import unpack

POOL_PROCESSES = 4


def run_windhawk_symbol_helper(windhawk_symbol_helper_path: Path,
                               windhawk_engine_path: Path,
                               symbols_path: Path,
                               executable_path: Path,
                               output_path: Path):
    # Usage: windhawk-symbol-helper.exe engineDir symbolsDir symbolServer
    # targetExecutable undecorated decorated outputFile
    subprocess.check_call([
        windhawk_symbol_helper_path,
        windhawk_engine_path,
        symbols_path,
        R'https://msdl.microsoft.com/download/symbols',
        executable_path,
        R'true',
        R'false',
        output_path,
    ])


# https://gist.github.com/geudrik/03152ba1a148d9475e81
def get_pe_extra_data(filename):
    with open(filename, 'rb') as handle:
        # Get PE offset (@60, DWORD) from DOS header
        handle.seek(60, 0)
        offset = handle.read(4)
        offset = unpack('<I', offset)[0]

        handle.seek(offset + 4, 0)
        word = handle.read(2)
        machine = unpack('<H', word)[0]

        handle.seek(offset + 8, 0)
        dword = handle.read(4)
        timestamp = unpack('<I', dword)[0]

        handle.seek(offset + 0x50, 0)
        dword = handle.read(4)
        image_size = unpack('<I', dword)[0]

    return {
        'machine': machine,
        'timestamp': timestamp,
        'image_size': image_size,
    }


def append_pe_information(executable_path: Path, output_path: Path):
    pe_extra_data = get_pe_extra_data(executable_path)

    with output_path.open('a') as f:
        f.write(f'machine={pe_extra_data["machine"]}\n')
        f.write(f'timestamp={pe_extra_data["timestamp"]}\n')
        f.write(f'image_size={pe_extra_data["image_size"]}\n')


def extract_all_symbols_worker(path: Path,
                               windhawk_symbol_helper_path: Path,
                               windhawk_engine_path: Path,
                               symbols_path: Path):
    try:
        output_path = path.with_name(path.name + '.txt')
        run_windhawk_symbol_helper(windhawk_symbol_helper_path,
                                   windhawk_engine_path,
                                   symbols_path,
                                   path,
                                   output_path)
        append_pe_information(path, output_path)
        path.unlink()
        return None
    except Exception as e:
        return f'Failed to extract symbols from {path}: {e}'


def extract_all_symbols(binaries_folder: Path,
                        windhawk_symbol_helper_path: Path,
                        windhawk_engine_path: Path,
                        symbols_path: Path):
    symbols_path_resolved = symbols_path.resolve()    

    paths = list(p for p in binaries_folder.rglob('*') if p.is_file() and p.suffix != '.txt')

    with Pool(POOL_PROCESSES) as pool:
        errors = pool.starmap(extract_all_symbols_worker, zip(
            paths,
            repeat(windhawk_symbol_helper_path),
            repeat(windhawk_engine_path),
            repeat(symbols_path_resolved),
        ))

    errors = [e for e in errors if e is not None]
    print(f'Extracted symbols from {len(paths)-len(errors)} of {len(paths)} files')

    for error in errors:
        print(error)


def main():
    parser = ArgumentParser()
    parser.add_argument('binaries_folder', type=Path)
    parser.add_argument('windhawk_symbol_helper_path', type=Path)
    parser.add_argument('windhawk_engine_path', type=Path)
    parser.add_argument('symbols_path', type=Path)
    args = parser.parse_args()

    binaries_folder = args.binaries_folder
    windhawk_symbol_helper_path = args.windhawk_symbol_helper_path
    windhawk_engine_path = args.windhawk_engine_path
    symbols_path = args.symbols_path

    extract_all_symbols(binaries_folder,
                        windhawk_symbol_helper_path,
                        windhawk_engine_path,
                        symbols_path)


if __name__ == '__main__':
    main()
