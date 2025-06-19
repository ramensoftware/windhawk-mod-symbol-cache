import subprocess
from argparse import ArgumentParser
from itertools import repeat
from multiprocessing import Pool
from pathlib import Path
from struct import unpack

import pefile

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


def is_hybrid_img(filename: Path):
    with pefile.PE(filename) as pe:
        load_config = getattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG', None)

        if load_config and hasattr(load_config.struct, 'CHPEMetadataPointer'):
            return bool(load_config.struct.CHPEMetadataPointer)

    return False


# Source:
# https://github.com/chromium/chromium/blob/ae46624acb85baa5bb3d0f960caae12d648b79ce/tools/symsrc/pdb_fingerprint_from_img.py
def get_pdb_info_from_img(filename: Path):
    """Returns the PDB fingerprint and the pdb filename given an image file"""

    __CV_INFO_PDB70_format__ = (
        'CV_INFO_PDB70',
        ('4s,CvSignature', '16s,Signature', 'L,Age'),
    )

    __GUID_format__ = ('GUID', ('L,Data1', 'H,Data2', 'H,Data3', '8s,Data4'))

    # Use last result. Reference:
    # https://github.com/dotnet-bot/corert/blob/8928dfd66d98f40017ec7435df1fbada113656a8/src/Native/Runtime/windows/PalRedhawkCommon.cpp#L109
    last_result = None

    with pefile.PE(filename) as pe:
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            if dbg.struct.Type != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                continue

            off = dbg.struct.AddressOfRawData
            size = dbg.struct.SizeOfData
            data = pe.get_memory_mapped_image()[off : off + size]

            cv = pefile.Structure(__CV_INFO_PDB70_format__)
            cv.__unpack__(data)
            cv.PdbFileName = data[cv.sizeof() :]
            guid = pefile.Structure(__GUID_format__)
            guid.__unpack__(cv.Signature)

            if not isinstance(guid.Data4[0], int):
                # In non-py3 pefile, this is a list of bytes.
                guid.Data4 = map(ord, guid.Data4)

            guid.Data4_0 = ''.join("%02X" % x for x in guid.Data4[0:2])
            guid.Data4_1 = ''.join("%02X" % x for x in guid.Data4[2:])

            last_result = (
                "%08X%04X%04X%s%s%d"
                % (
                    guid.Data1,
                    guid.Data2,
                    guid.Data3,
                    guid.Data4_0,
                    guid.Data4_1,
                    cv.Age,
                ),
                str(cv.PdbFileName.split(b'\x00', 1)[0].decode()),
            )

    return last_result


def append_pe_information(executable_path: Path, output_path: Path):
    pe_extra_data = get_pe_extra_data(executable_path)
    is_hybrid = is_hybrid_img(executable_path)
    pdb_info = get_pdb_info_from_img(executable_path)

    with output_path.open('a') as f:
        f.write(f'machine={pe_extra_data["machine"]}\n')
        f.write(f'timestamp={pe_extra_data["timestamp"]}\n')
        f.write(f'image_size={pe_extra_data["image_size"]}\n')

        if is_hybrid:
            f.write(f'is_hybrid=True\n')

        if pdb_info:
            f.write(f'pdb_fingerprint={pdb_info[0]}\n')
            f.write(f'pdb_filename={pdb_info[1]}\n')


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
        return f'Failed to extract symbols from binary {path}: {e}'


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

    if errors:
        print('Errors:')
        for error in errors:
            print(error)

    if paths:
        print(f'Processed files:')
        for path in paths:
            print(path)


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
