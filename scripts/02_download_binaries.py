import gzip
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path

import requests

BINARY_MAX_AGE_DAYS_TO_DOWNLOAD = 30
BINARY_MAX_AGE_DAYS_BEFORE_DELETION = 60

NAMES_TO_ALLOW_404 = [
    # Old binary, missing in insider builds.
    'explorerextensions.dll',
]

VERBOSE_OUTPUT = False


def get_modules_from_extracted_symbols(extracted_symbols: Path):
    with extracted_symbols.open() as f:
        data = json.load(f)

    modules = set()

    for mod_name in data:
        for arch in data[mod_name]:
            for module in data[mod_name][arch]:
                modules.add((arch, module))

    return modules


def make_symbol_server_url(file_name, timestamp, size):
    return f'https://msdl.microsoft.com/download/symbols/{file_name}/{timestamp:08X}{size:x}/{file_name}'


def make_symbol_server_candidate_urls(file_name,
                                      timestamp,
                                      file_size,
                                      last_section_pointer_to_raw_data,
                                      last_section_virtual_address):
    # Algorithm inspired by DeltaDownloader:
    # https://github.com/Wack0/DeltaDownloader/blob/ab71359fc5a1f2446b650b31450c74a701c40979/Program.cs#L68-L85

    PAGE_SIZE = 0x1000

    def get_mapped_size(size):
        PAGE_MASK = (PAGE_SIZE - 1)
        page = size & ~PAGE_MASK
        if (page == size):
            return page
        return page + PAGE_SIZE

    # We use the rift table (VirtualAddress,PointerToRawData pairs for each section) and the target file size to calculate the SizeOfImage.
    last_section_and_signature_size = file_size - last_section_pointer_to_raw_data
    last_section_and_signature_mapped_size = get_mapped_size(last_section_virtual_address + last_section_and_signature_size)

    size_of_image = last_section_and_signature_mapped_size
    lowest_size_of_image = last_section_virtual_address + PAGE_SIZE

    urls = []
    size = size_of_image
    while size >= lowest_size_of_image:
        url = make_symbol_server_url(file_name, timestamp, size)
        urls.append(url)
        size -= PAGE_SIZE

    return urls


def download_binaries_from_symbol_server(name: str, target_folder: Path, previous_folder: Path, target_arch: str, insider=False):
    if insider:
        url = f'https://m417z.com/winbindex-data-insider/by_filename_compressed/{name}.json.gz'
    elif target_arch == 'arm64':
        url = f'https://m417z.com/winbindex-data-arm64/by_filename_compressed/{name}.json.gz'
    else:
        url = f'https://winbindex.m417z.com/data/by_filename_compressed/{name}.json.gz'

    while True:
        try:
            r = requests.get(url)
            if 500 <= r.status_code < 600:
                raise Exception(f'Server Error: {r.status_code} for url: {url}')
            break
        except Exception as e:
            print(f'ERROR: failed to get {url}, retrying in 10 seconds')
            print(f'       {e}')
            time.sleep(10)

    if 400 <= r.status_code < 500:
        if r.status_code == 404 and name in NAMES_TO_ALLOW_404:
            return

        raise Exception(f'Client Error: {r.status_code} for url: {url}')

    data_compressed = r.content
    data_json_str = gzip.decompress(data_compressed).decode()
    data = json.loads(data_json_str)

    aria2c_list = ''

    hashes = sorted(data)

    for index, hash in enumerate(hashes):
        if VERBOSE_OUTPUT:
            print(f'Processing {index + 1}/{len(hashes)}')

        hash_data = data[hash]

        if 'fileInfo' not in hash_data:
            print(f'Skipping {hash} which has no fileInfo')
            continue

        hash_file_info = hash_data['fileInfo']

        if hash_file_info['machineType'] == 332:
            arch = 'x86'
        elif hash_file_info['machineType'] == 34404:
            arch = 'amd64'
        elif hash_file_info['machineType'] == 43620:
            arch = 'arm64'
        elif hash_file_info['machineType'] in [452]:
            arch = str(hash_file_info['machineType'])
        else:
            raise Exception(f'Unknown machine type: {hash_file_info["machineType"]}')

        if arch != target_arch:
            if VERBOSE_OUTPUT:
                print(f'Skipping {hash} which is not {target_arch}: {arch}')
            continue

        last_date = None
        for windows_version_info in hash_data['windowsVersions'].values():
            for update, update_data in windows_version_info.items():
                if insider:
                    release_date_timestamp = update_data['updateInfo']['created']
                    release_date = datetime.fromtimestamp(release_date_timestamp)
                else:
                    if update == 'BASE':
                        release_date_ymd = update_data['windowsVersionInfo']['releaseDate']
                    else:
                        release_date_ymd = update_data['updateInfo']['releaseDate']
                    release_date = datetime.strptime(release_date_ymd, "%Y-%m-%d")

                if last_date is None or release_date > last_date:
                    last_date = release_date

        if last_date is None:
            raise Exception(f'No release date for {hash}')

        age_days = (datetime.now() - last_date).days
        if age_days > BINARY_MAX_AGE_DAYS_BEFORE_DELETION:
            continue

        file_name = re.sub(r'^.*\.(.*)$', rf'{hash}.\g<1>', name)

        file_path = target_folder / file_name
        file_path_symbols = file_path.with_name(file_path.name + '.txt')

        previous_file_path = previous_folder / file_name
        previous_file_path_symbols = previous_file_path.with_name(previous_file_path.name + '.txt')

        if VERBOSE_OUTPUT:
            print(file_path)

        if previous_file_path_symbols.exists():
            previous_file_path_symbols.rename(file_path_symbols)
            continue

        if previous_file_path.exists():
            previous_file_path.rename(file_path)
            continue

        if file_path_symbols.exists() or file_path.exists():
            continue

        if age_days > BINARY_MAX_AGE_DAYS_TO_DOWNLOAD:
            if VERBOSE_OUTPUT:
                print(f'Skipping {hash} which is too old: {age_days} days')
            continue

        if 'virtualSize' in hash_file_info:
            file_url = make_symbol_server_url(name, hash_file_info['timestamp'], hash_file_info['virtualSize'])
        else:
            file_url = '\t'.join(make_symbol_server_candidate_urls(name,
                                                                   hash_file_info['timestamp'],
                                                                   hash_file_info['size'],
                                                                   hash_file_info['lastSectionPointerToRawData'],
                                                                   hash_file_info['lastSectionVirtualAddress']))

        aria2c_list += f'{file_url}\n'
        aria2c_list += f'  dir={file_path.parent}\n'
        aria2c_list += f'  out={file_path.name}\n'
        aria2c_list += f'  auto-file-renaming=false\n'

    if aria2c_list:
        # Can't use stdin due to the following bug:
        # https://github.com/aria2/aria2/issues/2138
        aria2c_list_tmp = tempfile.NamedTemporaryFile(delete=False)
        aria2c_list_tmp.write(aria2c_list.encode())
        aria2c_list_tmp.close()

        try:
            args = ['aria2c', '-x', '16', '--input-file', aria2c_list_tmp.name]
            if not VERBOSE_OUTPUT:
                args += ['--console-log-level=warn']
            subprocess.run(args)
        finally:
            os.unlink(aria2c_list_tmp.name)


def download_modules(module: tuple[str, str], binaries_folder: Path, previous_binaries_folder: Path):
    arch, module_name = module

    target_folder = binaries_folder / module_name / arch
    target_folder.mkdir(parents=True, exist_ok=True)

    previous_folder = previous_binaries_folder / module_name / arch

    download_binaries_from_symbol_server(module_name, target_folder, previous_folder, arch)
    download_binaries_from_symbol_server(module_name, target_folder, previous_folder, arch, insider=True)


def main():
    parser = ArgumentParser()
    parser.add_argument('extracted_symbols', type=Path)
    parser.add_argument('binaries_folder', type=Path)
    parser.add_argument('previous_binaries_folder', type=Path)
    args = parser.parse_args()

    extracted_symbols = args.extracted_symbols
    binaries_folder = args.binaries_folder
    previous_binaries_folder = args.previous_binaries_folder

    modules = get_modules_from_extracted_symbols(extracted_symbols)

    for module in modules:
        download_modules(module, binaries_folder, previous_binaries_folder)

    if previous_binaries_folder.exists():
        shutil.rmtree(previous_binaries_folder)


if __name__ == '__main__':
    main()
