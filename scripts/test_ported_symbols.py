"""Tests for using ported symbols until a binary's own symbols are extracted.

A ported symbols file only knows the symbols it lists. Any other symbol has to
be left out of the cache, so that the engine looks for it in the PDB, rather
than be written without an address, which tells the engine that it doesn't
exist.
"""

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

_SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPTS))

from symbols_file import (PORTED_SYMBOLS_FILE_SUFFIX, SYMBOLS_FILE_SUFFIX, addresses_file_path,
                          write_symbols_file)


def _load(module_name: str, file_name: str):
    spec = importlib.util.spec_from_file_location(module_name, _SCRIPTS / file_name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


download_binaries = _load('download_binaries', '02_download_binaries.py')
extract_symbols = _load('extract_symbols', '03_extract_symbols_from_binaries.py')
create_mod_cache = _load('create_mod_cache', '04_create_mod_cache.py')

PE_INFO = {
    'machine': 34404,
    'timestamp': 1,
    'image_size': 4096,
    'pdb_fingerprint': '0123456789ABCDEF0123456789ABCDEF1',
    'pdb_filename': 'x.pdb',
}
PORTED_PE_INFO = PE_INFO | {'ported': '10.0.1.2'}

FILE_CHANGE = re.compile(rb'M 100644 inline (.*)\ndata (\d+)\n')


def write(path: Path, pe_info: dict, lines: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    write_symbols_file(path, pe_info, ('\n'.join(lines) + '\n').encode())


def read_file_changes(path: Path) -> dict[str, str]:
    data = path.read_bytes()
    files = {}
    pos = 0
    while pos < len(data):
        match = FILE_CHANGE.match(data, pos)
        start = match.end()
        end = start + int(match[2])
        files[match[1].decode()] = data[start:end].decode()
        pos = end + 1
    return files


class TestModCache(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.arch_folder = self.root / 'binaries' / 'x.dll' / 'amd64'
        self.extracted_symbols = self.root / 'extracted_symbols.json'
        self.extracted_symbols.write_text(json.dumps(
            {'mod': {'amd64': {'x.dll': ['A', 'B', 'C']}}}))

    def create_cache(self) -> dict[str, str]:
        output = self.root / 'symbol_cache.fi'
        create_mod_cache.create_mod_cache(self.root / 'binaries', self.extracted_symbols, output)
        return read_file_changes(output)

    def write_ported(self):
        write(self.arch_folder / ('h.dll' + PORTED_SYMBOLS_FILE_SUFFIX), PORTED_PE_INFO,
              ['Found 1 symbols', '[00001000] A', 'absent: B'])

    def test_a_ported_symbol_has_its_address_and_an_unknown_one_is_left_out(self):
        self.write_ported()
        self.assertEqual(self.create_cache(), {
            f'mod/pdb_{PE_INFO["pdb_fingerprint"]}.txt': '1#x.dll#x86-64_1_4096_ported#A#4096#B#',
        })

    def test_no_file_is_written_for_a_mod_without_a_known_symbol(self):
        write(self.arch_folder / ('h.dll' + PORTED_SYMBOLS_FILE_SUFFIX), PORTED_PE_INFO,
              ['Found 1 symbols', '[00001000] D'])
        self.assertEqual(self.create_cache(), {})

    def test_the_binary_own_symbols_take_precedence(self):
        self.write_ported()
        write(self.arch_folder / ('h.dll' + SYMBOLS_FILE_SUFFIX), PE_INFO,
              ['Found 1 symbols', '[00002000] A'])
        self.assertEqual(self.create_cache(), {
            'mod/symbol-cache-x.dll/1-4096.txt': '1#1#4096#A#8192#B##C#',
            f'mod/pdb_{PE_INFO["pdb_fingerprint"]}.txt': '1#x.dll#x86-64_1_4096#A#8192#B##C#',
        })


class TestDownloadBinaries(unittest.TestCase):
    """A binary which isn't on the symbol server, with ported symbols."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.target = root / 'binaries'
        self.previous = root / 'binaries_previous'
        self.target.mkdir()
        self.previous.mkdir()
        self.ported_folder = root / 'ported_symbols'
        write(self.ported_folder / 'x.dll' / 'amd64' / ('h.dll' + SYMBOLS_FILE_SUFFIX), PORTED_PE_INFO,
              ['Found 1 symbols', '[00001000] A'])

    def run_download(self, age_days: int) -> mock.Mock:
        release_date = (datetime.now() - timedelta(days=age_days)).strftime('%Y-%m-%d')
        data = {'h': {
            'fileInfo': {'machineType': 34404, 'timestamp': 1, 'virtualSize': 4096},
            'windowsVersions': {'11-24H2': {'KB1': {'updateInfo': {'releaseDate': release_date}}}},
        }}

        def ported_path(name, arch, file_name):
            return self.ported_folder / name / arch / (file_name + SYMBOLS_FILE_SUFFIX)

        with mock.patch.object(download_binaries, 'load_winbindex_data', return_value=data), \
                mock.patch.object(download_binaries, 'ported_symbols_path', ported_path), \
                mock.patch.object(download_binaries.subprocess, 'run') as run:
            download_binaries.download_binaries_from_symbol_server(
                'x.dll', self.target, self.previous, Path('winbindex'), {}, 'amd64')
        return run

    def assertPdbLookup(self):
        self.assertEqual(extract_symbols.get_pdb_info_from_img(self.target / 'h.dll'),
                         (PE_INFO['pdb_fingerprint'], PE_INFO['pdb_filename']))

    def test_ported_symbols_are_used_and_the_pdb_is_looked_for(self):
        run = self.run_download(age_days=1)
        run.assert_called_once()
        self.assertTrue((self.target / ('h.dll' + PORTED_SYMBOLS_FILE_SUFFIX)).exists())
        self.assertPdbLookup()

    def test_the_pdb_is_looked_for_after_downloads_stop(self):
        run = self.run_download(age_days=40)
        run.assert_not_called()
        self.assertTrue((self.target / ('h.dll' + PORTED_SYMBOLS_FILE_SUFFIX)).exists())
        self.assertPdbLookup()

    def test_nothing_ported_is_used_once_the_own_symbols_are_extracted(self):
        write(self.previous / ('h.dll' + SYMBOLS_FILE_SUFFIX), PE_INFO, ['Found 1 symbols', '[00001000] A'])
        self.run_download(age_days=1)
        self.assertEqual(sorted(p.name for p in self.target.iterdir()), ['h.dll' + SYMBOLS_FILE_SUFFIX])


class TestPlacePortedSymbols(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.source = root / 'source.txt.zst'
        self.previous = root / 'previous' / ('h.dll' + PORTED_SYMBOLS_FILE_SUFFIX)
        self.target = root / 'target' / ('h.dll' + PORTED_SYMBOLS_FILE_SUFFIX)
        self.target.parent.mkdir()
        write(self.source, PORTED_PE_INFO, ['Found 1 symbols', '[00001000] A'])

    def test_an_identical_copy_from_the_previous_run_is_kept(self):
        self.previous.parent.mkdir()
        self.previous.write_bytes(self.source.read_bytes())
        os.utime(self.previous, (1, 1))
        addresses_file_path(self.previous).write_text('{}')

        download_binaries.place_ported_symbols(self.source, self.target, self.previous)

        self.assertEqual(self.target.stat().st_mtime, 1)
        self.assertTrue(addresses_file_path(self.target).exists())

    def test_a_changed_file_replaces_the_previous_copy_and_its_addresses(self):
        write(self.previous, PORTED_PE_INFO, ['Found 1 symbols', '[00002000] A'])
        addresses_file_path(self.previous).write_text('{}')

        download_binaries.place_ported_symbols(self.source, self.target, self.previous)

        self.assertEqual(self.target.read_bytes(), self.source.read_bytes())
        self.assertFalse(addresses_file_path(self.target).exists())


if __name__ == '__main__':
    unittest.main()
