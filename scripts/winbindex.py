"""Winbindex data, which lists the known versions of a binary.

The data is downloaded into a folder once, and then loaded from there, so that
every script which uses it reads the same snapshot.
"""

import gzip
import json
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

NAMES_TO_ALLOW_404 = [
    # Old binary, missing in insider builds.
    'explorerextensions.dll',
]

_DOWNLOAD_WORKERS = 8
_DOWNLOAD_TIMEOUT_SECONDS = 60
_DOWNLOAD_ATTEMPTS = 6
_DOWNLOAD_RETRY_DELAY_SECONDS = 10


def _djb2_hash(s: str):
    h = 5381
    for c in s:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h


def _get_url(name: str, arch: str, insider: bool):
    if insider:
        return f'https://m417z.com/winbindex-data-insider/by_filename_compressed/{_djb2_hash(name) & 0xFF:02x}/{name}.json.gz'
    if arch == 'arm64':
        return f'https://m417z.com/winbindex-data-arm64/by_filename_compressed/{name}.json.gz'
    return f'https://winbindex.m417z.com/data/by_filename_compressed/{name}.json.gz'


def _get_path(folder: Path, url: str):
    return folder / url.removeprefix('https://')


def _get_with_retries(session: requests.Session, url: str) -> requests.Response:
    """Get the URL, retrying on a server or connection error."""
    attempt = 1
    while True:
        try:
            r = session.get(url, timeout=_DOWNLOAD_TIMEOUT_SECONDS)
            if r.status_code < 500:
                return r
            error = f'Server Error: {r.status_code}'
        except requests.RequestException as e:
            error = str(e)

        if attempt == _DOWNLOAD_ATTEMPTS:
            raise Exception(f'Failed to get {url}: {error}')

        print(f'ERROR: failed to get {url}, retrying in {_DOWNLOAD_RETRY_DELAY_SECONDS} seconds')
        print(f'       {error}')
        time.sleep(_DOWNLOAD_RETRY_DELAY_SECONDS)
        attempt += 1


def _download(session: requests.Session, url: str, name: str, path: Path):
    r = _get_with_retries(session, url)
    if r.status_code == 404 and name in NAMES_TO_ALLOW_404:
        return

    r.raise_for_status()

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(r.content)


def download_winbindex_data(folder: Path, binaries: Iterable[tuple[str, str, bool]]):
    """Download the data of each (name, arch, insider) into the folder.

    Data which is already in the folder isn't downloaded again, and data which
    is shared, such as the release data of x86 and amd64, is downloaded once.
    """
    downloads: dict[str, tuple[str, Path]] = {}
    for name, arch, insider in binaries:
        url = _get_url(name, arch, insider)
        path = _get_path(folder, url)
        if not path.exists():
            downloads[url] = (name, path)

    print(f'Downloading {len(downloads)} Winbindex data files')

    session = requests.Session()
    with ThreadPoolExecutor(max_workers=_DOWNLOAD_WORKERS) as executor:
        futures = [executor.submit(_download, session, url, name, path)
                   for url, (name, path) in downloads.items()]
        for future in futures:
            future.result()


def load_winbindex_data(folder: Path, name: str, arch: str, insider: bool) -> dict | None:
    """The data which download_winbindex_data downloaded, or None if Winbindex
    doesn't have the binary and that's allowed for its name."""
    path = _get_path(folder, _get_url(name, arch, insider))
    if not path.exists() and name in NAMES_TO_ALLOW_404:
        return None

    return json.loads(gzip.decompress(path.read_bytes()))
