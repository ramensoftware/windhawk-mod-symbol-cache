import gzip
import json
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import requests

SYMBOL_SERVER_BASE = 'https://msdl.microsoft.com/download/symbols'

# Display label, target machine architecture, insider flag.
ARCH_VARIANTS: list[tuple[str, str, bool]] = [
    ('x64 (release builds)', 'amd64', False),
    ('ARM64 (release builds)', 'arm64', False),
    ('x64 (insider preview builds)', 'amd64', True),
]

# Mirrors the machine-type handling in 02_download_binaries.py: 332 (x86),
# 34404 (amd64) and 43620 (arm64) are mapped to the labels we report on.
# 452 (IMAGE_FILE_MACHINE_ARMNT) is recognised so we don't fail on it, but maps
# to a label that won't match any target_arch and is therefore filtered out.
# Any other machine type triggers a hard failure.
MACHINE_TYPE_TO_ARCH: dict[int, str] = {
    332: 'x86',
    34404: 'amd64',
    43620: 'arm64',
    452: 'arm',
}

# Kept in sync with NAMES_TO_ALLOW_404 in 02_download_binaries.py: the status
# page should not be more permissive than the script that drives the cache.
NAMES_TO_ALLOW_404 = [
    # Old binary, missing in insider builds.
    'explorerextensions.dll',
    # New binary, not available in stable builds yet.
    'systemtray.dll',
]

WINBINDEX_FETCH_WORKERS = 8

# Metadata lines (machine=, timestamp=, pdb_fingerprint=, pdb_filename=) are
# appended at the end of each .txt by append_pe_information in script 03.
# Reading just the tail avoids loading multi-MB symbol blobs that we don't need.
SYMBOLS_TXT_TAIL_BYTES = 4096

# Matches BINARY_MAX_AGE_DAYS_BEFORE_DELETION in 02_download_binaries.py - older
# entries don't have local cache info, so reporting on them is uninformative.
DATA_MAX_AGE_DAYS = 60

# A pdb_fingerprint is a 32-char GUID in hex followed by the decimal age, as
# written by append_pe_information in script 03.
PDB_FINGERPRINT_GUID_LEN = 32

# Manual (binary, timestamp, image_size) -> (pdb_filename, pdb_fingerprint)
# mappings extracted from Windhawk debug logs by extract_pdb_mappings_from_logs.py.
# Used as a fallback for binaries we couldn't download or extract locally.
MANUAL_PDB_MAPPINGS_PATH = Path(__file__).parent / 'manual_pdb_mappings.json'


@dataclass
class LocalFileInfo:
    file_present: bool
    extraction_done: bool
    pdb_filename: str | None
    pdb_fingerprint: str | None


@dataclass
class StatusRow:
    sha256: str
    date: datetime
    update_id: str
    version: str
    assembly_version: str
    file_url: str | None
    file_available: bool
    pdb_url: str | None
    pdb_available: bool


def djb2_hash(s: str) -> int:
    h = 5381
    for c in s:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h


def fetch_winbindex_data(session: requests.Session, name: str, target_arch: str, insider: bool):
    if insider:
        url = (
            f'https://m417z.com/winbindex-data-insider/by_filename_compressed/'
            f'{djb2_hash(name) & 0xFF:02x}/{name}.json.gz'
        )
    elif target_arch == 'arm64':
        url = f'https://m417z.com/winbindex-data-arm64/by_filename_compressed/{name}.json.gz'
    else:
        url = f'https://winbindex.m417z.com/data/by_filename_compressed/{name}.json.gz'

    r = session.get(url, timeout=60)
    if r.status_code == 404 and name in NAMES_TO_ALLOW_404:
        return None
    r.raise_for_status()
    return json.loads(gzip.decompress(r.content).decode())


def fetch_all_winbindex_data(modules: list[str]) -> dict[tuple[str, str], dict | None]:
    """Fetch Winbindex data for every (module, variant) pair in parallel."""
    tasks = [
        (name, label, target_arch, insider)
        for name in modules
        for label, target_arch, insider in ARCH_VARIANTS
    ]

    session = requests.Session()

    def fetch(task):
        name, label, target_arch, insider = task
        data = fetch_winbindex_data(session, name, target_arch, insider)
        return (name, label), data

    cache: dict[tuple[str, str], dict | None] = {}
    with ThreadPoolExecutor(max_workers=WINBINDEX_FETCH_WORKERS) as ex:
        for key, data in ex.map(fetch, tasks):
            cache[key] = data
    return cache


def make_file_url(file_name: str, timestamp: int, size: int) -> str:
    return f'{SYMBOL_SERVER_BASE}/{file_name}/{timestamp:08X}{size:x}/{file_name}'


def make_pdb_url(pdb_name: str, signature: str, age: int) -> str:
    return f'{SYMBOL_SERVER_BASE}/{pdb_name}/{signature}{age:X}/{pdb_name}'


def parse_pdb_fingerprint(fingerprint: str) -> tuple[str, int]:
    """Split a pdb_fingerprint into its GUID and decimal age components."""
    if len(fingerprint) <= PDB_FINGERPRINT_GUID_LEN:
        raise ValueError(f'pdb_fingerprint too short: {fingerprint!r}')
    guid = fingerprint[:PDB_FINGERPRINT_GUID_LEN]
    age = int(fingerprint[PDB_FINGERPRINT_GUID_LEN:])
    return guid, age


def parse_version_for_sort(version: str) -> tuple[int, ...]:
    """Turn a dotted version string into an int tuple suitable for ordering.
    Empty input sorts before any populated version.
    """
    if not version:
        return ()
    return tuple(int(p) for p in version.split('.'))


def truncate_with_full_in_comment(prefix: str, full: str) -> str:
    """Render a truncated value followed by an HTML comment carrying the full
    string, so it stays searchable in the rendered markdown.
    """
    return f'{prefix}...<!-- {full} -->'


def get_modules_from_extracted_symbols(extracted_symbols_path: Path) -> set[str]:
    with extracted_symbols_path.open() as f:
        data = json.load(f)

    modules: set[str] = set()
    for archs in data.values():
        for binaries in archs.values():
            for module in binaries:
                modules.add(module)
    return modules


def extract_assembly_version(update_data: dict) -> str | None:
    for assembly in (update_data.get('assemblies') or {}).values():
        version = (assembly.get('assemblyIdentity') or {}).get('version')
        if version:
            return version
    return None


def release_info_for_insider(update_data: dict, update_key: str) -> tuple[datetime, str]:
    ts = update_data['updateInfo']['created']
    release_date = datetime.fromtimestamp(ts)
    # Insider update keys are UUIDs; the full value is the id, presentation
    # decides how to display it.
    return release_date, update_key


def release_info_for_base(update_data: dict, windows_version_key: str) -> tuple[datetime, str]:
    release_date_ymd = update_data['windowsVersionInfo']['releaseDate']
    release_date = datetime.strptime(release_date_ymd, '%Y-%m-%d')
    update_id = f'{windows_version_key} BASE'
    return release_date, update_id


def release_info_for_kb(update_data: dict, update_key: str) -> tuple[datetime, str]:
    release_date_ymd = update_data['updateInfo']['releaseDate']
    release_date = datetime.strptime(release_date_ymd, '%Y-%m-%d')
    # Update key is the KB id, e.g. 'KB5006674'.
    return release_date, update_key


def latest_update_info(
    hash_data: dict, insider: bool
) -> tuple[datetime | None, str | None, str | None]:
    last_date: datetime | None = None
    last_update_id: str | None = None
    last_assembly_version: str | None = None

    for windows_version_key, windows_version_info in hash_data['windowsVersions'].items():
        for update_key, update_data in windows_version_info.items():
            if insider:
                release_date, update_id = release_info_for_insider(update_data, update_key)
            elif update_key == 'BASE':
                release_date, update_id = release_info_for_base(update_data, windows_version_key)
            else:
                release_date, update_id = release_info_for_kb(update_data, update_key)

            if last_date is None or release_date > last_date:
                last_date = release_date
                last_update_id = update_id
                last_assembly_version = extract_assembly_version(update_data)

    return last_date, last_update_id, last_assembly_version


def parse_symbols_txt_tail(txt_path: Path) -> LocalFileInfo:
    """Read just the tail of a .txt file produced by 03_extract_symbols_from_binaries
    to pull out the metadata lines without scanning megabytes of symbols.

    A `timestamp=` line indicates `append_pe_information` ran, which only happens
    when `windhawk-symbol-helper.exe` succeeded - i.e. the PDB was downloadable.
    """
    extraction_done = False
    pdb_filename: str | None = None
    pdb_fingerprint: str | None = None

    with txt_path.open('rb') as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - SYMBOLS_TXT_TAIL_BYTES))
        tail = f.read()

    for raw_line in tail.splitlines():
        try:
            line = raw_line.decode('utf-8')
        except UnicodeDecodeError:
            # The fixed-size tail can land mid-codepoint on the first line; the
            # metadata fields are pure ASCII so any undecodable line is junk.
            continue
        if line.startswith('timestamp='):
            extraction_done = True
        elif line.startswith('pdb_filename='):
            pdb_filename = line.split('=', 1)[1]
        elif line.startswith('pdb_fingerprint='):
            pdb_fingerprint = line.split('=', 1)[1]

    return LocalFileInfo(
        file_present=True,
        extraction_done=extraction_done,
        pdb_filename=pdb_filename,
        pdb_fingerprint=pdb_fingerprint,
    )


def build_local_info_map(binaries_folder: Path, name: str) -> dict[str, LocalFileInfo]:
    """Build a {hash: info} map for a binary by scanning every arch subdirectory
    once. Avoids per-hash iterdir/exists calls when consulting Winbindex hashes.
    """
    binary_dir = binaries_folder / name
    if not binary_dir.is_dir():
        return {}

    extension = name.rsplit('.', 1)[-1] if '.' in name else ''
    txt_suffix = f'.{extension}.txt' if extension else '.txt'
    bin_suffix = f'.{extension}' if extension else ''

    result: dict[str, LocalFileInfo] = {}
    for arch_dir in binary_dir.iterdir():
        if not arch_dir.is_dir():
            continue
        for entry in arch_dir.iterdir():
            entry_name = entry.name
            if entry_name.endswith(txt_suffix):
                hash_value = entry_name[: -len(txt_suffix)]
                result[hash_value] = parse_symbols_txt_tail(entry)
            elif bin_suffix and entry_name.endswith(bin_suffix):
                # Unprocessed binary (script 03 hasn't run yet).
                hash_value = entry_name[: -len(bin_suffix)]
                if hash_value not in result:
                    result[hash_value] = LocalFileInfo(
                        file_present=True,
                        extraction_done=False,
                        pdb_filename=None,
                        pdb_fingerprint=None,
                    )
    return result


def resolve_arch(file_info: dict) -> str:
    machine_type = file_info['machineType']
    try:
        return MACHINE_TYPE_TO_ARCH[machine_type]
    except KeyError:
        raise ValueError(f'Unknown machine type: {machine_type}') from None


def pdb_url_from_local(local: LocalFileInfo | None) -> str | None:
    if local is None or local.pdb_filename is None or local.pdb_fingerprint is None:
        return None
    guid, age = parse_pdb_fingerprint(local.pdb_fingerprint)
    return make_pdb_url(local.pdb_filename, guid, age)


def find_manual_pdb_entry(
    binary_name: str, file_info: dict, manual_mapping: dict
) -> dict | None:
    """Look up a manual-mapping entry for a Winbindex hash by (binary,
    timestamp). Returns the entry dict if there's a match with a non-empty
    pdb_filename, else None. Entries with an empty pdb_filename are placeholders
    awaiting manual fill-in and are skipped here.
    """
    timestamp = file_info.get('timestamp')
    if timestamp is None:
        return None

    virtual_size = file_info.get('virtualSize')
    binary_entries = manual_mapping.get(binary_name, {})
    if virtual_size is not None:
        entry = binary_entries.get(f'{timestamp}-{virtual_size}')
    else:
        # Winbindex sometimes lacks virtualSize for a hash. Timestamp alone is
        # unique enough in practice.
        prefix = f'{timestamp}-'
        matches = [v for k, v in binary_entries.items() if k.startswith(prefix)]
        if len(matches) > 1:
            raise ValueError(
                f'Multiple manual mapping entries match {binary_name} '
                f'timestamp {timestamp}: {len(matches)} candidates'
            )
        entry = matches[0] if matches else None

    if entry is None or not entry['pdb_filename']:
        return None
    return entry


def load_manual_pdb_mappings(path: Path) -> dict:
    if not path.is_file():
        return {}
    with path.open(encoding='utf-8') as f:
        return json.load(f)


def file_url_from_info(name: str, file_info: dict) -> str | None:
    timestamp = file_info.get('timestamp')
    size = file_info.get('virtualSize') or file_info.get('size')
    if timestamp is None or size is None:
        return None
    return make_file_url(name, timestamp, size)


def collect_rows(
    name: str,
    target_arch: str,
    insider: bool,
    data: dict | None,
    local_map: dict[str, LocalFileInfo],
    manual_pdb_mapping: dict,
    now: datetime,
) -> list[StatusRow]:
    if not data:
        return []

    rows: list[StatusRow] = []
    for hash_value, hash_data in data.items():
        file_info = hash_data.get('fileInfo')
        if not file_info:
            continue

        if resolve_arch(file_info) != target_arch:
            continue

        date, update_id, assembly_version = latest_update_info(hash_data, insider)
        if date is None or (now - date).days > DATA_MAX_AGE_DAYS:
            continue

        # File version comes back as e.g. '10.0.26100.8115 (WinBuild.160101.0800)';
        # the parenthesised suffix is the same for every Windows file and adds noise.
        version = (file_info.get('version') or '').split(' (', 1)[0]

        local = local_map.get(hash_value)
        manual_entry = find_manual_pdb_entry(name, file_info, manual_pdb_mapping)

        pdb_url = pdb_url_from_local(local)
        if pdb_url is None and manual_entry is not None:
            guid, age = parse_pdb_fingerprint(manual_entry['pdb_fingerprint'])
            pdb_url = make_pdb_url(manual_entry['pdb_filename'], guid, age)

        # A matching manual mapping means the binary itself isn't on the symbol
        # server (that's why we synthesize a PE in script 02), so report the
        # File column as unavailable even though we have a local .txt.
        file_available = (
            bool(local and local.file_present) and manual_entry is None
        )

        rows.append(StatusRow(
            sha256=hash_value,
            date=date,
            update_id=update_id or '',
            version=version,
            assembly_version=assembly_version or '',
            file_url=file_url_from_info(name, file_info),
            file_available=file_available,
            pdb_url=pdb_url,
            pdb_available=bool(local and local.extraction_done),
        ))

    rows.sort(
        key=lambda r: (r.date, parse_version_for_sort(r.assembly_version), r.sha256),
        reverse=True,
    )
    return rows


def availability_cell(url: str | None, available: bool) -> str:
    text = '🟢' if available else '🔴'
    if url:
        return f'[{text}]({url})'
    return text


def pdb_availability_cell(url: str | None, available: bool) -> str:
    # The PDB GUID+age comes from inspecting the binary, so without local info
    # we have no URL to query - PDB availability on the symbol server is
    # genuinely unknown rather than absent.
    if url is None:
        return '❓'
    text = '🟢' if available else '🔴'
    return f'[{text}]({url})'


def render_update_id_cell(update_id: str, insider: bool) -> str:
    if not insider:
        return update_id
    # Insider update ids are UUIDs; show the leading segment and stash the full
    # value in an HTML comment, mirroring the SHA256 cell formatting.
    return truncate_with_full_in_comment(update_id.split('-', 1)[0], update_id)


def render_table(rows: list[StatusRow], insider: bool) -> str:
    if not rows:
        return '_No data._\n'

    lines = [
        '| SHA256 | Update date | Update id | File version | Assembly version | File on symbol server | PDB on symbol server |',
        '| ------ | ----------- | --------- | ------------ | ---------------- | --------------------- | -------------------- |',
    ]
    for row in rows:
        sha_cell = truncate_with_full_in_comment(row.sha256[:6], row.sha256)
        date_str = row.date.strftime('%Y-%m-%d')
        update_id_cell = render_update_id_cell(row.update_id, insider)
        file_cell = availability_cell(row.file_url, row.file_available)
        pdb_cell = pdb_availability_cell(row.pdb_url, row.pdb_available)
        lines.append(
            f'| {sha_cell} | {date_str} | {update_id_cell} | {row.version} | {row.assembly_version} | {file_cell} | {pdb_cell} |'
        )
    return '\n'.join(lines) + '\n'


def render_binary_page(name: str, tables: dict[str, str]) -> str:
    parts = [f'# {name}', '']
    for label, _, _ in ARCH_VARIANTS:
        parts.append(f'## {label}')
        parts.append('')
        parts.append(tables[label])
    return '\n'.join(parts)


def render_toc(names: list[str]) -> str:
    lines = ['# Symbol cache availability status', '', '| Binary |', '| ------ |']
    for name in sorted(names):
        lines.append(f'| [{name}]({name}.md) |')
    return '\n'.join(lines) + '\n'


def create_status(extracted_symbols_path: Path, binaries_folder: Path, status_folder: Path):
    status_folder.mkdir(parents=True, exist_ok=True)

    modules = sorted(get_modules_from_extracted_symbols(extracted_symbols_path))
    manual_pdb_mapping = load_manual_pdb_mappings(MANUAL_PDB_MAPPINGS_PATH)

    print(f'Fetching Winbindex data for {len(modules)} binaries')
    winbindex_cache = fetch_all_winbindex_data(modules)

    now = datetime.now()

    for name in modules:
        print(f'Processing {name}')
        local_map = build_local_info_map(binaries_folder, name)

        tables: dict[str, str] = {}
        for label, target_arch, insider in ARCH_VARIANTS:
            data = winbindex_cache.get((name, label))
            rows = collect_rows(
                name, target_arch, insider, data, local_map, manual_pdb_mapping, now
            )
            tables[label] = render_table(rows, insider)

        page = render_binary_page(name, tables)
        (status_folder / f'{name}.md').write_text(page, encoding='utf-8')

    toc = render_toc(modules)
    (status_folder / 'README.md').write_text(toc, encoding='utf-8')


def main():
    parser = ArgumentParser()
    parser.add_argument('extracted_symbols_path', type=Path)
    parser.add_argument('binaries_folder', type=Path)
    parser.add_argument('status_folder', type=Path)
    args = parser.parse_args()

    create_status(args.extracted_symbols_path, args.binaries_folder, args.status_folder)


if __name__ == '__main__':
    main()
