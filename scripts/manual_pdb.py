"""Helpers for the manual (binary, timestamp, image_size) -> (pdb_filename,
pdb_fingerprint) mapping. The mapping captures Windhawk debug log evidence about
PDBs whose binaries aren't available on the symbol server.

When script 02 sees that a hash it would normally download has a matching entry,
it instead drops a synthetic PE shell next to the (missing) binary - just enough
scaffolding for LoadLibraryEx(LOAD_LIBRARY_AS_IMAGE_RESOURCE) and msdia's
loadDataForExe to find the embedded CV_INFO_PDB70 and pull the real PDB. From
script 03 onward the synthetic file is indistinguishable from any other
downloaded binary.
"""

import struct

# PE format constants used by synthesize_pdb_lookup_pe.
_IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
_IMAGE_FILE_DLL = 0x2000
_IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
_IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
_IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
_IMAGE_DEBUG_TYPE_CODEVIEW = 2
_IMAGE_DIRECTORY_ENTRY_DEBUG = 6
_IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40
_IMAGE_SCN_MEM_READ = 0x40000000
_PE_MACHINES_64BIT = {0x8664, 0xAA64}  # amd64, arm64

_PE_DOS_HEADER_SIZE = 64
_PE_SIGNATURE = b'PE\x00\x00'
_PE_FILE_HEADER_SIZE = 20
_PE_SECTION_HEADER_SIZE = 40
_PE_DEBUG_DIR_ENTRY_SIZE = 28
_PE_NUM_DATA_DIRECTORIES = 16
_PE_DATA_DIRECTORY_SIZE = 8
_PE_FILE_ALIGNMENT = 0x200
_PE_SECTION_ALIGNMENT = 0x1000


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def synthesize_pdb_lookup_pe(machine: int,
                             timestamp: int,
                             image_size: int,
                             pdb_filename: str,
                             pdb_fingerprint: str) -> bytes:
    """Build the smallest PE shell that windhawk-symbol-helper.exe accepts.
    Only the debug directory's CV_INFO_PDB70 record carries meaningful data;
    everything else is just enough scaffolding for
    LoadLibraryEx(LOAD_LIBRARY_AS_IMAGE_RESOURCE) and msdia's loadDataForExe
    to parse the file and locate the PDB on the symbol server.
    """
    if len(pdb_fingerprint) <= 32:
        raise ValueError(f'pdb_fingerprint too short: {pdb_fingerprint!r}')

    # Fingerprint format (per script 03's append_pe_information): hex dump of
    # GUID's Data1/Data2/Data3/Data4 components followed by the decimal age.
    # On disk those components are written in their native endianness (LE for
    # the three integers, raw bytes for Data4), which is what we need here.
    guid_hex = pdb_fingerprint[:32]
    age = int(pdb_fingerprint[32:])
    data1 = int(guid_hex[0:8], 16)
    data2 = int(guid_hex[8:12], 16)
    data3 = int(guid_hex[12:16], 16)
    data4 = bytes.fromhex(guid_hex[16:32])
    guid_disk = struct.pack('<IHH', data1, data2, data3) + data4

    cv_info = (
        b'RSDS' + guid_disk + struct.pack('<I', age)
        + pdb_filename.encode('utf-8') + b'\x00'
    )

    is_64bit = machine in _PE_MACHINES_64BIT
    optional_header_size = 240 if is_64bit else 224

    headers_unaligned = (
        _PE_DOS_HEADER_SIZE
        + len(_PE_SIGNATURE)
        + _PE_FILE_HEADER_SIZE
        + optional_header_size
        + _PE_SECTION_HEADER_SIZE
    )
    headers_aligned = _align_up(headers_unaligned, _PE_FILE_ALIGNMENT)

    section_rva = _PE_SECTION_ALIGNMENT
    cv_info_rva = section_rva + _PE_DEBUG_DIR_ENTRY_SIZE
    section_pointer_to_raw_data = headers_aligned

    debug_dir_entry = struct.pack(
        '<IIHHIIII',
        0,                                  # Characteristics
        timestamp,                          # TimeDateStamp
        0, 0,                               # MajorVersion, MinorVersion
        _IMAGE_DEBUG_TYPE_CODEVIEW,
        len(cv_info),                       # SizeOfData
        cv_info_rva,                        # AddressOfRawData (RVA)
        section_pointer_to_raw_data + _PE_DEBUG_DIR_ENTRY_SIZE,
    )
    section_data = debug_dir_entry + cv_info
    section_virtual_size = len(section_data)
    section_raw_size_aligned = _align_up(section_virtual_size, _PE_FILE_ALIGNMENT)

    image_size_required = _align_up(section_rva + section_virtual_size,
                                    _PE_SECTION_ALIGNMENT)
    final_image_size = max(image_size, image_size_required)

    dos_header = bytearray(_PE_DOS_HEADER_SIZE)
    dos_header[0:2] = b'MZ'
    struct.pack_into('<I', dos_header, 0x3C, _PE_DOS_HEADER_SIZE)  # e_lfanew

    file_header = struct.pack(
        '<HHIIIHH',
        machine,
        1,                                  # NumberOfSections
        timestamp,
        0, 0,                               # PointerToSymbolTable, NumberOfSymbols
        optional_header_size,
        _IMAGE_FILE_EXECUTABLE_IMAGE | _IMAGE_FILE_DLL,
    )

    if is_64bit:
        optional_header = struct.pack(
            '<HBBIIIIIQ' 'IIHHHHHHIIIIHHQQQQII',
            _IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            14, 0,
            0, 0, 0, 0, 0,
            0x180000000,
            _PE_SECTION_ALIGNMENT, _PE_FILE_ALIGNMENT,
            6, 0, 0, 0, 6, 0,
            0,
            final_image_size, headers_aligned, 0,
            _IMAGE_SUBSYSTEM_WINDOWS_GUI, 0,
            0x100000, 0x1000,
            0x100000, 0x1000,
            0, _PE_NUM_DATA_DIRECTORIES,
        )
    else:
        optional_header = struct.pack(
            '<HBBIIIIIIIIIIHHHHHHIIIIHHIIIIII',
            _IMAGE_NT_OPTIONAL_HDR32_MAGIC,
            14, 0,
            0, 0, 0, 0, 0, 0,
            0x10000000,
            _PE_SECTION_ALIGNMENT, _PE_FILE_ALIGNMENT,
            6, 0, 0, 0, 6, 0,
            0,
            final_image_size, headers_aligned, 0,
            _IMAGE_SUBSYSTEM_WINDOWS_GUI, 0,
            0x100000, 0x1000,
            0x100000, 0x1000,
            0, _PE_NUM_DATA_DIRECTORIES,
        )

    data_directories = bytearray(_PE_NUM_DATA_DIRECTORIES * _PE_DATA_DIRECTORY_SIZE)
    struct.pack_into(
        '<II',
        data_directories,
        _IMAGE_DIRECTORY_ENTRY_DEBUG * _PE_DATA_DIRECTORY_SIZE,
        section_rva,
        _PE_DEBUG_DIR_ENTRY_SIZE,
    )
    optional_header_with_dirs = optional_header + bytes(data_directories)
    if len(optional_header_with_dirs) != optional_header_size:
        raise RuntimeError(
            f'optional header size mismatch: '
            f'{len(optional_header_with_dirs)} vs {optional_header_size}'
        )

    section_header = struct.pack(
        '<8sIIIIIIHHI',
        b'.debug\x00\x00',
        section_virtual_size,
        section_rva,
        section_raw_size_aligned,
        section_pointer_to_raw_data,
        0, 0, 0, 0,
        _IMAGE_SCN_CNT_INITIALIZED_DATA | _IMAGE_SCN_MEM_READ,
    )

    pe = bytearray()
    pe += dos_header
    pe += _PE_SIGNATURE
    pe += file_header
    pe += optional_header_with_dirs
    pe += section_header
    pe += bytes(headers_aligned - len(pe))
    pe += section_data
    pe += bytes(section_raw_size_aligned - section_virtual_size)
    return bytes(pe)
