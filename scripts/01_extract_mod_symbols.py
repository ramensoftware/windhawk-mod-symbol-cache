import json
import re
from argparse import ArgumentParser
from pathlib import Path

ALL_ARCHITECTURES = [
    'x86',
    'x86-64',
]

SYMBOL_BLOCK_MODULES_BY_BLOCK_NAME: dict[tuple[str, str], list[str]] = {
    ('aerexplorer', 'efHooks'): ['ExplorerFrame.dll'],
    ('aerexplorer', 'isCplHooks'): ['ExplorerFrame.dll'],
    ('aerexplorer', 'shHooks'): ['shell32.dll'],
    ('aerexplorer', 'storageHooks'): ['windows.storage.dll'],
    ('aero-flyout-fix', 'actioncenterHooks'): ['ActionCenter.dll'],
    ('aero-flyout-fix', 'sndvolHooks'): ['SndVol.exe'],
    ('aero-flyout-fix', 'stobjectHooks'): ['stobject.dll'],
    ('aero-flyout-fix', 'timedateHooks'): ['timedate.cpl'],
    ('aero-tray', 'hooks'): ['explorer.exe'],
    ('classic-file-picker-dialog', 'symbolHook'): ['comdlg32.dll'],
    ('desktop-watermark-tweaks', 'hooks'): ['shell32.dll'],
    ('dwm-ghost-mods', 'hooks'): ['dwmghost.dll'],
    ('dwm-unextend-frames', 'comctl32_hook'): ['comctl32.dll'],
    ('pinned-items-double-click', 'symbolHooks'): ['Taskbar.dll', 'explorer.exe'],
    ('start-menu-all-apps', 'taskbarHooks'): ['StartMenu.dll'],
    ('taskbar-autohide-better', 'symbolHooks'): ['Taskbar.dll', 'explorer.exe'],
    ('taskbar-button-click', 'symbolHooks'): ['Taskbar.dll', 'explorer.exe'],
    ('taskbar-clock-customization', 'taskbarHooks10'): ['explorer.exe'],
    ('taskbar-clock-customization', 'taskbarHooks11'): ['Taskbar.View.dll'],
    ('taskbar-thumbnail-reorder', 'symbolHooks'): ['Taskbar.dll', 'explorer.exe'],
    ('unlock-taskmgr-server', 'hook'): ['taskmgr.exe'],
    ('virtual-desktop-taskbar-order', 'taskbarSymbolHooks'): ['Taskbar.dll', 'explorer.exe'],
    ('virtual-desktop-taskbar-order', 'twinuiPcshellSymbolHooks'): ['twinui.pcshell.dll'],
    ('win32-tray-clock-experience', 'hooks'): ['Taskbar.dll', 'explorer.exe'],
    ('windows-7-clock-spacing', 'hooks'): ['explorer.exe'],
}

SYMBOL_BLOCK_MODULES_BY_FUNCTION: dict[str, list[str]] = {
    'HookTaskbarSymbols': ['Taskbar.dll', 'explorer.exe'],
    'HookTaskbarDllSymbols': ['Taskbar.dll', 'explorer.exe'],
    'HookTaskbarViewDllSymbols': ['Taskbar.View.dll'],
    'HookExplorerFrameSymbols': ['ExplorerFrame.dll'],
    'HookFileExplorerExtensionsSymbols': ['FileExplorerExtensions.dll'],
    'HookICMH_CAODTM': [
        'shell32.dll',
        'ExplorerFrame.dll',
        'explorer.exe',
        'twinui.dll',
        'twinui.pcshell.dll',
        'SndVolSSO.dll',
        'pnidui.dll',
        'SecurityHealthSSO.dll',
        'Narrator.exe',
    ],
}

SYMBOL_BLOCK_MODULES_BY_MODULE_NAME: dict[str, list[str]] = {
    'dwmcore': ['dwmcore.dll'],
    'hAppFrameModule': ['ApplicationFrame.dll'],
    'hComCtl': ['comctl32.dll'],
    'hComCtl32': ['comctl32.dll'],
    'hExplFrame': ['ExplorerFrame.dll'],
    'hExplorer': ['explorer.exe'],
    'hExplorerFrame': ['ExplorerFrame.dll'],
    'hRegEdit': ['regedit.exe'],
    'hShell32': ['shell32.dll'],
    'hShutdownUx': ['shutdownux.dll'],
    'hUser32': ['user32.dll'],
    'hUxTheme': ['uxtheme.dll'],
    'udwm': ['udwm.dll'],
    'user32': ['user32.dll'],
    'uxtheme': ['uxtheme.dll'],
}


def get_mod_metadata(mod_name: str, mod_source: str):
    p = r'^\/\/[ \t]+==WindhawkMod==[ \t]*$([\s\S]+?)^\/\/[ \t]+==\/WindhawkMod==[ \t]*$'
    match = re.search(p, mod_source, re.MULTILINE)
    if not match:
        raise Exception(f'Mod {mod_name} has no metadata block')
    
    metadata_block = match.group(1)

    p = r'^\/\/[ \t]+@architecture[ \t]+(.*)$'
    match = re.findall(p, metadata_block, re.MULTILINE)

    architecture = match or ALL_ARCHITECTURES

    if any (x not in ALL_ARCHITECTURES for x in architecture):
        raise Exception(f'Mod {mod_name} has unknown architecture')

    return {
        'architectures': architecture,
    }


def process_symbol_block(mod_name: str, mod_source: str, symbol_block_match: re.Match, string_definitions: dict[str, str]):
    symbol_block = symbol_block_match.group(0)
    symbol_block_name = symbol_block_match.group(1)

    # Make sure there are no preprocessor directives.
    p = r'^[ \t]*#'
    if re.search(p, symbol_block, re.MULTILINE):
        raise Exception(f'Mod {mod_name}, block {symbol_block_name}: Unsupported preprocessor directives')

    # Merge strings spanning over multiple lines.
    p = r'"([ \t]*\n)+[ \t]*L?"'
    symbol_block = re.sub(p, '', symbol_block)

    # Replace string definitions.
    def sub(match):
        symbol = match.group(1)
        if symbol is None:
            symbol = match.group(2)

        if symbol not in string_definitions:
            raise Exception(f'Mod {mod_name}, block {symbol_block_name}: Unknown string definition {symbol}')

        return string_definitions[symbol]

    p = r'"\s*(\w+)\s*L"|"\s+(\w+)\s+"'
    symbol_block = re.sub(p, sub, symbol_block)

    # Extract symbols.
    p = r'LR"\((.*?)\)"|L"(.*?)"'
    symbols = re.findall(p, symbol_block)
    symbols = list(map(lambda x: x[0] if x[0] else x[1], symbols))

    if any('"' in x or '\\' in x for x in symbols):
        raise Exception(f'Mod {mod_name}, block {symbol_block_name}: Unsupported strings')

    if len(symbols) * 2 != symbol_block.count('"'):
        raise Exception(f'Mod {mod_name}, block {symbol_block_name}: Unsupported strings')

    if symbols == []:
        return None

    # Deduce modules.
    modules = SYMBOL_BLOCK_MODULES_BY_BLOCK_NAME.get((mod_name, symbol_block_name))
    if modules is None:
        if symbol_block[0] not in [' ', '\t']:
            print(f'Mod {mod_name}, block {symbol_block_name}: No indentation for deducing function')

        mod_source_before = mod_source[:symbol_block_match.start(0)]
        p = r'^\S*[ \t]\S.*'
        last_function_line = re.findall(p, mod_source_before, re.MULTILINE)[-1]

        p = r'(\w+)\('
        if match := re.search(p, last_function_line):
            last_function = match.group(1)
        else:
            raise Exception(f'Mod {mod_name}, block {symbol_block_name}: Can not deduce function name')

        if last_function in SYMBOL_BLOCK_MODULES_BY_FUNCTION:
            modules = SYMBOL_BLOCK_MODULES_BY_FUNCTION[last_function]

        mod_source_after = mod_source[symbol_block_match.end(0):]
        p = r'^\}[ \t]*$'
        if match := re.search(p, mod_source_after, re.MULTILINE):
            function_remainder_code = mod_source_after[:match.end(0)]
        else:
            raise Exception(f'Mod {mod_name}, block {symbol_block_name}: Can not deduce function code')

        p = rf'HookSymbols\(\s*(\w+),\s*&?{re.escape(symbol_block_name)},'
        if (match := re.findall(p, function_remainder_code, re.MULTILINE)) and len(match) == 1:
            module_name = match[0]

            if module_name in SYMBOL_BLOCK_MODULES_BY_MODULE_NAME:
                modules_by_module_name = SYMBOL_BLOCK_MODULES_BY_MODULE_NAME[module_name]
                if modules is None:
                    modules = modules_by_module_name
                elif modules != modules_by_module_name:
                    raise Exception(f'Mod {mod_name}, block {symbol_block_name}: Conflicting module names ({modules} and {modules_by_module_name})')
        else:
            module_name = None

    if modules is None:
        raise Exception(f'Mod {mod_name}, block {symbol_block_name}: Unknown module ({last_function=}, {module_name=})')

    modules = list(map(lambda x: x.lower(), modules))

    return {
        'symbols': symbols,
        'modules': modules,
    }


def get_mod_symbol_blocks(mod_name: str, mod_source: str, arch: str):
    # Remove comments.
    mod_source = re.sub(r'[ \t]*//.*', '', mod_source)
    mod_source = re.sub(r'/\*[\s\S]*?\*/', '', mod_source)

    # Expand #ifdef _WIN64 conditions.
    def sub(match):
        if match.group(1) == 'ifdef':
            condition_matches = arch == 'x86-64'
        else:
            assert match.group(1) == 'ifndef'
            condition_matches = arch != 'x86-64'

        if condition_matches:
            return match.group(2)

        return match.group(4) or ''

    p = r'^[ \t]*#(ifn?def)[ \t]*_WIN64[ \t]*([\s\S]*?)(^[ \t]*#else[ \t]*$([\s\S]*?))?^[ \t]*#endif[ \t]*$'
    mod_source = re.sub(p, sub, mod_source, flags=re.MULTILINE)

    # Extract string definitions.
    p = r'^[ \t]*#[ \t]*define[ \t]+(\w+)[ \t]+L"(.*?)"[ \t]*$'
    string_definitions = dict(re.findall(p, mod_source, re.MULTILINE))
    if any('"' in x for x in string_definitions.values()):
        raise Exception(f'Mod {mod_name} has unsupported string definitions')

    # Extract symbol blocks.
    symbol_blocks = []
    p = r'^[ \t]*(?:const[ \t]+)?(?:CMWF_|WindhawkUtils::)?SYMBOL_HOOK[ \t]+(\w+)[\[ \t][\s\S]*?\};[ \t]*$'
    for match in re.finditer(p, mod_source, re.MULTILINE):
        try:
            symbol_block = process_symbol_block(mod_name, mod_source, match, string_definitions)
        except Exception as e:
            print(f'Mod {mod_name}, block {match.group(1)}: {e}')
            symbol_block = None

        symbol_blocks.append(symbol_block)

    p = r'SYMBOL_HOOK.*=(?![^{\n]+;)'
    if len(symbol_blocks) != len(re.findall(p, mod_source, re.MULTILINE)):
        raise Exception(f'Mod {mod_name} has unsupported symbol blocks')

    symbol_blocks = list(filter(lambda x: x is not None, symbol_blocks))

    return symbol_blocks


def get_mod_symbols(mod_name: str, path: Path):
    result = {}

    mod_source = path.read_text(encoding='utf-8')

    metadata = get_mod_metadata(mod_name, mod_source)

    for arch in metadata['architectures']:
        symbol_blocks = get_mod_symbol_blocks(mod_name, mod_source, arch)
        if len(symbol_blocks) == 0:
            continue

        result[arch] = {}
        for block in symbol_blocks:
            for module in block['modules']:
                result[arch][module] = block['symbols']

    return result


def main():
    parser = ArgumentParser()
    parser.add_argument('mods_folder', type=Path)
    parser.add_argument('output_file', type=Path)
    args = parser.parse_args()

    mods_folder = args.mods_folder
    output_file = args.output_file

    result = {}

    for path in mods_folder.glob('*.wh.cpp'):
        mod_name = path.name.removesuffix('.wh.cpp')
        mod_symbols = get_mod_symbols(mod_name, path)
        if len(mod_symbols) == 0:
            continue

        result[mod_name] = mod_symbols

    if str(output_file) == '-':
        print(json.dumps(result, indent=2))
    else:
        with output_file.open('w') as f:
            json.dump(result, f, indent=2)


if __name__ == '__main__':
    main()
