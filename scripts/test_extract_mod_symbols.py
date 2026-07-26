"""Tests for reading the symbol names out of a mod.

The point of most cases here is what the extractor refuses. A symbol which is
missing from the cache is invisible - the mod still builds, and nothing downstream
knows a name was meant to be there - so a block whose names can't be read has to
raise rather than contribute whatever part of itself happened to be readable.
"""

import importlib.util
import sys
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPTS))

_spec = importlib.util.spec_from_file_location(
    'extract_mod_symbols', _SCRIPTS / '01_extract_mod_symbols.py')
extract = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(extract)


class SymbolBlockTestCase(unittest.TestCase):
    def symbols(self, block: str):
        return extract.get_symbol_block_symbols(block)

    def assertRejected(self, block: str, message: str):
        with self.assertRaises(Exception) as context:
            self.symbols(block)
        self.assertIn(message, str(context.exception))


class TestSymbolNameLists(SymbolBlockTestCase):
    def test_an_array_of_hooks(self):
        block = ('const SYMBOL_HOOK hooks[] = {\n'
                 '    {{L"a"}, (void**)&originalA, hookA},\n'
                 '    {{L"b", L"c"}, (void**)&originalB, hookB, true},\n'
                 '};')
        self.assertEqual(self.symbols(block), ['a', 'b', 'c'])

    def test_a_single_hook(self):
        block = 'SYMBOL_HOOK hook = {{L"a"}, (void**)&original, hookFunction};'
        self.assertEqual(self.symbols(block), ['a'])

    def test_a_single_hook_with_a_braced_initializer(self):
        block = 'SYMBOL_HOOK hook{{L"a"}, (void**)&original};'
        self.assertEqual(self.symbols(block), ['a'])

    def test_trailing_commas(self):
        block = ('SYMBOL_HOOK hooks[] = {\n'
                 '    {{L"a", L"b",}, (void**)&original, hookFunction,},\n'
                 '};')
        self.assertEqual(self.symbols(block), ['a', 'b'])

    def test_a_comma_inside_a_name_is_not_a_separator(self):
        block = 'SYMBOL_HOOK hooks[] = {{{L"f(int,int)"}, (void**)&original}};'
        self.assertEqual(self.symbols(block), ['f(int,int)'])

    def test_members_after_the_names_are_not_read_as_names(self):
        # The other members hold identifiers by nature, and a comma between
        # template arguments splits them further. Neither is a symbol name.
        block = ('SYMBOL_HOOK hooks[] = {\n'
                 '    {{L"a"}, (void**)&Class<int, long>::original, hookFunction},\n'
                 '};')
        self.assertEqual(self.symbols(block), ['a'])


class TestRejectedSymbolNames(SymbolBlockTestCase):
    def test_a_name_which_is_an_identifier(self):
        block = 'SYMBOL_HOOK hooks[] = {{{kSymbolName}, (void**)&original}};'
        self.assertRejected(block, 'Symbol name is not a string: kSymbolName')

    def test_a_name_which_is_an_identifier_beside_a_name_which_is_a_string(self):
        block = 'SYMBOL_HOOK hooks[] = {{{L"a", kSymbolName}, (void**)&original}};'
        self.assertRejected(block, 'Symbol name is not a string: kSymbolName')

    def test_a_name_which_is_a_qualified_identifier(self):
        block = 'SYMBOL_HOOK hooks[] = {{{Names::kSymbol}, (void**)&original}};'
        self.assertRejected(block, 'Symbol name is not a string: Names::kSymbol')

    def test_a_name_which_is_a_call(self):
        block = 'SYMBOL_HOOK hooks[] = {{{GetSymbolName()}, (void**)&original}};'
        self.assertRejected(block, 'Symbol name is not a string: GetSymbolName()')

    def test_a_name_which_is_an_element_of_an_array(self):
        block = 'SYMBOL_HOOK hooks[] = {{{names[0]}, (void**)&original}};'
        self.assertRejected(block, 'Symbol name is not a string: names[0]')

    def test_a_name_which_is_a_cast(self):
        block = 'SYMBOL_HOOK hooks[] = {{{(PCWSTR)pName}, (void**)&original}};'
        self.assertRejected(block, 'Symbol name is not a string: (PCWSTR)pName')

    def test_a_name_beside_an_unexpanded_macro(self):
        block = 'SYMBOL_HOOK hooks[] = {{{L"a" SUFFIX}, (void**)&original}};'
        self.assertRejected(block, 'Symbol name is not a string: L"a" SUFFIX')

    def test_a_name_list_which_is_not_a_list(self):
        # A whole list taken from somewhere else, as a hook built in a loop does.
        block = 'SYMBOL_HOOK hook = {hooks[i].symbols, &addresses[i], NULL};'
        self.assertRejected(block, 'Unsupported symbol name list: hooks[i].symbols')

    def test_a_hook_without_a_name(self):
        block = 'SYMBOL_HOOK hooks[] = {{{}, (void**)&original}};'
        self.assertRejected(block, 'Symbol hook without a name')

    def test_an_entry_which_is_not_a_hook(self):
        block = 'SYMBOL_HOOK hooks[] = {hookA, hookB};'
        self.assertRejected(block, 'Unsupported symbol hook: hookA')

    def test_an_unterminated_block(self):
        self.assertRejected('SYMBOL_HOOK hooks[] = {{{L"a"}, &original};',
                            'Unsupported symbol block')


class TestConditionalSymbolNames(SymbolBlockTestCase):
    """A name chosen when the mod runs is a name the mod can hook, so every
    branch of a conditional counts and the condition itself is disregarded."""

    def test_both_branches_are_taken(self):
        block = ('SYMBOL_HOOK hooks[] = {{\n'
                 '    {version == Legacy ? L"a" : L"b"},\n'
                 '    (void**)&original,\n'
                 '}};')
        self.assertEqual(self.symbols(block), ['a', 'b'])

    def test_a_chain_of_conditionals(self):
        block = 'SYMBOL_HOOK hooks[] = {{{c1 ? L"a" : c2 ? L"b" : L"c"}, &original}};'
        self.assertEqual(self.symbols(block), ['a', 'b', 'c'])

    def test_a_conditional_nested_in_a_branch(self):
        block = 'SYMBOL_HOOK hooks[] = {{{c1 ? (c2 ? L"a" : L"b") : L"c"}, &original}};'
        self.assertEqual(self.symbols(block), ['a', 'b', 'c'])

    def test_a_scope_operator_in_the_condition(self):
        block = 'SYMBOL_HOOK hooks[] = {{{v == Ver::Win10 ? L"a" : L"b"}, &original}};'
        self.assertEqual(self.symbols(block), ['a', 'b'])

    def test_a_branch_which_is_not_a_string(self):
        block = 'SYMBOL_HOOK hooks[] = {{{c ? L"a" : kSymbolName}, &original}};'
        self.assertRejected(block, 'Symbol name is not a string: kSymbolName')


class TestProcessSymbolBlock(unittest.TestCase):
    """The whole of a block, macros and the check on stray strings included."""

    def process(self, mod_source: str):
        blocks = extract.get_mod_symbol_blocks(mod_source, extract.Architecture.amd64)
        return [symbol for block in blocks for symbol in block['symbols']]

    def test_a_block_with_a_module_comment(self):
        source = ('// target.dll\n'
                  'const SYMBOL_HOOK hooks[] = {\n'
                  '    {{L"a"}, (void**)&original, hookFunction},\n'
                  '};\n')
        self.assertEqual(self.process(source), ['a'])

    def test_a_name_built_from_a_macro(self):
        source = ('#define CALL L" __cdecl "\n'
                  'const SYMBOL_HOOK targetDllHooks[] = {\n'
                  '    {{L"void" CALL L"f(void)"}, (void**)&original},\n'
                  '};\n')
        self.assertEqual(self.process(source), ['void __cdecl f(void)'])

    def test_a_string_given_to_a_member_which_is_not_the_names(self):
        source = ('const SYMBOL_HOOK targetDllHooks[] = {\n'
                  '    {{L"a"}, (void**)&original, L"b"},\n'
                  '};\n')
        with self.assertRaises(Exception) as context:
            self.process(source)
        self.assertIn('Unsupported strings', str(context.exception))

    def test_a_block_without_symbols(self):
        source = 'const SYMBOL_HOOK targetDllHooks[] = {};\n'
        with self.assertRaises(Exception) as context:
            self.process(source)
        self.assertIn('Symbol block without symbols', str(context.exception))


if __name__ == '__main__':
    unittest.main()
