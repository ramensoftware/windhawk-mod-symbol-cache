"""Tests for the minimal C preprocessor.

Every case here asserts one of two outcomes: the module gets the answer a C
preprocessor would give, or it refuses to answer - a conditional left unresolved,
or an exception. A case which is neither is a bug, since the caller reads symbol
names out of the result and has no way to tell a wrong answer from a right one.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from preprocessor import (  # noqa: E402
    FunctionLikeMacro,
    MacroState,
    blank_comments,
    check_literals_are_fully_expanded,
    concat_adjacent_literals,
    expand_macros,
    find_bracket_group_end,
    get_string_literal_value,
    get_string_literals,
    iter_top_level_characters,
    preprocess_conditionals,
    split_top_level,
)

# The outcome of a two branch conditional.
THEN = 'then'
ELSE = 'else'
UNRESOLVED = 'unresolved'


class PreprocessorTestCase(unittest.TestCase):
    def preprocess(self, source: str, defined=None, undefined=()):
        result = preprocess_conditionals(source, defined or {}, undefined)

        # Line numbers of the result have to index into the original source.
        self.assertEqual(len(result.source.split('\n')),
                         len(source.split('\n')))
        for index, line in enumerate(result.source.split('\n')):
            self.assertIn(line, ('', source.split('\n')[index]))

        return result

    def kept_lines(self, source: str, defined=None, undefined=()):
        """The lines of the source which are part of the build, in order."""
        result = self.preprocess(source, defined, undefined)
        return [x.strip() for x in result.source.split('\n') if x.strip()]

    def select_branch(self, expression: str, defined=None, undefined=()):
        """Which branch of "#if <expression> ... #else ... #endif" is taken."""
        source = f'#if {expression}\nTHEN\n#else\nELSE\n#endif\n'
        result = self.preprocess(source, defined, undefined)

        if result.unresolved_lines:
            # An unresolved group is reported whole and left exactly as it was.
            self.assertEqual(sorted(result.unresolved_lines), [0, 1, 2, 3, 4])
            self.assertEqual(result.source, source)
            return UNRESOLVED

        kept = [x.strip() for x in result.source.split('\n') if x.strip()]
        self.assertIn(kept, [['THEN'], ['ELSE']])
        return THEN if kept == ['THEN'] else ELSE


class TestBlankComments(PreprocessorTestCase):
    def assert_blanked(self, code: str, *comments: str):
        """Exactly the given comments become spaces, newlines aside."""
        expected = code

        for comment in comments:
            self.assertIn(comment, expected)
            expected = expected.replace(
                comment, ''.join('\n' if x == '\n' else ' ' for x in comment))

        self.assertEqual(blank_comments(code), expected)

    def test_comments_become_spaces_in_place(self):
        self.assert_blanked('int a; // one\nint b; /* two */ int c;\n',
                            '// one', '/* two */')

    def test_block_comment_keeps_line_structure(self):
        self.assert_blanked('a /* one\ntwo\nthree */ b\n',
                            '/* one\ntwo\nthree */')

    def test_unterminated_block_comment_reaches_the_end(self):
        self.assert_blanked('a /* b\nc', '/* b\nc')

    def test_line_comment_continued_with_a_backslash(self):
        self.assert_blanked('// one \\\nstill a comment\nint a;\n',
                            '// one \\\nstill a comment')

    def test_comment_markers_inside_a_string_literal(self):
        for code in ('char* s = "// not a comment";',
                     'char* s = "/* not a comment */";',
                     'char* s = L"//";',
                     'char* s = u8"/*";',
                     'char* s = "a\\"//\\"b";'):
            with self.subTest(code=code):
                self.assertEqual(blank_comments(code), code)

    def test_comment_markers_inside_a_raw_string_literal(self):
        for code in ('char* s = R"(// not a comment)";',
                     'char* s = R"(/* not a comment)";',
                     'char* s = R"x(a)"//)x";',
                     'char* s = LR"(//\n/*)";'):
            with self.subTest(code=code):
                self.assertEqual(blank_comments(code), code)

    def test_comment_markers_inside_a_character_literal(self):
        self.assert_blanked("char c = '/'; char d = '\\''; // gone\n",
                            '// gone')

    def test_a_quote_inside_a_character_literal_is_not_a_string(self):
        self.assert_blanked('char c = \'"\'; // gone\n', '// gone')

    def test_a_digit_separator_is_not_a_character_literal(self):
        self.assert_blanked("int a = 1'000'000; // gone\nint b;\n", '// gone')

    def test_an_odd_apostrophe_does_not_swallow_the_code_after_it(self):
        # No literal starts here, so the comment which follows is still blanked.
        self.assert_blanked('#error can\'t\nint a; // "NotASymbol"\n',
                            '// "NotASymbol"')

    def test_an_unterminated_string_does_not_swallow_the_code_after_it(self):
        self.assert_blanked('char* s = "abc;\nint a; // gone\n', '// gone')

    def test_a_comment_wins_over_a_literal_which_starts_inside_it(self):
        self.assert_blanked('// "unterminated\nint a;\n', '// "unterminated')

    def test_a_block_comment_ends_at_the_first_terminator(self):
        self.assert_blanked('a /* /* */ b\n', '/* /* */')
        self.assert_blanked('a /*/ b\n', '/*/ b\n')

    def test_a_line_comment_may_start_with_a_block_marker(self):
        self.assert_blanked('a //* b\nc\n', '//* b')


class TestGetStringLiterals(PreprocessorTestCase):
    def test_plain_and_prefixed_literals(self):
        code = '{"a", L"b", u8"c", u"d", U"e"}'
        self.assertEqual(get_string_literals(code), ['a', 'b', 'c', 'd', 'e'])

    def test_escapes_are_kept_as_written(self):
        self.assertEqual(get_string_literals(r'"a\"b\\c"'), [r'a\"b\\c'])

    def test_raw_literals(self):
        code = 'R"(a"b)" R"x(c)"d)x" LR"()"'
        self.assertEqual(get_string_literals(code), ['a"b', 'c)"d', ''])

    def test_character_literals_are_not_string_literals(self):
        self.assertEqual(get_string_literals("{'a', 'b'}"), [])

    def test_a_quote_inside_a_character_literal_is_not_a_string(self):
        self.assertEqual(get_string_literals('{\'"\', "sym"}'), ['sym'])

    def test_a_digit_separator_does_not_hide_a_string(self):
        self.assertEqual(get_string_literals('{1\'0000, "sym"}'), ['sym'])


class TestGetStringLiteralValue(PreprocessorTestCase):
    def test_a_literal_on_its_own(self):
        self.assertEqual(get_string_literal_value('  L"sym"  '), 'sym')

    def test_a_raw_literal_on_its_own(self):
        self.assertEqual(get_string_literal_value('LR"(a(b)c)"'), 'a(b)c')

    def test_an_identifier_is_not_a_literal(self):
        self.assertIsNone(get_string_literal_value('kSymbolName'))

    def test_a_literal_with_anything_beside_it_is_not_a_literal(self):
        self.assertIsNone(get_string_literal_value('L"a" MACRO'))
        self.assertIsNone(get_string_literal_value('L"a" L"b"'))
        self.assertIsNone(get_string_literal_value('f(L"a")'))


class TestCodeScanning(PreprocessorTestCase):
    def test_split_on_a_separator_which_brackets_enclose(self):
        code = 'a, f(b, c), {d, e}, g[h, i]'
        self.assertEqual(split_top_level(code, ','),
                         ['a', ' f(b, c)', ' {d, e}', ' g[h, i]'])

    def test_split_on_a_separator_which_a_literal_holds(self):
        self.assertEqual(split_top_level('"a,b", "c"', ','), ['"a,b"', ' "c"'])

    def test_split_without_a_separator(self):
        self.assertEqual(split_top_level('a', ','), ['a'])

    def test_split_keeps_empty_parts(self):
        self.assertEqual(split_top_level('a,,b,', ','), ['a', '', 'b', ''])

    def test_a_bracket_inside_a_literal_is_not_a_bracket(self):
        self.assertEqual(split_top_level('{"}", a}, b', ','), ['{"}", a}', ' b'])

    def test_template_arguments_do_not_nest(self):
        # Angle brackets aren't counted, so a comma between template arguments
        # splits like any other.
        self.assertEqual(split_top_level('a<b, c>, d', ','), ['a<b', ' c>', ' d'])

    def test_find_the_end_of_a_bracket_group(self):
        code = 'x = {a, {b}, c}; y'
        self.assertEqual(find_bracket_group_end(code, 4), len('x = {a, {b}, c}'))

    def test_find_the_end_of_a_bracket_group_holding_a_literal(self):
        code = '{"}"} '
        self.assertEqual(find_bracket_group_end(code, 0), 5)

    def test_an_unclosed_bracket_group_has_no_end(self):
        self.assertIsNone(find_bracket_group_end('{a, {b}', 0))

    def test_top_level_characters_skip_brackets_and_literals(self):
        code = 'a?{b}:"c"'
        self.assertEqual([x for _, x in iter_top_level_characters(code)],
                         ['a', '?', ':'])


class TestResolvedConditionals(PreprocessorTestCase):
    def test_if_true_and_false(self):
        self.assertEqual(self.select_branch('1'), THEN)
        self.assertEqual(self.select_branch('0'), ELSE)

    def test_ifdef_and_ifndef(self):
        cases = [
            ('#ifdef A', {'A': '1'}, (), THEN),
            ('#ifdef A', {}, ['A'], ELSE),
            ('#ifdef A', {}, (), UNRESOLVED),
            ('#ifndef A', {'A': '1'}, (), ELSE),
            ('#ifndef A', {}, ['A'], THEN),
            ('#ifndef A', {}, (), UNRESOLVED),
        ]

        for directive, defined, undefined, expected in cases:
            with self.subTest(directive=directive, defined=defined):
                source = f'{directive}\nTHEN\n#else\nELSE\n#endif\n'
                result = self.preprocess(source, defined, undefined)
                if expected is UNRESOLVED:
                    self.assertEqual(sorted(result.unresolved_lines),
                                     [0, 1, 2, 3, 4])
                else:
                    kept = [x for x in result.source.split('\n') if x]
                    self.assertEqual(kept, [expected.upper()])

    def test_ifdef_with_something_other_than_a_name(self):
        source = '#ifdef A B\nTHEN\n#endif\n'
        self.assertEqual(sorted(self.preprocess(source).unresolved_lines),
                         [0, 1, 2])

    def test_elif_chain(self):
        source = ('#if A == 1\nONE\n#elif A == 2\nTWO\n#elif A == 3\nTHREE\n'
                  '#else\nOTHER\n#endif\n')
        for value, expected in (('1', 'ONE'), ('2', 'TWO'), ('3', 'THREE'),
                                ('4', 'OTHER')):
            with self.subTest(value=value):
                self.assertEqual(self.kept_lines(source, {'A': value}),
                                 [expected])

    def test_elif_without_else_can_take_no_branch(self):
        source = '#if 0\nONE\n#elif 0\nTWO\n#endif\n'
        self.assertEqual(self.kept_lines(source), [])

    def test_an_earlier_true_branch_hides_a_later_unknown_condition(self):
        source = '#if 1\nONE\n#elif UNKNOWN\nTWO\n#endif\n'
        result = self.preprocess(source)
        self.assertEqual(result.unresolved_lines, {})
        self.assertEqual(self.kept_lines(source), ['ONE'])

    def test_nested_conditionals(self):
        source = ('#if A\n'
                  'A\n'
                  '#ifdef B\n'
                  'AB\n'
                  '#else\n'
                  'AnotB\n'
                  '#endif\n'
                  '#else\n'
                  'notA\n'
                  '#endif\n')
        self.assertEqual(self.kept_lines(source, {'A': '1', 'B': ''}),
                         ['A', 'AB'])
        self.assertEqual(self.kept_lines(source, {'A': '1'}, ['B']),
                         ['A', 'AnotB'])
        self.assertEqual(self.kept_lines(source, {'A': '0'}, ['B']), ['notA'])

    def test_directives_may_be_indented_and_spaced_out(self):
        source = '  #  ifdef A\nTHEN\n\t#\telse\nELSE\n   #endif\n'
        self.assertEqual(self.kept_lines(source, {'A': '1'}), ['THEN'])

    def test_a_directive_continued_over_lines(self):
        source = '#if defined(A) && \\\n    defined(B)\nBOTH\n#endif\n'
        self.assertEqual(self.kept_lines(source, {'A': '1', 'B': '1'}), ['BOTH'])
        self.assertEqual(self.kept_lines(source, {'A': '1'}, ['B']), [])

    def test_other_directives_are_left_alone(self):
        source = ('#include <windows.h>\n'
                  '#pragma once\n'
                  '#if 0\n'
                  '#pragma dropped\n'
                  '#endif\n')
        self.assertEqual(self.kept_lines(source),
                         ['#include <windows.h>', '#pragma once'])

    def test_a_directive_inside_a_comment_is_not_a_directive(self):
        source = ('/*\n#if 0\n*/\nCODE\n')
        self.assertEqual(self.kept_lines(source), ['/*', '#if 0', '*/', 'CODE'])

    def test_a_directive_inside_a_raw_string_is_not_a_directive(self):
        source = 'char* s = R"(\n#if 0\nx\n#endif\n)";\n'
        result = self.preprocess(source)
        self.assertEqual(result.source, source)
        self.assertEqual(result.unresolved_lines, {})

    def test_an_unbalanced_endif_inside_a_raw_string_is_not_a_directive(self):
        source = 'char* s = R"(\n#endif\n)";\nCODE\n'
        self.assertEqual(self.preprocess(source).source, source)

    def test_a_hash_in_the_middle_of_a_spliced_line_is_not_a_directive(self):
        # The backslash joins the two lines, so what follows it is code.
        source = 'int a = 1; \\\n#define A 1\nCODE\n'
        result = self.preprocess(source)
        self.assertEqual(result.source, source)
        self.assertNotIn('A', result.macros)

    def test_a_spliced_line_is_dropped_as_a_whole(self):
        source = '#if 0\nint a = 1; \\\n    + 2;\n#endif\nCODE\n'
        self.assertEqual(self.kept_lines(source), ['CODE'])


class TestMalformedConditionals(PreprocessorTestCase):
    def test_endif_without_if(self):
        with self.assertRaises(Exception):
            preprocess_conditionals('CODE\n#endif\n', {})

    def test_else_without_if(self):
        with self.assertRaises(Exception):
            preprocess_conditionals('CODE\n#else\nCODE\n', {})

    def test_unterminated_if(self):
        with self.assertRaises(Exception):
            preprocess_conditionals('#if 1\nCODE\n', {})

    def test_unterminated_nested_if(self):
        with self.assertRaises(Exception):
            preprocess_conditionals('#if 1\n#if 1\n#endif\n', {})

    def test_elif_after_else(self):
        with self.assertRaises(Exception):
            preprocess_conditionals('#if 1\n#else\n#elif 1\n#endif\n', {})

    def test_else_after_else(self):
        with self.assertRaises(Exception):
            preprocess_conditionals('#if 1\n#else\n#else\n#endif\n', {})


class TestConditionalExpressions(PreprocessorTestCase):
    def test_arithmetic_and_comparisons(self):
        true_expressions = [
            '2 > 1',
            '1 >= 1',
            '1 != 2',
            '2 == 2',
            '1 + 2 * 3 == 7',
            '(1 + 2) * 3 == 9',
            '10 - 2 - 3 == 5',
            '0x10 == 16',
            '1l == 1',
            '10 / 3 == 3',
            '-7 / 2 == -3',
            '-7 % 2 == -1',
            '7 % -2 == 1',
            '1 << 4 == 16',
            '256 >> 4 == 16',
            '~0 == -1',
            '-(-1) == 1',
            '+1 == 1',
            '!0',
            '!!5',
            '(6 & 3) == 2',
            '(6 | 1) == 7',
            '(6 ^ 3) == 5',
            "'A' == 65",
            '1 && 2',
            '0 || 3',
            '-9223372036854775807 - 1 < 0',
        ]

        for expression in true_expressions:
            with self.subTest(expression=expression):
                self.assertEqual(self.select_branch(expression), THEN)

        for expression in true_expressions:
            with self.subTest(expression=f'!({expression})'):
                self.assertEqual(self.select_branch(f'!({expression})'), ELSE)

    def test_octal_is_not_treated_as_decimal(self):
        self.assertEqual(self.select_branch('017 == 15'), THEN)
        self.assertEqual(self.select_branch('017 == 17'), ELSE)
        self.assertEqual(self.select_branch('0 == 0'), THEN)
        # 09 isn't a valid octal literal.
        self.assertEqual(self.select_branch('09 == 9'), UNRESOLVED)

    def test_operator_precedence_matches_c(self):
        cases = [
            # == binds tighter than &, | and ^, so these are not 2, 7 and 5.
            ('6 & 3 == 2', ELSE),
            ('6 | 1 == 7', THEN),
            ('(6 | 1 == 7) == 6', THEN),
            ('(6 ^ 3 == 5) == 6', THEN),
            # Shifts bind tighter than comparisons.
            ('1 << 2 > 3', THEN),
            ('(1 << 2 > 3) == 1', THEN),
            # && binds tighter than ||.
            ('0 && 0 || 1', THEN),
            ('1 || 1 && 0', THEN),
        ]

        for expression, expected in cases:
            with self.subTest(expression=expression):
                self.assertEqual(self.select_branch(expression), expected)

    def test_an_undefined_macro_is_zero(self):
        self.assertEqual(self.select_branch('A', {}, ['A']), ELSE)
        self.assertEqual(self.select_branch('!A', {}, ['A']), THEN)
        self.assertEqual(self.select_branch('A == 0', {}, ['A']), THEN)

    def test_defined(self):
        cases = [
            ('defined(A)', {'A': '0'}, (), THEN),
            ('defined A', {'A': '0'}, (), THEN),
            ('!defined(A)', {'A': '0'}, (), ELSE),
            ('defined(A)', {}, ['A'], ELSE),
            ('defined(A)', {}, (), UNRESOLVED),
            ('defined(A) || defined(B)', {'B': '1'}, (), THEN),
            ('defined(A) && defined(B)', {}, ['A'], ELSE),
        ]

        for expression, defined, undefined, expected in cases:
            with self.subTest(expression=expression, defined=defined):
                self.assertEqual(
                    self.select_branch(expression, defined, undefined), expected)

    def test_short_circuit_with_an_unknown_operand(self):
        cases = [
            ('UNKNOWN && 0', ELSE),
            ('0 && UNKNOWN', ELSE),
            ('UNKNOWN || 1', THEN),
            ('1 || UNKNOWN', THEN),
            ('UNKNOWN && 1', UNRESOLVED),
            ('UNKNOWN || 0', UNRESOLVED),
            ('UNKNOWN', UNRESOLVED),
            ('!UNKNOWN', UNRESOLVED),
            ('UNKNOWN > 1', UNRESOLVED),
            ('UNKNOWN * 0', UNRESOLVED),
        ]

        for expression, expected in cases:
            with self.subTest(expression=expression):
                self.assertEqual(self.select_branch(expression), expected)

    def test_a_macro_value_is_evaluated(self):
        self.assertEqual(self.select_branch('A', {'A': '1'}), THEN)
        self.assertEqual(self.select_branch('A', {'A': '0'}), ELSE)
        self.assertEqual(self.select_branch('A > 1', {'A': '2'}), THEN)
        self.assertEqual(self.select_branch('A', {'A': '1 + 2'}), THEN)
        self.assertEqual(self.select_branch('A', {'A': 'B'}, ['B']), ELSE)
        self.assertEqual(self.select_branch('A + 1 == 3', {'A': 'B', 'B': '2'}),
                         THEN)
        self.assertEqual(self.select_branch('A + 1 == 3', {'A': 'B'}),
                         UNRESOLVED)
        self.assertEqual(self.select_branch('A * 3 == 9', {'A': '(1 + 2)'}),
                         THEN)

    def test_a_macro_value_which_could_bind_differently_is_not_guessed(self):
        # 1+2*3 is 7, not (1+2)*3, so the value can't be evaluated on its own.
        self.assertEqual(self.select_branch('A * 3 == 7', {'A': '1 + 2'}),
                         UNRESOLVED)
        self.assertEqual(self.select_branch('-A == -3', {'A': '1 + 2'}),
                         UNRESOLVED)
        self.assertEqual(self.select_branch('(A)', {'A': '1 + 2'}), UNRESOLVED)

    def test_a_macro_which_expands_to_itself(self):
        self.assertEqual(self.select_branch('A', {'A': 'A'}), UNRESOLVED)
        self.assertEqual(self.select_branch('A', {'A': 'B', 'B': 'A'}),
                         UNRESOLVED)

    def test_a_macro_with_an_empty_value(self):
        self.assertEqual(self.select_branch('A', {'A': ''}), UNRESOLVED)
        self.assertEqual(self.select_branch('defined(A)', {'A': ''}), THEN)

    def test_unsupported_expressions_are_not_guessed(self):
        expressions = [
            '',
            '1 ? 2 : 3',
            '1.5 > 1',
            '1, 2',
            '(1',
            '1)',
            '1 1',
            '1 = 1',
            "'ab' == 24930",
            '0u == 0',
            '1U',
            '__has_include(<windows.h>)',
            '__has_include("a.h")',
            '__has_attribute(x)',
            '1 / 0',
            '1 % 0',
            '1 << 64',
            '1 << -1',
            '1 >> 64',
            '0x7fffffffffffffff + 1',
            '-9223372036854775807 - 2 < 0',
            '0x8000000000000000',
            '1 << 62 << 1',
            '"a" == "a"',
        ]

        for expression in expressions:
            with self.subTest(expression=expression):
                self.assertEqual(self.select_branch(expression), UNRESOLVED)

    def test_a_condition_which_depends_on_an_ambiguous_macro(self):
        source = ('#if UNKNOWN\n'
                  '#define A 1\n'
                  '#endif\n'
                  '#ifdef A\n'
                  'IFDEF\n'
                  '#endif\n'
                  '#if A\n'
                  'IF\n'
                  '#endif\n'
                  '#define B A\n'
                  '#if B\n'
                  'THROUGH_B\n'
                  '#endif\n')
        result = self.preprocess(source)
        self.assertEqual(sorted(result.unresolved_lines),
                         [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12])

    def test_a_digit_separator_in_a_condition_is_not_guessed(self):
        self.assertEqual(self.select_branch("1'000 > 1"), UNRESOLVED)

    def test_a_function_like_macro_in_a_condition_is_not_guessed(self):
        source = ('#define F(x) x + 1\n'
                  '#if F(1) == 2\n'
                  'THEN\n'
                  '#endif\n')
        result = self.preprocess(source)
        self.assertEqual(sorted(result.unresolved_lines), [1, 2, 3])

    def test_a_function_like_macro_is_defined(self):
        source = ('#define F(x) x + 1\n'
                  '#if defined(F)\n'
                  'THEN\n'
                  '#endif\n')
        self.assertEqual(self.kept_lines(source), ['#define F(x) x + 1', 'THEN'])

    def test_a_function_like_macro_without_an_invocation_is_not_guessed(self):
        source = ('#define F(x) x + 1\n'
                  '#if F\n'
                  'THEN\n'
                  '#endif\n')
        self.assertEqual(sorted(self.preprocess(source).unresolved_lines),
                         [1, 2, 3])

    def test_an_unsupported_macro_is_defined_but_has_no_value(self):
        source = ('#define S(x) #x\n'
                  '#if defined(S)\n'
                  'DEFINED\n'
                  '#endif\n'
                  '#if S\n'
                  'VALUE\n'
                  '#endif\n')
        result = self.preprocess(source)
        self.assertEqual(sorted(result.unresolved_lines), [4, 5, 6])
        self.assertIn('DEFINED', result.source)


class TestUnresolvedGroups(PreprocessorTestCase):
    def test_an_unresolved_group_is_left_exactly_as_it_was(self):
        source = ('BEFORE\n'
                  '#if UNKNOWN\n'
                  'A\n'
                  '#else\n'
                  'B\n'
                  '#endif\n'
                  'AFTER\n')
        result = self.preprocess(source)
        self.assertEqual(result.source, source)
        self.assertEqual(sorted(result.unresolved_lines), [1, 2, 3, 4, 5])
        self.assertEqual(set(result.unresolved_lines.values()),
                         {'#if UNKNOWN'})

    def test_the_span_of_a_multi_line_directive_is_reported(self):
        source = ('#if defined(A) && \\\n'
                  '    defined(UNKNOWN)\n'
                  'A\n'
                  '#endif\n')
        result = self.preprocess(source, {'A': '1'})
        self.assertEqual(sorted(result.unresolved_lines), [0, 1, 2, 3])

    def test_the_outermost_unresolved_group_explains_its_lines(self):
        source = ('#if UNKNOWN_OUTER\n'
                  '#if UNKNOWN_INNER\n'
                  'A\n'
                  '#endif\n'
                  '#endif\n')
        result = self.preprocess(source)
        self.assertEqual(set(result.unresolved_lines.values()),
                         {'#if UNKNOWN_OUTER'})

    def test_a_resolvable_group_inside_an_unresolved_one(self):
        source = ('#if UNKNOWN\n'
                  '#if 0\n'
                  'DROPPED\n'
                  '#endif\n'
                  'KEPT\n'
                  '#endif\n')
        result = self.preprocess(source)
        self.assertNotIn('DROPPED', result.source)
        self.assertIn('KEPT', result.source)
        self.assertEqual(sorted(result.unresolved_lines), [0, 1, 2, 3, 4, 5])

    def test_an_unresolved_group_inside_a_branch_which_is_not_built(self):
        source = ('#if 0\n'
                  '#if UNKNOWN\n'
                  'A\n'
                  '#endif\n'
                  '#endif\n'
                  'AFTER\n')
        result = self.preprocess(source)
        self.assertEqual(result.unresolved_lines, {})
        self.assertEqual(self.kept_lines(source), ['AFTER'])

    def test_an_unresolved_elif_reports_the_whole_group(self):
        source = ('#if 0\n'
                  'A\n'
                  '#elif UNKNOWN\n'
                  'B\n'
                  '#else\n'
                  'C\n'
                  '#endif\n')
        result = self.preprocess(source)
        self.assertEqual(sorted(result.unresolved_lines), [0, 1, 2, 3, 4, 5, 6])
        self.assertEqual(result.source, source)

    def test_a_macro_from_before_an_unresolved_group_is_still_known(self):
        source = ('#define A 1\n'
                  '#if UNKNOWN\n'
                  'X\n'
                  '#endif\n'
                  '#if A\n'
                  'Y\n'
                  '#endif\n')
        result = self.preprocess(source)
        self.assertEqual(sorted(result.unresolved_lines), [1, 2, 3])
        self.assertIn('Y', result.source)

    def test_a_later_group_is_still_resolved(self):
        source = ('#if UNKNOWN\n'
                  'A\n'
                  '#endif\n'
                  '#if 1\n'
                  'B\n'
                  '#endif\n')
        result = self.preprocess(source)
        self.assertEqual(sorted(result.unresolved_lines), [0, 1, 2])
        self.assertIn('B', result.source)


class TestDefinitions(PreprocessorTestCase):
    def macros(self, source: str, defined=None, undefined=()):
        return self.preprocess(source, defined, undefined).macros

    def test_object_like_definitions(self):
        cases = [
            ('#define A 1\n', 'A', '1'),
            ('#define A\n', 'A', ''),
            ('#define A 1 + 2\n', 'A', '1 + 2'),
            ('#define A (1 + 2)\n', 'A', '(1 + 2)'),
            ('#define A 1 // comment\n', 'A', '1'),
            ('#define A /* comment */ 1\n', 'A', '1'),
            ('#define A "text"\n', 'A', '"text"'),
            ('#define A \\\n    1\n', 'A', '1'),
            ('#define A "#"\n', 'A', '"#"'),
        ]

        for source, name, value in cases:
            with self.subTest(source=source):
                self.assertEqual(self.macros(source)[name], value)

    def test_function_like_definitions(self):
        macros = self.macros('#define F(a, b) a + b\n#define G() 1\n')
        self.assertEqual(macros['F'], FunctionLikeMacro(['a', 'b'], 'a + b'))
        self.assertEqual(macros['G'], FunctionLikeMacro([], '1'))

    def test_unsupported_definitions(self):
        for source in ('#define S(x) #x\n',
                       '#define P(a, b) a##b\n',
                       '#define V(...) f(__VA_ARGS__)\n',
                       '#define W(a, ...) f(a)\n',
                       '#define AB X ## Y\n'):
            with self.subTest(source=source):
                name = source.split()[1].split('(')[0]
                self.assertIs(self.macros(source)[name], MacroState.UNSUPPORTED)

    def test_undef(self):
        macros = self.macros('#define A 1\n#undef A\n')
        self.assertIs(macros['A'], MacroState.UNDEFINED)

    def test_undef_of_a_macro_which_was_never_defined(self):
        source = '#undef A\n#ifdef A\nTHEN\n#else\nELSE\n#endif\n'
        self.assertEqual(self.kept_lines(source), ['#undef A', 'ELSE'])

    def test_a_definition_continued_over_lines(self):
        macros = self.macros('#define F(a) \\\n    a + \\\n    1\n')
        self.assertEqual(macros['F'], FunctionLikeMacro(['a'], 'a +      1'))

    def test_a_definition_replaces_an_earlier_one(self):
        self.assertEqual(self.macros('#define A 1\n#define A 2\n')['A'], '2')

    def test_a_definition_in_a_branch_which_is_not_built_is_ignored(self):
        macros = self.macros('#if 0\n#define A 1\n#endif\n')
        self.assertIs(macros['A'], MacroState.UNDEFINED)

    def test_a_definition_in_a_branch_which_is_not_taken_is_ignored(self):
        macros = self.macros('#if 1\n#define A 1\n#else\n#define B 2\n#endif\n')
        self.assertEqual(macros['A'], '1')
        self.assertIs(macros['B'], MacroState.UNDEFINED)

    def test_an_earlier_definition_survives_a_branch_which_is_not_taken(self):
        macros = self.macros('#define A 1\n#if 0\n#define A 2\n#endif\n')
        self.assertEqual(macros['A'], '1')

    def test_a_definition_under_an_unresolved_condition_is_ambiguous(self):
        for source in ('#if UNKNOWN\n#define A 1\n#endif\n',
                       '#if UNKNOWN\n#define A 1\n#else\n#define A 2\n#endif\n',
                       '#define A 1\n#if UNKNOWN\n#undef A\n#endif\n'):
            with self.subTest(source=source):
                self.assertIs(self.macros(source)['A'], MacroState.AMBIGUOUS)

    def test_definitions_apply_in_order(self):
        source = ('#ifdef A\n'
                  'BEFORE\n'
                  '#endif\n'
                  '#define A 1\n'
                  '#ifdef A\n'
                  'AFTER\n'
                  '#endif\n')
        result = self.preprocess(source, {}, ['A'])
        self.assertEqual([x for x in result.source.split('\n') if x],
                         ['#define A 1', 'AFTER'])

    def test_a_definition_decides_a_later_condition(self):
        source = ('#define A 2\n'
                  '#if A == 2\n'
                  'TWO\n'
                  '#else\n'
                  'OTHER\n'
                  '#endif\n')
        self.assertEqual(self.kept_lines(source), ['#define A 2', 'TWO'])

    def test_the_given_macros_are_reported_too(self):
        macros = self.macros('CODE\n', {'A': '1'}, ['B'])
        self.assertEqual(macros['A'], '1')
        self.assertIs(macros['B'], MacroState.UNDEFINED)


class TestExpandMacros(PreprocessorTestCase):
    def test_object_like_expansion(self):
        self.assertEqual(expand_macros('a A b', {'A': '1'}), 'a 1 b')

    def test_expansion_is_repeated(self):
        macros = {'A': 'B', 'B': 'C', 'C': '1'}
        self.assertEqual(expand_macros('A', macros), '1')

    def test_a_name_which_is_not_a_macro_is_left_alone(self):
        self.assertEqual(expand_macros('AB A_ xA', {'A': '1'}), 'AB A_ xA')

    def test_an_undefined_macro_is_left_alone(self):
        self.assertEqual(expand_macros('A', {'A': MacroState.UNDEFINED}), 'A')

    def test_literals_are_not_expanded(self):
        macros = {'A': '1'}
        for code in ('"A"', 'L"A"', "'A'", 'R"(A)"', 'u8"A A"'):
            with self.subTest(code=code):
                self.assertEqual(expand_macros(code, macros), code)

    def test_a_digit_separator_is_not_a_literal(self):
        self.assertEqual(expand_macros("1'000'000 + A", {'A': '2'}),
                         "1'000'000 + 2")

    def test_function_like_expansion(self):
        macros = {'F': FunctionLikeMacro(['a', 'b'], '(a) + (b)')}
        self.assertEqual(expand_macros('F(1, 2)', macros), '(1) + (2)')
        self.assertEqual(expand_macros('F( 1 , 2 )', macros), '(1) + (2)')
        self.assertEqual(expand_macros('F(1,\n2)', macros), '(1) + (2)')

    def test_function_like_expansion_with_no_parameters(self):
        macros = {'F': FunctionLikeMacro([], '1')}
        self.assertEqual(expand_macros('F()', macros), '1')

    def test_an_empty_argument(self):
        macros = {'F': FunctionLikeMacro(['a'], '[a]')}
        self.assertEqual(expand_macros('F()', macros), '[]')

    def test_an_argument_which_is_a_macro(self):
        macros = {'F': FunctionLikeMacro(['a'], '[a]'), 'A': '1'}
        self.assertEqual(expand_macros('F(A)', macros), '[1]')

    def test_an_argument_may_hold_commas_in_parentheses_or_literals(self):
        macros = {'F': FunctionLikeMacro(['a'], '[a]')}
        self.assertEqual(expand_macros('F(g(1, 2))', macros), '[g(1, 2)]')
        self.assertEqual(expand_macros('F("1, 2")', macros), '["1, 2"]')
        self.assertEqual(expand_macros("F(',')", macros), "[',']")

    def test_a_parameter_is_only_replaced_as_a_whole_name(self):
        macros = {'F': FunctionLikeMacro(['a'], 'a ab _a "a"')}
        self.assertEqual(expand_macros('F(1)', macros), '1 ab _a "a"')

    def test_a_function_like_macro_is_only_expanded_when_invoked(self):
        macros = {'F': FunctionLikeMacro(['a'], 'a')}
        self.assertEqual(expand_macros('F + 1', macros), 'F + 1')
        self.assertEqual(expand_macros('&F', macros), '&F')
        self.assertEqual(expand_macros('F\n(1)', macros), '1')

    def test_nested_invocations(self):
        macros = {
            'F': FunctionLikeMacro(['a'], 'G(a) + 1'),
            'G': FunctionLikeMacro(['a'], '(a)'),
        }
        self.assertEqual(expand_macros('F(F(2))', macros), '((2) + 1) + 1')

    def test_a_wrong_number_of_arguments_is_rejected(self):
        macros = {'F': FunctionLikeMacro(['a', 'b'], 'a')}
        for code in ('F(1)', 'F(1, 2, 3)', 'F()'):
            with self.subTest(code=code):
                with self.assertRaises(Exception):
                    expand_macros(code, macros)

    def test_an_unterminated_invocation_is_rejected(self):
        macros = {'F': FunctionLikeMacro(['a'], 'a')}
        with self.assertRaises(Exception):
            expand_macros('F(1', macros)

    def test_an_expansion_which_does_not_terminate_is_rejected(self):
        for macros in ({'A': 'A'},
                       {'A': 'B', 'B': 'A'},
                       {'F': FunctionLikeMacro(['a'], 'F(a)')}):
            with self.subTest(macros=macros):
                with self.assertRaises(Exception):
                    expand_macros('F(1) A', macros)

    def test_an_ambiguous_or_unsupported_macro_is_rejected(self):
        for state in (MacroState.AMBIGUOUS, MacroState.UNSUPPORTED):
            with self.subTest(state=state):
                with self.assertRaises(Exception):
                    expand_macros('A', {'A': state})

    def test_macros_from_a_preprocessed_source(self):
        source = ('#define NAME "Sym"\n'
                  '#define HOOK(x) {{x}, &original, hook}\n'
                  'HOOK(NAME)\n')
        result = self.preprocess(source)
        self.assertEqual(expand_macros('HOOK(NAME)', result.macros),
                         '{{"Sym"}, &original, hook}')


class TestConcatAdjacentLiterals(PreprocessorTestCase):
    def test_adjacent_literals_are_merged(self):
        cases = [
            ('"a" "b"', 'L"ab"'),
            ('"a""b""c"', 'L"abc"'),
            ('L"a" "b"', 'L"ab"'),
            ('"a"\n    "b"', 'L"ab"'),
            ('R"(a)" "b"', 'L"ab"'),
            ('{"a", "b"}', '{L"a", L"b"}'),
            ('f("a" "b", "c")', 'f(L"ab", L"c")'),
            ('"a"', 'L"a"'),
            ('no literals', 'no literals'),
        ]

        for code, expected in cases:
            with self.subTest(code=code):
                self.assertEqual(concat_adjacent_literals(code), expected)

    def test_a_character_literal_is_left_alone(self):
        self.assertEqual(concat_adjacent_literals('{\'x\', "a"}'),
                         '{\'x\', L"a"}')
        self.assertEqual(concat_adjacent_literals('{\'"\', "a"}'),
                         '{\'"\', L"a"}')

    def test_a_character_literal_does_not_join_two_strings(self):
        self.assertEqual(concat_adjacent_literals('"a" \'x\' "b"'),
                         'L"a" \'x\' L"b"')

    def test_a_value_which_cannot_be_rewritten_is_rejected(self):
        for code in (r'"a\\b"', r'"a\"b"', r'"a\n"', 'R"(a"b)"', 'R"(a\nb)"'):
            with self.subTest(code=code):
                with self.assertRaises(Exception):
                    concat_adjacent_literals(code)


class TestCheckLiteralsAreFullyExpanded(PreprocessorTestCase):
    def test_a_literal_in_ordinary_company_is_accepted(self):
        for code in ('{L"a", L"b"}', 'f(L"a")', 'x = L"a";', "{'x', L\"a\"}"):
            with self.subTest(code=code):
                check_literals_are_fully_expanded(code)

    def test_a_literal_next_to_an_identifier_is_rejected(self):
        # The last one is two literals which weren't merged, so the prefix of the
        # second one reads as an identifier. Merging them comes first.
        for code in ('FOO L"a"', 'L"a" FOO', '{L"a" SUFFIX, L"b"}',
                     'FOO\nL"a"', 'L"a" L"b"'):
            with self.subTest(code=code):
                with self.assertRaises(Exception):
                    check_literals_are_fully_expanded(code)


class TestModLikeSources(PreprocessorTestCase):
    """The whole job, on sources shaped like the mods this is used for."""

    X86 = ({'_M_IX86': '300'}, {'_WIN64', '_M_X64', '_M_ARM64'})
    AMD64 = ({'_WIN64': '1', '_M_X64': '100'}, {'_M_IX86', '_M_ARM64'})
    ARM64 = ({'_WIN64': '1', '_M_ARM64': '1'}, {'_M_IX86', '_M_X64'})

    SOURCE = ('const WindhawkUtils::SYMBOL_HOOK hooks[] = {\n'
              '#ifdef _WIN64\n'
              '    {{L"Sym64"}, &original, hook},\n'
              '#else\n'
              '    {{L"Sym32"}, &original, hook},\n'
              '#endif\n'
              '#if defined(_M_ARM64)\n'
              '    {{L"SymArm"}, &original, hook},\n'
              '#endif\n'
              '};\n')

    def symbols(self, source: str, arch):
        defined, undefined = arch
        result = self.preprocess(source, defined, undefined)
        self.assertEqual(result.unresolved_lines, {})
        return get_string_literals(result.source)

    def test_symbols_per_architecture(self):
        self.assertEqual(self.symbols(self.SOURCE, self.X86), ['Sym32'])
        self.assertEqual(self.symbols(self.SOURCE, self.AMD64), ['Sym64'])
        self.assertEqual(self.symbols(self.SOURCE, self.ARM64),
                         ['Sym64', 'SymArm'])

    def symbol_block(self, source: str):
        """The symbol block of a preprocessed source, the way the caller reads it."""
        match = re.search(r'SYMBOL_HOOK[\s\S]*?\};', source)
        self.assertIsNotNone(match)
        return match.group(0)

    def test_symbols_built_from_macros(self):
        source = ('#define SYMBOL_A L"A"\n'
                  '#define HOOK(symbol) {{symbol}, &original, hook}\n'
                  'const WindhawkUtils::SYMBOL_HOOK hooks[] = {\n'
                  '    HOOK(SYMBOL_A),\n'
                  '#ifdef _M_IX86\n'
                  '    HOOK(L"B" L"32"),\n'
                  '#endif\n'
                  '};\n')
        result = self.preprocess(source, *self.X86)
        block = expand_macros(self.symbol_block(result.source), result.macros)
        block = concat_adjacent_literals(block)
        check_literals_are_fully_expanded(block)
        self.assertEqual(get_string_literals(block), ['A', 'B32'])

    def test_a_symbol_built_from_a_macro_of_another_architecture(self):
        source = ('#ifdef _M_IX86\n'
                  '#define SYM L"A32"\n'
                  '#else\n'
                  '#define SYM L"A64"\n'
                  '#endif\n'
                  'const WindhawkUtils::SYMBOL_HOOK hooks[] = {\n'
                  '    {{SYM}, &original, hook},\n'
                  '};\n')
        for arch, expected in ((self.X86, ['A32']), (self.AMD64, ['A64'])):
            with self.subTest(expected=expected):
                result = self.preprocess(source, *arch)
                block = expand_macros(self.symbol_block(result.source),
                                      result.macros)
                self.assertEqual(get_string_literals(block), expected)

    def test_a_block_under_an_unknown_condition_is_reported(self):
        source = ('#if MY_HEADER_MACRO\n'
                  'const WindhawkUtils::SYMBOL_HOOK hooks[] = {\n'
                  '    {{L"Sym"}, &original, hook},\n'
                  '};\n'
                  '#endif\n')
        result = self.preprocess(source, *self.AMD64)
        block_lines = range(1, 4)
        self.assertTrue(all(x in result.unresolved_lines for x in block_lines))
        self.assertEqual(result.source, source)

    def test_a_symbol_which_depends_on_an_unknown_condition_is_reported(self):
        source = ('const WindhawkUtils::SYMBOL_HOOK hooks[] = {\n'
                  '#if MY_HEADER_MACRO\n'
                  '    {{L"Sym"}, &original, hook},\n'
                  '#endif\n'
                  '};\n')
        result = self.preprocess(source, *self.AMD64)
        self.assertIn(2, result.unresolved_lines)

    def test_a_symbol_built_from_an_ambiguous_macro_is_rejected(self):
        source = ('#if MY_HEADER_MACRO\n'
                  '#define SYM L"A"\n'
                  '#else\n'
                  '#define SYM L"B"\n'
                  '#endif\n'
                  'const WindhawkUtils::SYMBOL_HOOK hooks[] = {\n'
                  '    {{SYM}, &original, hook},\n'
                  '};\n')
        result = self.preprocess(source, *self.AMD64)
        with self.assertRaises(Exception):
            expand_macros('{{SYM}, &original, hook}', result.macros)

    def test_a_commented_out_symbol_is_not_a_symbol(self):
        source = ('const WindhawkUtils::SYMBOL_HOOK hooks[] = {\n'
                  '    // {{L"Old"}, &original, hook},\n'
                  '    {{L"New"}, &original, hook},\n'
                  '};\n')
        result = self.preprocess(source, *self.AMD64)
        self.assertEqual(get_string_literals(blank_comments(result.source)),
                         ['New'])

    def test_the_architecture_macros_of_other_architectures_are_undefined(self):
        source = ('#if defined(_M_IX86)\nX86\n'
                  '#elif defined(_M_X64)\nAMD64\n'
                  '#elif defined(_M_ARM64)\nARM64\n'
                  '#else\n#error unknown\n#endif\n')
        for arch, expected in ((self.X86, 'X86'), (self.AMD64, 'AMD64'),
                               (self.ARM64, 'ARM64')):
            with self.subTest(expected=expected):
                self.assertEqual(self.kept_lines(source, *arch), [expected])

    def test_an_architecture_macro_which_is_not_declared_is_unknown(self):
        # The gcc spelling isn't among the macros the caller declares, so a mod
        # which branches on it is reported instead of being resolved as x86.
        source = ('#ifdef __x86_64__\n'
                  '{{L"Sym64"}, &original, hook},\n'
                  '#endif\n')
        result = self.preprocess(source, *self.AMD64)
        self.assertEqual(sorted(result.unresolved_lines), [0, 1, 2])


if __name__ == '__main__':
    unittest.main()
