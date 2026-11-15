#!/usr/bin/env python3
"""Actual lexical regressions; these do not compile or qualify any runtime."""
import unittest

from rust_source_tokens import rust_tokens, rust_structure_tokens


class RustSourceTokenTests(unittest.TestCase):
    def test_comments_and_intertoken_whitespace_are_preserved_equivalently(self):
        for tokenize in (rust_tokens,rust_structure_tokens):
            self.assertEqual(tokenize('a && b'),tokenize('a /* outer /* inner */ */ && // line\n b'))
            self.assertEqual(tokenize("fn f<'a>(s: &'a str) {}"),tokenize("fn f < 'a > (s : & 'a str) { }"))

    def test_every_joint_operator_refuses_internal_whitespace_or_comment(self):
        for operator in ('&&','||','==','!=','<=','>=','<<','>>','<<=','>>=',
                         '+=','-=','*=','/=','%=','&=','|=','^=','::','->','=>','..','..=','...'):
            for split in (operator[0]+' '+operator[1:],operator[0]+'/**/'+operator[1:]):
                for tokenize in (rust_tokens,rust_structure_tokens):
                    with self.subTest(operator=operator,split=split,mode=tokenize.__name__):
                        self.assertNotEqual(tokenize('a '+operator+' b'),tokenize('a '+split+' b'))

    def test_literal_prefixes_cannot_be_split_or_substituted(self):
        pairs = [('b"scope"','b "scope"'),('c"scope"','c "scope"'),
                 ('br#"scope"#','br #"scope"#'),('cr#"scope"#','cr #"scope"#'),
                 ('r#"scope"#','r #"scope"#'),("b'a'","b 'a'"),
                 ('b"scope"','"scope"'),('br#"scope"#','r#"scope"#')]
        for before,after in pairs:
            for tokenize in (rust_tokens,rust_structure_tokens):
                with self.subTest(before=before,after=after,mode=tokenize.__name__):
                    self.assertNotEqual(tokenize(before),tokenize(after))

    def test_exact_literal_bytes_survive_comments_and_structural_mode_is_explicit(self):
        original = 'hash(b"scope", &[b"/* data, not comment */"])'
        changed = original.replace('scope','other')
        self.assertNotEqual(rust_tokens(original),rust_tokens(changed))
        self.assertEqual(rust_structure_tokens(original),rust_structure_tokens(changed))
        self.assertIn('b"/* data, not comment */"',rust_tokens(original))
        self.assertNotEqual(rust_tokens('r#"one"#'),rust_tokens('r#"two"#'))

    def test_lifetimes_numbers_and_unterminated_input_do_not_merge(self):
        self.assertNotEqual(rust_tokens('1.25'),rust_tokens('1 . 25'))
        self.assertEqual(rust_tokens("'a"),("'a",))
        for text in ('/* unfinished','"unfinished',r'r##"unfinished"#',"' a"):
            for tokenize in (rust_tokens,rust_structure_tokens):
                with self.subTest(text=text,mode=tokenize.__name__),self.assertRaises(ValueError):
                    tokenize(text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
