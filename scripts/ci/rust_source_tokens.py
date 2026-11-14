"""Small, literal-aware lexer for closed Rust source contracts.

This is not a Rust parser or a compilation verdict. It ignores only comments
and whitespace between tokens. Joint operators, literal prefixes and lifetimes
remain tokens, so whitespace inside them cannot silently change the contract.
Both functions are pure in the complete current input text; callers may cache
by that text within an invocation, never by a filename or a previous verdict.
"""
from __future__ import annotations

import re

_RAW = re.compile(r'(br|cr|r)(#*)"')
_STRING = re.compile(r'(b|c)?"')
_CHARACTER = re.compile(r"b?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'")
_LIFETIME = re.compile(r"'[A-Za-z_][A-Za-z_0-9]*")
_IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z_0-9]*')
_NUMBER = re.compile(r'(?:0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+|'
                     r'[0-9][0-9_]*(?:\.(?!\.)[0-9][0-9_]*)?'
                     r'(?:[eE][+-]?[0-9][0-9_]*)?)(?:[A-Za-z_][A-Za-z_0-9]*)?')
_JOINT = re.compile(r'<<=|>>=|\.\.\.|\.\.=|::|->|=>|&&|\|\||==|!=|<=|>=|'
                    r'\+=|-=|\*=|/=|%=|\^=|&=|\|=|<<|>>|\.\.')


def rust_tokens(text: str, *, structural: bool = False) -> tuple[str, ...]:
    """Return exact tokens, or literal-kind tokens for a structural comparison.

    Structural mode still distinguishes byte/C/raw/ordinary string literals,
    and preserves the complete nonliteral token stream. Callers choosing it
    must independently check every schema-affecting literal's exact bytes.
    """
    result = []
    i = 0
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        if text.startswith('//', i):
            end = text.find('\n', i)
            i = len(text) if end < 0 else end
            continue
        if text.startswith('/*', i):
            i += 2
            depth = 1
            while i < len(text) and depth:
                if text.startswith('/*', i):
                    depth += 1
                    i += 2
                elif text.startswith('*/', i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth:
                raise ValueError('Rust contract unterminated comment')
            continue
        start = i
        kind = None
        if match := _RAW.match(text, i):
            end = text.find('"' + match[2], match.end())
            if end < 0:
                raise ValueError('Rust contract unterminated raw literal')
            i = end + 1 + len(match[2])
            kind = 'raw-' + match[1]
        elif match := _STRING.match(text, i):
            i = match.end()
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == '\\' else 1
            if i >= len(text):
                raise ValueError('Rust contract unterminated literal')
            i += 1
            kind = 'string-' + (match[1] or '')
        elif match := _CHARACTER.match(text, i):
            i = match.end()
            kind = 'byte-character' if text[start] == 'b' else 'character'
        elif match := _LIFETIME.match(text, i):
            i = match.end()
        elif match := _IDENTIFIER.match(text, i):
            i = match.end()
        elif match := _NUMBER.match(text, i):
            i = match.end()
        elif match := _JOINT.match(text, i):
            i = match.end()
        elif text[i] == "'":
            raise ValueError('Rust contract malformed character or lifetime')
        else:
            i += 1
        result.append('<literal:' + kind + '>' if structural and kind else text[start:i])
    return tuple(result)


def rust_structure_tokens(text: str) -> tuple[str, ...]:
    """Structural tokens with literal kinds retained; no filesystem/cache access."""
    return rust_tokens(text, structural=True)
