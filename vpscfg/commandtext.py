"""Literal command text handling.

Threats: preserves quoted data and statement boundaries in approved commands;
exposes shell-equivalent literal words for deny scans. This is not a shell
interpreter and cannot prove the effects of arbitrary scripts or expansions.
"""
import shlex
import re


def normalize(text):
    """Collapse horizontal whitespace only outside quotes; never rewrite data."""
    result, quote, escaped, space = [], None, False, False
    for char in (text or '').strip():
        if escaped:
            result.append(char)
            escaped = False
            continue
        if char == '\\' and quote != "'":
            if space and result:
                result.append(' ')
            space = False
            result.append(char)
            escaped = True
        elif quote:
            result.append(char)
            if char == quote:
                quote = None
        elif char in "\"'":
            if space and result:
                result.append(' ')
            space = False
            quote = char
            result.append(char)
        elif char in ' \t\r':
            space = True
        else:
            if space and result and char != '\n':
                result.append(' ')
            space = False
            result.append(char)
    return ''.join(result)


def literal_words(text):
    lexer = shlex.shlex(text.replace('\\\n', ''), posix=True, punctuation_chars=';&|<>')
    lexer.whitespace_split = True
    lexer.commenters = ''
    return list(lexer)


def has_expansion(text):
    """An automatic read must not acquire new options via glob/brace expansion."""
    quote, i = None, 0
    while i < len(text):
        char = text[i]
        if char == '\\' and quote != "'":
            i += 2
            continue
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == '{':
            # Bare Docker Go-template field selectors do not expand in sh.
            field = re.match(r'\{\{\.[A-Za-z0-9_.]+\}\}', text[i:])
            if field:
                i += len(field[0])
                continue
            return True
        elif char in '*?[~()':
            return True
        i += 1
    return False
