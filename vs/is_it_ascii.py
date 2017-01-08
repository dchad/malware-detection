# Determine if a string is all ascii characters.

def is_ascii(s):
    return all(ord(c) < 128 for c in s)


def is_printable_ascii(s):
    return all(ord(c) > 31 and ord(c) < 127 for c in s)