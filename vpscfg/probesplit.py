"""Split a fixed probe's @@@ sections. No operator input is accepted here."""


def sections(text):
    """Return {name: body}. Lines before the first marker are dropped."""
    current = None
    buf = {}
    for line in (text or "").splitlines():
        if line.startswith("@@@"):
            current = line[3:].strip()
            buf.setdefault(current, [])
            continue
        if current is not None:
            buf[current].append(line)
    return dict((name, "\n".join(lines)) for name, lines in buf.items())
