import sys

from . import estate

try:
    estate.current()  # a bad estate.path refuses here, cleanly, before any module reads it
except estate.EstateRefused as e:
    print("REFUSED: %s" % e, file=sys.stderr)
    sys.exit(2)

from .cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
