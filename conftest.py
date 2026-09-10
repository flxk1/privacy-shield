import sys
from pathlib import Path

# Minimal harness: put the extracted `src/` package tree on the path.
# (Deliberately does NOT pull in the Brain app's fastapi/multipart bootstrap —
# this repo is the privacy-shield subset only.)
SRC = Path(__file__).resolve().parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
