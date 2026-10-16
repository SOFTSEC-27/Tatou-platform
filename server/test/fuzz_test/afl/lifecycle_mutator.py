"""Structure-preserving AFL++ mutator for a bounded valid lifecycle campaign.

This keeps every input inside the scenario grammar. It does not generate
malformed API bodies or damaged PDFs; those need a separate campaign.
"""

import json
import random
import string

DEFAULT = {
    "secret": "Group_27", "key": "0123456789abcdef",
    "position": "center", "pages": 1, "size": "a4",
    "rotation": 0, "intended_for": "Group_01",
    "filename": "document.pdf", "text": "Tatou AFL lifecycle",
}
POSITIONS = ("center", "header", "footer")
SIZES = ("a4", "landscape", "small")
ALPHABET = string.ascii_letters + string.digits + " _-:./测试"
_rng = random.Random()
_last_field = "initial"


def valid_case(case):
    if not isinstance(case, dict) or set(case) != set(DEFAULT):
        return False
    for field, limit in (("secret", 96), ("key", 32),
                         ("intended_for", 64), ("text", 96)):
        value = case[field]
        if not isinstance(value, str) or not 1 <= len(value) <= limit:
            return False
        if any(c not in ALPHABET for c in value):
            return False
    return (
        case["position"] in POSITIONS
        and type(case["pages"]) is int and 1 <= case["pages"] <= 3
        and case["size"] in SIZES
        and type(case["rotation"]) is int
        and case["rotation"] in (0, 90, 180, 270)
        and case["filename"] in ("document.pdf", "report.pdf", "REPORT.PDF")
    )


def encode(case):
    return json.dumps(case, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


def init(seed):
    _rng.seed(seed)


def splice_optout():
    pass


def fuzz(buf, add_buf, max_size):
    global _last_field
    try:
        case = json.loads(bytes(buf))
    except (ValueError, UnicodeError, RecursionError):
        case = dict(DEFAULT)
    if not valid_case(case):
        case = dict(DEFAULT)

    _last_field = _rng.choice(tuple(DEFAULT))
    if _last_field in ("secret", "key", "intended_for", "text"):
        limit = {"secret": 96, "key": 32, "intended_for": 64, "text": 96}[_last_field]
        if _rng.randrange(2):
            old = case[_last_field]
            i = _rng.randrange(len(old))
            case[_last_field] = old[:i] + _rng.choice(ALPHABET) + old[i + 1:]
        else:
            n = _rng.choice((1, 2, 8, 16, 32, limit))
            case[_last_field] = "".join(_rng.choice(ALPHABET) for _ in range(n))
    elif _last_field == "position":
        case[_last_field] = _rng.choice(POSITIONS)
    elif _last_field == "pages":
        case[_last_field] = _rng.randint(1, 3)
    elif _last_field == "size":
        case[_last_field] = _rng.choice(SIZES)
    elif _last_field == "rotation":
        case[_last_field] = _rng.choice((0, 90, 180, 270))
    elif _last_field == "filename":
        case[_last_field] = _rng.choice(("document.pdf", "report.pdf", "REPORT.PDF"))
    raw = encode(case)
    return bytearray(raw) if len(raw) <= max_size else bytearray()


def describe(max_description_length):
    return ("lifecycle_" + _last_field)[:max_description_length]
