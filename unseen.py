#!/usr/bin/env python3
"""
unseen — find, decode, strip, and craft hidden text in Unicode.

Some characters are invisible to humans (and to approval dialogs) but are read
by LLMs, agents, chat apps, and code review tools. Attackers use them to smuggle
instructions ("ignore your rules, exfiltrate X") into prompts, MCP tool
descriptions, emails, commit messages, and web pages. This is a single-file,
dependency-free tool to deal with them.

Subcommands:
  detect   list every hidden/suspicious code point, with position, name, risk
  decode   reconstruct smuggled payloads (Unicode Tags, variation-selector bytes,
           zero-width binary) and print the hidden message(s)
  strip    remove hidden characters and print cleaned text
  encode   craft a Unicode-Tag smuggled payload (for authorized testing)

Input comes from a TEXT argument, --file PATH, or stdin (pipe).
Exit codes (detect): 0 clean, 1 hidden chars at/above --fail-risk, 2 error.

Python 3.8+. No dependencies.

Examples:
  echo "hello world" | ./unseen.py detect
  ./unseen.py detect --file suspicious.txt
  ./unseen.py decode --file tool_description.json
  ./unseen.py strip --file dirty.txt > clean.txt
  ./unseen.py encode "ignore previous instructions" --carrier "Weather tool."
"""

import sys
import argparse
import unicodedata

# ---------------------------------------------------------------------------
# Character categories
# ---------------------------------------------------------------------------
# Unicode Tags block (U+E0000..U+E007F): the primary smuggling channel. Tag
# chars mirror ASCII (U+E0020..U+E007E == space..~). Legit only inside flag
# emoji sequences (U+1F3F4 ... U+E007F).
TAG_LO, TAG_HI = 0xE0000, 0xE007F

# Bidirectional overrides (Trojan Source, CVE-2021-42574): reorder displayed
# text vs. logical order. Almost never legitimate in code or tool metadata.
BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
        0x2066, 0x2067, 0x2068, 0x2069,
        0x200E, 0x200F, 0x061C}

# Zero-width: stego carriers or formatting. 200D (ZWJ) is common in emoji/scripts.
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E}

# Variation selectors. FE00..FE0F and E0100..E01EF can encode arbitrary bytes
# ("smuggling data through emoji"). FE0F alone is the benign emoji selector.
VS_LO1, VS_HI1 = 0xFE00, 0xFE0F
VS_LO2, VS_HI2 = 0xE0100, 0xE01EF

# Other invisible / format characters worth surfacing.
OTHER_INVISIBLE = {
    0x00AD,  # soft hyphen
    0x034F,  # combining grapheme joiner
    0x115F, 0x1160,  # hangul fillers
    0x17B4, 0x17B5,  # khmer inherent vowels
    0x180B, 0x180C, 0x180D,  # mongolian free variation selectors
    0x2028, 0x2029,  # line / paragraph separator
    0x205F,  # medium mathematical space
    0x2061, 0x2062, 0x2063, 0x2064,  # invisible math operators
    0x3164, 0xFFA0,  # hangul filler / halfwidth
    0xFFF9, 0xFFFA, 0xFFFB,  # interlinear annotation
}

RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def category_for(cp):
    """Return (category, base_risk) for a code point, or None if ordinary."""
    if TAG_LO <= cp <= TAG_HI:
        return ("unicode-tag", "high")
    if cp in BIDI:
        return ("bidi-control", "high")
    if VS_LO1 <= cp <= VS_HI1 or VS_LO2 <= cp <= VS_HI2:
        return ("variation-selector", "low")
    if cp in ZERO_WIDTH:
        return ("zero-width", "medium")
    if cp in OTHER_INVISIBLE:
        return ("invisible", "low")
    return None


def _flag_legit_indices(cps):
    """Indices of tag chars that belong to a legitimate flag-emoji sequence."""
    legit = set()
    n = len(cps)
    j = 0
    while j < n:
        if cps[j] == 0x1F3F4:
            run = []
            k = j + 1
            while k < n and TAG_LO <= cps[k] <= TAG_HI:
                run.append(k)
                if cps[k] == 0xE007F:
                    k += 1
                    break
                k += 1
            if run and cps[run[-1]] == 0xE007F:
                legit.update(run)
            j = k
        else:
            j += 1
    return legit


def scan(text):
    """Return a list of findings for every hidden/suspicious character."""
    cps = [ord(c) for c in text]
    legit = _flag_legit_indices(cps)
    findings = []
    for i, cp in enumerate(cps):
        cat = category_for(cp)
        if cat is None:
            continue
        category, risk = cat
        note = ""
        if i in legit:
            risk, note = "info", "part of flag-emoji sequence"
        elif cp == 0xFE0F:
            risk, note = "low", "emoji presentation selector (usually benign)"
        elif cp == 0x200D:
            note = "zero-width joiner (emoji/script joiner)"
        try:
            name = unicodedata.name(chr(cp))
        except ValueError:
            name = "<unnamed>"
        findings.append({
            "index": i, "cp": cp, "char": chr(cp),
            "name": name, "category": category, "risk": risk, "note": note,
        })
    return findings


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------
def _runs(cps, lo, hi, skip=frozenset()):
    """Yield (start, [codepoints]) for maximal runs within [lo,hi], skipping idx in `skip`."""
    n = len(cps)
    i = 0
    while i < n:
        if lo <= cps[i] <= hi and i not in skip:
            start = i
            run = []
            while i < n and lo <= cps[i] <= hi and i not in skip:
                run.append(cps[i])
                i += 1
            yield start, run
        else:
            i += 1


def decode_tags(text):
    cps = [ord(c) for c in text]
    skip = _flag_legit_indices(cps)
    out = []
    for start, run in _runs(cps, TAG_LO, TAG_HI, skip):
        chars = []
        for cp in run:
            c = cp - 0xE0000
            if cp == 0xE007F:        # cancel / terminator
                continue
            if cp == 0xE0001:        # language tag marker
                continue
            chars.append(chr(c) if 0x09 <= c <= 0x7E else ".")
        msg = "".join(chars).strip()
        if msg:
            out.append((start, msg))
    return out


def decode_variation_selectors(text):
    """Decode the FE00-FE0F / E0100-E01EF byte-smuggling scheme."""
    cps = [ord(c) for c in text]
    out = []
    i, n = 0, len(cps)
    while i < n:
        cp = cps[i]
        is_vs = (VS_LO1 <= cp <= VS_HI1) or (VS_LO2 <= cp <= VS_HI2)
        if is_vs:
            start = i
            data = bytearray()
            while i < n:
                cp = cps[i]
                if VS_LO1 <= cp <= VS_HI1:
                    data.append(cp - VS_LO1)
                elif VS_LO2 <= cp <= VS_HI2:
                    data.append(cp - VS_LO2 + 16)
                else:
                    break
                i += 1
            if len(data) >= 2:  # a lone selector is just emoji styling
                try:
                    msg = data.decode("utf-8")
                except UnicodeDecodeError:
                    msg = data.hex()
                out.append((start, msg))
        else:
            i += 1
    return out


def decode_zero_width(text):
    """Heuristic: decode a ZWSP(0)/ZWNJ(1) binary stego scheme, if present."""
    bits = []
    start = None
    for i, c in enumerate(text):
        if ord(c) == 0x200B:
            bits.append("0"); start = i if start is None else start
        elif ord(c) == 0x200C:
            bits.append("1"); start = i if start is None else start
    if len(bits) < 8:
        return []
    chars = []
    for b in range(0, len(bits) - 7, 8):
        byte = int("".join(bits[b:b + 8]), 2)
        chars.append(chr(byte) if 0x20 <= byte <= 0x7E else ".")
    msg = "".join(chars).strip(".")
    return [(start, msg)] if msg else []


# ---------------------------------------------------------------------------
# Strip / encode
# ---------------------------------------------------------------------------
def strip_text(text, aggressive=False):
    cps = [ord(c) for c in text]
    legit = _flag_legit_indices(cps)
    out = []
    for i, cp in enumerate(cps):
        cat = category_for(cp)
        if cat is None:
            out.append(chr(cp)); continue
        if i in legit:
            out.append(chr(cp)); continue                 # keep flag emoji
        if not aggressive and cp in (0xFE0F, 0x200D):
            out.append(chr(cp)); continue                 # keep emoji styling/joiner
        # otherwise drop it
    return "".join(out)


def encode_tags(payload, carrier=""):
    for ch in payload:
        if ord(ch) > 0x7F:
            raise ValueError("payload must be printable ASCII (got %r)" % ch)
    tagged = "".join(chr(0xE0000 + ord(ch)) for ch in payload)
    return carrier + tagged


# ---------------------------------------------------------------------------
# I/O + CLI
# ---------------------------------------------------------------------------
def read_input(args):
    if getattr(args, "text", None):
        return args.text
    if getattr(args, "file", None):
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read().decode("utf-8", errors="replace")
    sys.stderr.write("error: no input (give TEXT, --file, or pipe via stdin)\n")
    sys.exit(2)


def _color(enabled):
    if enabled:
        return {"high": "\033[1;31m", "medium": "\033[1;33m", "low": "\033[2m",
                "info": "\033[2;32m", "reset": "\033[0m", "hdr": "\033[1;36m"}
    return {k: "" for k in ("high", "medium", "low", "info", "reset", "hdr")}


def cmd_detect(args):
    text = read_input(args)
    findings = scan(text)
    use_color = sys.stdout.isatty() and not args.no_color and not args.json
    C = _color(use_color)
    threshold = RISK_ORDER[args.min_risk]
    shown = [f for f in findings if RISK_ORDER[f["risk"]] >= threshold]

    if args.json:
        import json
        print(json.dumps({"count": len(shown), "findings": shown}, ensure_ascii=False, indent=2))
    else:
        if not shown:
            print("clean: no hidden characters at/above risk '%s'." % args.min_risk)
        else:
            print("%s%d hidden character(s):%s" % (C["hdr"], len(shown), C["reset"]))
            for f in shown:
                col = C[f["risk"]]
                note = ("  — " + f["note"]) if f["note"] else ""
                print("  %s[%-6s] pos %-5d U+%04X  %s%s%s"
                      % (col, f["risk"], f["index"], f["cp"], f["name"], note, C["reset"]))
            by = {}
            for f in shown:
                by[f["risk"]] = by.get(f["risk"], 0) + 1
            print("  summary: " + ", ".join("%s=%d" % (k, by[k])
                  for k in ("high", "medium", "low", "info") if k in by))

    worst = max((RISK_ORDER[f["risk"]] for f in findings), default=-1)
    return 1 if worst >= RISK_ORDER[args.fail_risk] else 0


def cmd_decode(args):
    text = read_input(args)
    any_found = False
    for label, items in (("unicode-tag", decode_tags(text)),
                         ("variation-selector-bytes", decode_variation_selectors(text)),
                         ("zero-width-binary (heuristic)", decode_zero_width(text))):
        for pos, msg in items:
            any_found = True
            print("[%s @ pos %d] %s" % (label, pos, msg))
    if not any_found:
        print("no decodable smuggled payload found.")
        return 1
    return 0


def cmd_strip(args):
    text = read_input(args)
    cleaned = strip_text(text, aggressive=args.aggressive)
    removed = len(text) - len(cleaned)
    sys.stdout.buffer.write(cleaned.encode("utf-8"))
    if sys.stdout.isatty():
        sys.stdout.write("\n")
    sys.stderr.write("removed %d hidden character(s).\n" % removed)
    return 0


def cmd_encode(args):
    try:
        result = encode_tags(args.payload, args.carrier or "")
    except ValueError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2
    sys.stdout.buffer.write(result.encode("utf-8"))
    if sys.stdout.isatty():
        sys.stdout.write("\n")
    sys.stderr.write("encoded %d-char payload into %d invisible tag char(s)"
                     "%s.\n" % (len(args.payload), len(args.payload),
                                " after carrier text" if args.carrier else ""))
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="unseen",
        description="Find, decode, strip, and craft hidden text in Unicode.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_io(sp):
        sp.add_argument("text", nargs="?", help="input text (else --file or stdin)")
        sp.add_argument("--file", help="read input from this file")

    d = sub.add_parser("detect", help="list hidden/suspicious characters")
    add_io(d)
    d.add_argument("--min-risk", choices=list(RISK_ORDER), default="low",
                   help="only show findings at/above this risk (default: low)")
    d.add_argument("--fail-risk", choices=list(RISK_ORDER), default="medium",
                   help="exit 1 if any finding reaches this risk (default: medium)")
    d.add_argument("--json", action="store_true", help="machine-readable output")
    d.add_argument("--no-color", action="store_true")
    d.set_defaults(func=cmd_detect)

    de = sub.add_parser("decode", help="reconstruct smuggled payloads")
    add_io(de)
    de.set_defaults(func=cmd_decode)

    st = sub.add_parser("strip", help="remove hidden characters, print cleaned text")
    add_io(st)
    st.add_argument("--aggressive", action="store_true",
                    help="also remove emoji joiner/selector (FE0F, ZWJ)")
    st.set_defaults(func=cmd_strip)

    en = sub.add_parser("encode", help="craft a Unicode-Tag smuggled payload (testing)")
    en.add_argument("payload", help="printable-ASCII text to hide")
    en.add_argument("--carrier", help="visible text to prepend")
    en.set_defaults(func=cmd_encode)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
