#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import sys
import io
from collections import defaultdict

HEX32 = re.compile(r'^([0-9a-fA-F]{32})')
PWDUMP_LINE_RE = re.compile(r'^(.*?:[0-9]{1,}:.*?:.*?:::)\s*$', re.MULTILINE)


def extract_pwdump_lines_from_secretsdump(fp):
    """
    Extracts pwdump-formatted lines from raw secretsdump output
    using the PWDUMP_LINE_RE regex.
    """
    text = fp.read()
    return [m.group(1) for m in PWDUMP_LINE_RE.finditer(text)]


def parse_pwdump(fp):
    """
    Reads pwdump lines of the form:
      user:RID:LM:NTLM:::
    and groups users by NTLM hash.
    """
    by_hash = defaultdict(list)
    for raw in fp:
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(':')
        if len(parts) < 4:
            continue
        user = parts[0].strip()
        ntlm_raw = parts[3].strip()
        m = HEX32.match(ntlm_raw)
        if not m:
            continue
        h = m.group(1).lower()
        if user not in by_hash[h]:
            by_hash[h].append(user)
    return by_hash


def parse_cracked(fp):
    """
    Reads a dictionary of the form:
      NTLM:password
    (e.g., output of `hashcat --show`)
    """
    cracked = {}
    for raw in fp:
        line = raw.strip()
        if not line or line.startswith('#') or ':' not in line:
            continue
        h, pw = line.split(':', 1)
        m = HEX32.match(h.strip())
        if not m:
            continue
        cracked[m.group(1).lower()] = pw.strip()
    return cracked


def main():
    ap = argparse.ArgumentParser(
        prog="dupe-finder.py",
        description=(
            "Find users by NTLM hashes in secretsdump/pwdump output and attach known passwords "
            "from a dictionary (hashcat format: NTLM:password).\n\n"
            "The tool accepts either raw secretsdump.py output (it auto-extracts lines like "
            "user:rid:LM:NTLM::: via regex) or ready-to-use pwdump lines."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Input formats:\n"
            "  • SECRETS_DUMP: lines like user:RID:LM:NTLM::: (secretsdump.py / pwdump)\n"
            "  • CRACKED:      lines like NTLM:password (hashcat --show)\n\n"
            "Output criteria:\n"
            "  • Prints only groups for which a password is known (NTLM present in CRACKED).\n"
            "  • Groups are ordered by descending size (more matches first).\n"
            "  • Single-user groups are printed if their NTLM is cracked.\n\n"
            "Quick start:\n"
            "  $ python3 dupe-finder.py DC_dump.txt passwords_from_hashcat.txt\n"
            "  $ python3 dupe-finder.py DC_dump.txt passwords_from_hashcat.txt -o result.txt\n"
        ),
    )

    ap.add_argument(
        "secretsdump",
        metavar="SECRETS_DUMP",
        help="Path to the DC dump (secretsdump.py) or pwdump lines. Example: DC_dump.txt",
    )
    ap.add_argument(
        "cracked",
        metavar="CRACKED",
        help="Path to a dictionary of NTLM:password (hashcat --show). Example: passwords_from_hashcat.txt",
    )
    ap.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="File to save the result. If omitted, prints to stdout.",
    )

    args = ap.parse_args()

    with open(args.secretsdump, 'r', encoding='utf-8', errors='ignore') as fsec:
        extracted_lines = extract_pwdump_lines_from_secretsdump(fsec)

    if extracted_lines:
        pwdump_stream = io.StringIO("\n".join(extracted_lines))
    else:
        pwdump_stream = open(args.secretsdump, 'r', encoding='utf-8', errors='ignore')

    try:
        by_hash = parse_pwdump(pwdump_stream)
    finally:
        pwdump_stream.close()

    with open(args.cracked, 'r', encoding='utf-8', errors='ignore') as f2:
        cracked = parse_cracked(f2)

    out_fp = None
    if args.output:
        out_fp = open(args.output, 'w', encoding='utf-8', errors='ignore')
        writer = lambda s="": print(s, file=out_fp)
    else:
        writer = lambda s="": print(s)

    # Keep only groups for which the password is known
    items = [(h, users) for h, users in by_hash.items() if h in cracked]

    # Sort: larger groups first, then by NTLM
    items.sort(key=lambda kv: (-len(kv[1]), kv[0]))

    if not items:
        msg = "No matching entries with known passwords were found."
        if out_fp:
            writer(msg)
        else:
            print(msg, file=sys.stderr)
        if out_fp:
            out_fp.close()
        return

    for h, users in items:
        for u in users:
            writer(u)
        verb = "have" if len(users) != 1 else "has"
        writer(f"{verb} the password and NTLM - {h}:{cracked[h]}\n")

    if out_fp:
        out_fp.close()


if __name__ == "__main__":
    main()
