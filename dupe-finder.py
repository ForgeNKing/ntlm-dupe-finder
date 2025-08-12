#!/usr/bin/env python3
import argparse, re, sys
from collections import defaultdict

HEX32 = re.compile(r'^([0-9a-fA-F]{32})')

def parse_pwdump(fp):
    by_hash = defaultdict(list)
    for line in fp:
        line = line.strip()
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
    cracked = {}
    for line in fp:
        line = line.strip()
        if not line or line.startswith('#') or ':' not in line:
            continue
        h, pw = line.split(':', 1)
        m = HEX32.match(h.strip())
        if not m:
            continue
        cracked[m.group(1).lower()] = pw.strip()
    return cracked

def main():
    ap = argparse.ArgumentParser(description="Найти пользователей с одинаковым NTLM и показать пароль из 2.txt.")
    ap.add_argument('pwdump', help="Путь к 1.txt (формат pwdump: user:rid:LM:NTLM:::)")
    ap.add_argument('cracked', help="Путь к 2.txt (строки вида NTLM:пароль)")
    args = ap.parse_args()

    with open(args.pwdump, 'r', encoding='utf-8', errors='ignore') as f1:
        by_hash = parse_pwdump(f1)
    with open(args.cracked, 'r', encoding='utf-8', errors='ignore') as f2:
        cracked = parse_cracked(f2)

    printed_any = False
    for h, users in sorted(by_hash.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        if len(users) >= 2 and h in cracked:
            for u in users:
                print(u)
            print(f"имеют пароль и NTLM - {h}:{cracked[h]}\n")
            printed_any = True

    if not printed_any:
        print("Совпадений среди одинаковых NTLM с известными паролями не найдено.", file=sys.stderr)

if __name__ == "__main__":
    main()
