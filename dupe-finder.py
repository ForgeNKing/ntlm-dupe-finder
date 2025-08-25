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
    Извлекает строки формата pwdump из «сырого» вывода secretsdump
    по заданной регулярке PWDUMP_LINE_RE.
    """
    text = fp.read()
    return [m.group(1) for m in PWDUMP_LINE_RE.finditer(text)]


def parse_pwdump(fp):
    """
    Читает pwdump-строки:
      user:RID:LM:NTLM:::
    и группирует пользователей по NTLM-хэшу.
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
    Читает словарь вида:
      NTLM:пароль
    (например, вывод `hashcat --show`)
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
            "Найдите пользователей по NTLM-хэшам в выводе secretsdump/pwdump и подставьте известный пароль "
            "из словаря (формата hashcat: NTLM:пароль).\n\n"
            "Инструмент принимает либо «сырой» вывод secretsdump.py (автоматически извлекает строки вида "
            "user:rid:LM:NTLM::: по регулярке), либо уже готовые pwdump-строки."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Форматы входных данных:\n"
            "  • SECRETS_DUMP: строки вида user:RID:LM:NTLM::: (secretsdump.py / pwdump)\n"
            "  • CRACKED:      строки вида NTLM:пароль (hashcat --show)\n\n"
            "Критерии вывода:\n"
            "  • Печатаются только те группы, для которых известен пароль (NTLM присутствует в CRACKED).\n"
            "  • Порядок групп — по убыванию размера (больше совпадений выше).\n"
            "  • Группы из одного пользователя выводятся, если для их NTLM известен пароль.\n\n"
            "Быстрый старт (в репозитории лежат тестовые файлы):\n"
            "  $ python3 dupe-finder.py DC_dump.txt passwords_from_hashcat.txt\n"
            "  $ python3 dupe-finder.py DC_dump.txt passwords_from_hashcat.txt -o result.txt\n"
        ),
    )

    ap.add_argument(
        "secretsdump",
        metavar="SECRETS_DUMP",
        help="Путь к файлу с выводом DC (secretsdump.py) или pwdump-строками. Например: DC_dump.txt",
    )
    ap.add_argument(
        "cracked",
        metavar="CRACKED",
        help="Путь к словарю вида NTLM:пароль (hashcat --show). Например: passwords_from_hashcat.txt",
    )
    ap.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Файл для сохранения результата. Если не указан, печать в stdout.",
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

    # Оставляем только те группы, для которых известен пароль
    items = [(h, users) for h, users in by_hash.items() if h in cracked]

    # Сортировка: больше пользователей выше, при равенстве — по NTLM
    items.sort(key=lambda kv: (-len(kv[1]), kv[0]))

    if not items:
        msg = "Подходящих записей с известными паролями не найдено."
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
        verb = "имеют" if len(users) != 1 else "имеет"
        writer(f"{verb} пароль и NTLM - {h}:{cracked[h]}\n")

    if out_fp:
        out_fp.close()


if __name__ == "__main__":
    main()
