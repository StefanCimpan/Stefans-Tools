#!/usr/bin/env python3
"""
Generator de parole aleatorii sigure.
Foloseste modulul 'secrets' (nu 'random') pentru randomness criptografic.

Utilizare:
    python3 generate_password.py
    python3 generate_password.py -l 16
    python3 generate_password.py -l 20 --no-symbols
    python3 generate_password.py -l 12 -n 5          # genereaza 5 parole
"""

import argparse
import secrets
import string
import sys


def build_charset(use_upper: bool, use_lower: bool, use_digits: bool, use_symbols: bool) -> str:
    charset = ""
    if use_upper:
        charset += string.ascii_uppercase
    if use_lower:
        charset += string.ascii_lowercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += "!@#$%^&*()-_=+[]{}?"
    return charset


def generate_password(length: int, use_upper: bool, use_lower: bool,
                       use_digits: bool, use_symbols: bool) -> str:
    charset = build_charset(use_upper, use_lower, use_digits, use_symbols)
    if not charset:
        raise ValueError("Cel putin un tip de caracter trebuie activat.")

    # ne asiguram ca fiecare tip selectat apare cel putin o data
    pools = []
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{}?")

    if length < len(pools):
        raise ValueError(f"Lungimea minima pentru optiunile alese este {len(pools)}.")

    password_chars = [secrets.choice(pool) for pool in pools]
    remaining = length - len(password_chars)
    password_chars += [secrets.choice(charset) for _ in range(remaining)]

    # amestecam pozitiile ca sa nu fie predictibil (primele caractere din pools)
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def strength_label(length: int, num_types: int) -> str:
    score = length * num_types
    if score >= 60:
        return "Foarte puternica"
    if score >= 40:
        return "Puternica"
    if score >= 24:
        return "Medie"
    return "Slaba"


def main():
    parser = argparse.ArgumentParser(description="Generator de parole aleatorii sigure.")
    parser.add_argument("-l", "--length", type=int, default=12, help="Lungimea parolei (implicit 12)")
    parser.add_argument("-n", "--count", type=int, default=1, help="Cate parole sa genereze (implicit 1)")
    parser.add_argument("--no-upper", action="store_true", help="Exclude literele mari")
    parser.add_argument("--no-lower", action="store_true", help="Exclude literele mici")
    parser.add_argument("--no-numbers", action="store_true", help="Exclude cifrele")
    parser.add_argument("--no-symbols", action="store_true", help="Exclude simbolurile")
    args = parser.parse_args()

    use_upper = not args.no_upper
    use_lower = not args.no_lower
    use_digits = not args.no_numbers
    use_symbols = not args.no_symbols
    num_types = sum([use_upper, use_lower, use_digits, use_symbols])

    try:
        for _ in range(args.count):
            pw = generate_password(args.length, use_upper, use_lower, use_digits, use_symbols)
            print(f"{pw}   [{strength_label(args.length, num_types)}]")
    except ValueError as e:
        print(f"Eroare: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()