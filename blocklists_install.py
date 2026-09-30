"""Standard-library installer embedded into generated self-contained scripts."""
# Copyright 2025-2026 CK Cameron. SPDX-License-Identifier: GPL-3.0-only
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib


def atomic_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    old = path.stat() if path.exists() else None
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, old.st_mode & 0o777 if old else 0o644)
        if old:
            os.chown(name, old.st_uid, old.st_gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def managed_block(original, content, tag='python-blocklists'):
    begin, end = f'# BEGIN {tag}', f'# END {tag}'
    if original.count(begin) != original.count(end) or original.count(begin) > 1:
        raise ValueError('Malformed managed markers; refusing to modify file')
    original = re.sub(re.escape(begin) + r'\n.*?' + re.escape(end) + r'\n?', '', original, flags=re.S)
    return original.rstrip('\n') + '\n' + begin + '\n' + content + end + '\n'


def dnscrypt_config(original, filename):
    """Edit exactly one TOML table/key, preserving other configuration/comments."""
    parsed = tomllib.loads(original)
    table = parsed.get('blocked_names', {})
    if not isinstance(table, dict):
        raise ValueError('blocked_names must be a TOML table')
    section = re.search(r'(?m)^[ \t]*\[blocked_names\][ \t]*(?:#.*)?$', original)
    assignment = 'blocked_names_file = ' + json.dumps(str(filename)) + '\n'
    if not section:
        if table:
            raise ValueError('Use a [blocked_names] table, not dotted/inline table syntax')
        updated = original.rstrip() + '\n\n[blocked_names]\n' + assignment
    else:
        start = section.end()
        following = re.search(r'(?m)^[ \t]*\[', original[start:])
        end = start + following.start() if following else len(original)
        body = original[start:end]
        match = re.search(r'(?m)^[ \t]*blocked_names_file[ \t]*=.*(?:\n|$)', body)
        body = (body[:match.start()] + assignment + body[match.end():]) if match else body.rstrip('\n') + '\n' + assignment
        updated = original[:start] + body + original[end:]
    check = tomllib.loads(updated)
    if check.get('blocked_names', {}).get('blocked_names_file') != str(filename):
        raise ValueError('Could not safely update blocked_names_file')
    return updated


def main(kind, payload):
    p = argparse.ArgumentParser(description=f'Install generated {kind} blocks; backup, validate, reload.')
    defaults = {'wrappers': '/etc/hosts.deny', 'unbound': '/etc/unbound/unbound.conf',
                'dnscrypt': '/etc/dnscrypt-proxy/dnscrypt-proxy.toml'}
    p.add_argument('--config', type=Path, default=Path(defaults[kind]))
    p.add_argument('--service', default='dnscrypt-proxy' if kind == 'dnscrypt' else 'unbound')
    p.add_argument('--no-reload', action='store_true', help='validate and install only')
    args = p.parse_args()
    if os.geteuid() != 0:
        p.error('run as root')
    config = args.config.resolve()
    with open('/run/lock/python-blocklists-install.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        original = config.read_text() if config.exists() else ''
        if kind != 'wrappers' and not original:
            p.error('existing resolver configuration is required')
        if kind == 'wrappers':
            updated = managed_block(original, payload)
            target = None
        elif kind == 'unbound':
            target = config.parent / 'python-blocklists.conf'
            # include: accepts a file containing a server: section.
            updated = managed_block(original, 'include: ' + json.dumps(str(target)) + '\n')
        else:
            target = config.parent / 'python-blocklists-blocked-names.txt'
            updated = dnscrypt_config(original, target)
            # Preserve existing user block patterns while avoiding accumulation of
            # stale generated entries over repeated runs.
            old_config = tomllib.loads(original)
            old_name = old_config.get('blocked_names', {}).get('blocked_names_file')
            user_rules = ''
            if old_name:
                previous = Path(old_name)
                if not previous.is_absolute():
                    previous = config.parent / previous
                if previous.exists():
                    user_rules = previous.read_text()
                elif previous.resolve() != target.resolve():
                    raise ValueError(f'Existing blocklist does not exist: {previous}')
            payload = managed_block(user_rules, payload)
        saved = {config: original if config.exists() else None}
        if target:
            saved[target] = target.read_text() if target.exists() else None
        for path in saved:
            if path.exists():
                shutil.copy2(path, str(path) + '.blocklists.bak')
        try:
            if target:
                atomic_write(target, payload)
            atomic_write(config, updated)
            if kind == 'unbound':
                subprocess.run(['unbound-checkconf', str(config)], check=True)
            elif kind == 'dnscrypt':
                subprocess.run(['dnscrypt-proxy', '-config', str(config), '-check'], cwd=config.parent, check=True)
            if kind != 'wrappers' and not args.no_reload:
                subprocess.run(['systemctl', 'reload-or-restart', args.service], check=True)
        except BaseException:
            for path, text in saved.items():
                if text is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_write(path, text)
            if kind != 'wrappers' and not args.no_reload:
                subprocess.run(['systemctl', 'reload-or-restart', args.service], check=False)
            raise
        print(f'Installed {kind} blocks in {config}')
