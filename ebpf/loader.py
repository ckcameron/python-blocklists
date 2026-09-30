"""Generated eBPF loader/monitor: compile, stage maps, attach and inspect TC."""
# Copyright 2026 CK Cameron. SPDX-License-Identifier: GPL-3.0-only
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import time
import uuid

PREF = '1'
HANDLE = '0xb10c'
ROOT = Path('/sys/fs/bpf/python_blocklists')
STATE = Path('/var/lib/python-blocklists/ebpf.json')


def run(*args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, text=True, **kwargs)


def query(*args):
    return json.loads(run(*args, capture_output=True).stdout)


def program_id(path):
    value = query('bpftool', '-j', 'prog', 'show', 'pinned', path)
    return (value[0] if isinstance(value, list) else value)['id']


def filter_program_id(filt):
    options = filt.get('options', {})
    return options.get('prog', {}).get('id', options.get('id'))


def prefix_key(network):
    n = ipaddress.ip_network(network)
    return struct.pack('=I', n.prefixlen) + n.network_address.packed


def live_links():
    return {link['ifname']: link['ifindex'] for link in query('ip', '-j', 'link', 'show')}


def attach(pin, interfaces, previous):
    links = live_links()
    selected = interfaces or list(links)
    if any(name not in links for name in selected):
        raise ValueError('An interface does not exist in the current network namespace')
    # Refuse to overwrite an unrelated filter or run after an earlier classifier.
    old_ids = set(previous.get('program_ids', []))
    new_ids = {program_id(pin / 'progs' / f'bl_{direction}')
               for direction in ('ingress', 'egress')}
    for name in selected:
        for direction in ('ingress', 'egress'):
            for filt in query('tc', '-j', 'filter', 'show', 'dev', name, direction):
                # tc also emits a summary record for each filter priority.
                if 'options' not in filt:
                    continue
                if int(filt.get('pref', 65535)) <= int(PREF):
                    options = filt.get('options', {})
                    if (filt.get('kind') != 'bpf' or filter_program_id(filt) not in old_ids | new_ids
                            or str(options.get('handle')) not in (HANDLE, str(int(HANDLE, 16)))):
                        raise ValueError(f'{name}/{direction}: conflicting TC filter at priority {filt.get("pref")}')
    installed = dict(previous.get('interfaces', {}))
    for name in selected:
        qdiscs = query('tc', '-j', 'qdisc', 'show', 'dev', name)
        if not any(q.get('kind') == 'clsact' for q in qdiscs):
            run('tc', 'qdisc', 'add', 'dev', name, 'clsact')
        for direction in ('ingress', 'egress'):
            run('tc', 'filter', 'replace', 'dev', name, direction, 'pref', PREF,
                'handle', HANDLE, 'protocol', 'all', 'bpf', 'da', 'skip_hw', 'pinned',
                pin / 'progs' / f'bl_{direction}')
        installed[name] = links[name]
    return installed, sorted(new_ids)


def save_state(state):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix('.tmp')
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(STATE)


def install(source, networks, interfaces):
    previous = json.loads(STATE.read_text()) if STATE.exists() else {}
    if previous and previous.get('netns') != os.readlink('/proc/self/ns/net'):
        raise ValueError('Existing installation belongs to a different network namespace')
    # bpffs must already be mounted; do not silently pin into an ordinary fs.
    mounted = run('stat', '-f', '-c', '%t', '/sys/fs/bpf', capture_output=True).stdout.strip()
    if int(mounted, 16) != 0xCAFE4A11:  # BPF_FS_MAGIC, linux/magic.h
        raise ValueError('Mount bpffs first: mount -t bpf bpf /sys/fs/bpf')
    ROOT.mkdir(exist_ok=True)
    generation = ROOT / ('g' + uuid.uuid4().hex[:12])
    generation.mkdir()
    (generation / 'maps').mkdir()
    (generation / 'progs').mkdir()
    try:
        with tempfile.TemporaryDirectory(prefix='blocklists-bpf-') as tmp:
            tmp = Path(tmp)
            (tmp / 'blocklists.c').write_text(source)
            command = ['clang', '-O2', '-g', '-target', 'bpf',
                       f'-DMAX_PREFIXES={max(1024, len(networks) + 1)}']
            multiarch = Path('/usr/include') / (platform.machine() + '-linux-gnu')
            if multiarch.exists():
                command += ['-I', str(multiarch)]
            run(*command, '-c', tmp / 'blocklists.c', '-o', tmp / 'blocklists.o')
            run('bpftool', 'prog', 'loadall', tmp / 'blocklists.o', generation / 'progs',
                'type', 'classifier', 'pinmaps', generation / 'maps')
            batch = tmp / 'map.batch'
            with batch.open('w') as stream:
                for network in networks:
                    n = ipaddress.ip_network(network)
                    key = ' '.join(f'{b:02x}' for b in prefix_key(network))
                    value = ' '.join(f'{b:02x}' for b in struct.pack('=I', 1))
                    stream.write(f'map update pinned {generation}/maps/blocked{n.version} key hex {key} value hex {value}\n')
            if networks:
                run('bpftool', 'batch', 'file', batch)
        # Record generation before attaching, so a failed partial attach remains
        # recoverable. Keep old pins until all interfaces are successfully replaced.
        ids = [program_id(generation / 'progs' / f'bl_{d}')
               for d in ('ingress', 'egress')]
        recovery = dict(previous)
        recovery['netns'] = os.readlink('/proc/self/ns/net')
        recovery['interfaces'] = live_links()
        recovery['program_ids'] = list(set(previous.get('program_ids', []) + ids))
        recovery['pending_pin'] = str(generation)
        save_state(recovery)
        # Always migrate previously covered interfaces that still exist.
        links = live_links()
        selected = list(dict.fromkeys((interfaces or list(links)) + [n for n in previous.get('interfaces', {}) if n in links]))
        installed, ids = attach(generation, selected, recovery)
        state = {'pin': str(generation), 'interfaces': installed, 'program_ids': ids,
                 'netns': os.readlink('/proc/self/ns/net')}
        save_state(state)
        for old in ROOT.iterdir():
            if old != generation and old.is_dir():
                shutil.rmtree(old)
        print('eBPF active on ingress and egress:', ', '.join(selected))
    except BaseException:
        print(f'Install failed. Staged pins retained for recovery: {generation}')
        raise


def monitor(state):
    pin = Path(state['pin'])
    # Decode the documented raw map layout on the same host as the BPF program.
    records = query('bpftool', '-j', 'map', 'dump', 'pinned', pin / 'maps' / 'drops')
    for record in records:
        raw = bytes(int(v, 16) if isinstance(v, str) else v for v in record['key'])
        family, ifindex, direction, endpoint = struct.unpack('=IIII', raw[:16])
        address = raw[16:20 if family == 4 else 32]
        values = [struct.unpack('=QQ', bytes(int(b, 16) if isinstance(b, str) else b for b in v['value']))
                  for v in record['values']]
        packets = sum(v[0] for v in values)
        size = sum(v[1] for v in values)
        print(json.dumps({'ip': str(ipaddress.ip_address(address)), 'ifindex': ifindex,
                          'direction': 'egress' if direction else 'ingress',
                          'endpoint': 'destination' if endpoint else 'source',
                          'packets': packets, 'bytes': size}))
    print(json.dumps({'totals': query('bpftool', '-j', 'map', 'dump', 'pinned', pin / 'maps' / 'totals')}))


def main(source, networks):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'watch', 'monitor', 'remove'), nargs='?', default='install')
    parser.add_argument('--interfaces', nargs='+', help='default: all current interfaces, including loopback')
    parser.add_argument('--interval', type=float, default=5)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root in the network namespace to protect')
    if args.interval <= 0:
        parser.error('interval must be positive')
    for tool in ('ip', 'tc', 'bpftool') + (('clang',) if args.action == 'install' else ()):
        if not shutil.which(tool):
            parser.error(f'missing {tool}')
    with open('/run/lock/python-blocklists-ebpf.lock', 'a') as lock:
        # Lock individual mutations; monitor/watch must not block later updates.
        if args.action in ('install', 'remove'):
            fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == 'install':
            install(source, networks, args.interfaces)
            return
        while True:
            if not STATE.exists():
                parser.error('no eBPF installation state')
            state = json.loads(STATE.read_text())
            if state.get('netns') != os.readlink('/proc/self/ns/net'):
                parser.error('installation belongs to another network namespace')
            if args.action == 'remove':
                links = live_links()
                for name, index in state.get('interfaces', {}).items():
                    if links.get(name) != index:
                        continue
                    for direction in ('ingress', 'egress'):
                        filters = query('tc', '-j', 'filter', 'show', 'dev', name, direction)
                        if any(filter_program_id(f) in state['program_ids'] for f in filters):
                            run('tc', 'filter', 'del', 'dev', name, direction, 'pref', PREF, 'handle', HANDLE, 'protocol', 'all', 'bpf')
                shutil.rmtree(ROOT)
                STATE.unlink()
                return
            if args.action == 'watch':
                fcntl.flock(lock, fcntl.LOCK_EX)
                try:
                    state = json.loads(STATE.read_text())
                    installed, ids = attach(Path(state['pin']), args.interfaces, state)
                    state.update(interfaces=installed, program_ids=ids)
                    save_state(state)
                    monitor(state)
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
            else:
                monitor(state)
                return
            time.sleep(args.interval)
