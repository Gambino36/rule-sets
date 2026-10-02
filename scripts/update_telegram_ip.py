#!/usr/bin/env python3
"""Rebuild the exact union of three Telegram IP sources only when they change.

Dependencies: Python 3.12+, PyYAML 6.0.3, Mihomo v1.19.32 (build only).
YAML uses bare CIDRs for behavior: ipcidr, with IPv6 then IPv4 numerically
descending. All fetches and validation finish before tracked files are written.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.request import Request, urlopen

import yaml


ROOT = Path(__file__).resolve().parents[1]
STATE = Path('.github/telegram-ip-sources.json')
YAML = Path('Mihomo/telegram-ip.yaml')
MRS = Path('Mihomo/telegram-ip.mrs')
MIHOMO_VERSION = 'v1.19.32'
MAX_SOURCE_BYTES = 2 * 1024 * 1024
SOURCES = (
    ('666OS.txt', 'https://raw.githubusercontent.com/666OS/rules/release/mihomo/ip/Telegram.txt'),
    ('metacubex.list', 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/telegram.list'),
    ('davoyan.yaml', 'https://raw.githubusercontent.com/Davoyan/mihomo-rule-sets/main/domains/additional-telegram-ips.yaml'),
)


class UniqueKeyLoader(yaml.SafeLoader):
    """Reject duplicate YAML mapping keys instead of silently losing entries."""


def unique_mapping(loader, node):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in mapping:
            raise ValueError(f'Duplicate YAML key: {key!r}')
        mapping[key] = loader.construct_object(value_node)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping,
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_rule(rule: str):
    if not isinstance(rule, str):
        raise ValueError(f'IP rule must be a string: {rule!r}')
    rule = rule.partition('#')[0].strip()
    family = None
    match = re.fullmatch(r'(IP-CIDR6|IP-CIDR)[:,](.+)', rule)
    if match:
        # Mihomo IP-CIDR accepts both families; IP-CIDR6 explicitly means IPv6.
        family = 6 if match[1] == 'IP-CIDR6' else None
        fields = match[2].split(',')
        if len(fields) > 2 or (len(fields) == 2 and fields[1].strip() != 'no-resolve'):
            raise ValueError(f'Unsupported IP rule fields: {rule!r}')
        rule = fields[0].strip()
    if not rule or '/' not in rule:
        raise ValueError(f'Expected a CIDR: {rule!r}')
    # Mask host bits: e.g. 185.76.151.0/22 means 185.76.148.0/22.
    network = ipaddress.ip_network(rule, strict=False)
    if family is not None and network.version != family:
        raise ValueError(f'IP-CIDR family mismatch: {rule!r}')
    return network


def parse_source(name: str, data: bytes):
    text = data.decode('utf-8-sig')
    if name.endswith('.yaml'):
        parsed = yaml.load(text, Loader=UniqueKeyLoader)
        if not isinstance(parsed, dict) or set(parsed) != {'payload'}:
            raise ValueError(f'{name}: expected only a payload mapping')
        rules = parsed['payload']
        if not isinstance(rules, list):
            raise ValueError(f'{name}: payload must be a list')
    else:
        rules = [line for line in text.splitlines() if line.partition('#')[0].strip()]
    if not rules:
        raise ValueError(f'{name}: source is empty')
    networks = []
    for number, rule in enumerate(rules, 1):
        try:
            networks.append(parse_rule(rule))
        except (ValueError, TypeError) as error:
            raise ValueError(f'{name}, entry {number}: {error}') from error
    return networks


def address_ranges(networks):
    """Independent interval union, also used to verify the MRS round trip."""
    result = []
    for family in (4, 6):
        intervals = sorted(
            (int(n.network_address), int(n.broadcast_address))
            for n in networks if n.version == family
        )
        merged = []
        for start, end in intervals:
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        result.extend((family, start, end) for start, end in merged)
    return result


def combine(sources):
    networks = []
    for name, _ in SOURCES:
        networks.extend(parse_source(name, sources[name]))
    unique = set(networks)
    collapsed = []
    for family in (4, 6):
        collapsed.extend(ipaddress.collapse_addresses(n for n in unique if n.version == family))
    collapsed.sort(key=lambda n: (n.version, int(n.network_address), n.prefixlen), reverse=True)
    if address_ranges(networks) != address_ranges(collapsed):
        raise ValueError('CIDR reduction changed the original address coverage')
    print(f'{len(networks)} source entries; {len(unique)} unique CIDRs; '
          f'{len(collapsed)} non-overlapping CIDRs '
          f'({sum(n.version == 4 for n in collapsed)} IPv4, '
          f'{sum(n.version == 6 for n in collapsed)} IPv6).')
    return collapsed


def render(networks) -> bytes:
    return ('payload:\n' + ''.join(f"  - '{network}'\n" for network in networks)).encode()


def fetch_source(item):
    name, url = item
    for attempt in range(3):
        try:
            request = Request(url, headers={'User-Agent': 'Telegram-IP-rules-updater/1.0'})
            with urlopen(request, timeout=30) as response:
                if response.status != 200:
                    raise ValueError(f'{name}: unexpected HTTP status {response.status}')
                data = response.read(MAX_SOURCE_BYTES + 1)
            if len(data) > MAX_SOURCE_BYTES:
                raise ValueError(f'{name}: source exceeds {MAX_SOURCE_BYTES} bytes')
            return name, data
        except (OSError, ValueError) as error:
            if attempt == 2:
                raise ValueError(f'Could not fetch {url}: {error}') from error
            time.sleep(attempt + 1)


def source_manifest(sources):
    return [
        {'name': name, 'url': url, 'sha256': digest(sources[name])}
        for name, url in SOURCES
    ]


def read_state(root: Path):
    path = root / STATE
    if not path.exists():
        return None
    state = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(state, dict) or state.get('schema') != 1:
        raise ValueError('Unsupported Telegram source-state schema')
    if not isinstance(state.get('sources'), list) or not isinstance(state.get('outputs'), dict):
        raise ValueError('Invalid Telegram source-state structure')
    return state


def verify_outputs(root: Path, state, networks):
    expected = render(networks)
    if (root / YAML).read_bytes() != expected:
        raise ValueError('Tracked Telegram YAML differs from the current source union')
    for path in (YAML, MRS):
        data = (root / path).read_bytes()
        if not data or state['outputs'].get(path.as_posix()) != digest(data):
            raise ValueError(f'Tracked {path} checksum does not match the validated build')


def check(snapshot_dir: Path, github_output: Path | None = None, root: Path = ROOT):
    with ThreadPoolExecutor(max_workers=len(SOURCES)) as pool:
        sources = dict(pool.map(fetch_source, SOURCES))
    networks = combine(sources)
    manifest = source_manifest(sources)
    state = read_state(root)
    changed = state is None or state['sources'] != manifest
    if not changed:
        verify_outputs(root, state, networks)
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    for name, data in sources.items():
        (snapshot_dir / name).write_bytes(data)
    (snapshot_dir / 'manifest.json').write_text(
        json.dumps(manifest, indent=2) + '\n', encoding='utf-8',
    )
    if github_output is not None:
        with github_output.open('a', encoding='utf-8') as output:
            output.write(f'changed={str(changed).lower()}\n')
    print('Original source files changed.' if changed else 'Sources unchanged; compilation skipped.')
    return changed


def load_snapshot(snapshot_dir: Path):
    sources = {name: (snapshot_dir / name).read_bytes() for name, _ in SOURCES}
    manifest = json.loads((snapshot_dir / 'manifest.json').read_text(encoding='utf-8'))
    if manifest != source_manifest(sources):
        raise ValueError('Downloaded sources no longer match their snapshot checksums')
    return sources, manifest


def run_mihomo(mihomo: Path, *args):
    result = subprocess.run(
        [str(mihomo.resolve()), *map(str, args)], capture_output=True, text=True, check=True,
        timeout=60,
    )
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip())
    return result.stdout + result.stderr


def build(snapshot_dir: Path, mihomo: Path, root: Path = ROOT):
    sources, manifest = load_snapshot(snapshot_dir)
    networks = combine(sources)
    previous = read_state(root)
    if previous is not None and previous['sources'] == manifest:
        verify_outputs(root, previous, networks)
        print('Sources unchanged; compilation skipped.')
        return False
    version = run_mihomo(mihomo, '-v')
    if not re.search(r'\bv1\.19\.32\b', version):
        raise ValueError(f'Expected Mihomo {MIHOMO_VERSION}')
    with tempfile.TemporaryDirectory(prefix='telegram-ip-') as temporary:
        work = Path(temporary)
        source, compiled, exported = (work / name for name in ('source.yaml', 'output.mrs', 'export.txt'))
        source.write_bytes(render(networks))
        run_mihomo(mihomo, 'convert-ruleset', 'ipcidr', 'yaml', source, compiled)
        if not compiled.is_file() or not compiled.stat().st_size:
            raise ValueError('Mihomo did not produce a non-empty MRS')
        run_mihomo(mihomo, 'convert-ruleset', 'ipcidr', 'mrs', compiled, exported)
        restored = parse_source('mrs-export.txt', exported.read_bytes())
        if address_ranges(networks) != address_ranges(restored):
            raise ValueError('MRS address coverage differs from the source YAML')
        yaml_data, mrs_data = source.read_bytes(), compiled.read_bytes()
    state = {
        'schema': 1,
        'compiler': f'Mihomo {MIHOMO_VERSION}',
        'sources': manifest,
        'outputs': {YAML.as_posix(): digest(yaml_data), MRS.as_posix(): digest(mrs_data)},
        'networks': {'ipv4': sum(n.version == 4 for n in networks),
                     'ipv6': sum(n.version == 6 for n in networks)},
    }
    files = {YAML: yaml_data, MRS: mrs_data,
             STATE: (json.dumps(state, indent=2) + '\n').encode()}
    # Each replacement is atomic. The workflow publishes all three in one commit.
    for path, data in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as output:
            temporary = Path(output.name)
            try:
                output.write(data)
                output.flush()
                os.fchmod(output.fileno(), 0o644)
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise
        try:
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    print(f'Validated and published {len(networks)} CIDRs to {YAML} and {MRS}.')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    check_parser = commands.add_parser('check', help='Fetch and validate sources, detect byte changes')
    check_parser.add_argument('--snapshot-dir', type=Path, required=True)
    check_parser.add_argument('--github-output', type=Path)
    build_parser = commands.add_parser('build', help='Compile changed snapshots and verify coverage')
    build_parser.add_argument('--snapshot-dir', type=Path, required=True)
    build_parser.add_argument('--mihomo', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'check':
            check(args.snapshot_dir, args.github_output)
        else:
            build(args.snapshot_dir, args.mihomo)
    except (OSError, ValueError, yaml.YAMLError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Telegram IP update failed: {error}\n')


if __name__ == '__main__':
    main()
