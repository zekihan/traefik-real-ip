#!/usr/bin/env python3
"""Offline structural workflow policy; run after installing requirements-policy.txt."""
import pathlib
import re
import sys
import yaml

SHA = re.compile(r"[^\s@]+/[^\s@]+@[0-9a-f]{40}\Z")


def validate(doc):
    errors = []
    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key == 'uses' and (not isinstance(child, str) or
                        (not child.startswith('./') and not SHA.fullmatch(child))):
                    errors.append('external uses must be pinned to a full commit SHA')
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(doc)
    if not isinstance(doc, dict) or not isinstance(doc.get('jobs'), dict):
        return errors + ['workflow must contain jobs']
    if any('secrets.' in str(v) for v in doc.get('env', {}).values()):
        errors.append('workflow env must not expose secrets')
    permissions = doc.get('permissions')
    if not isinstance(permissions, dict) or any(v != 'read' for v in permissions.values()):
        errors.append('workflow permissions must be explicitly read-only; scope writes to jobs')
    for name, job in doc['jobs'].items():
        if any('secrets.' in str(v) for v in job.get('env', {}).values()):
            errors.append(f'{name}: job env must not expose secrets')
        for step in job.get('steps', []):
            if step.get('uses', '').startswith('actions/checkout@') and step.get('with', {}).get('persist-credentials') is not False:
                errors.append(f'{name}: checkout must disable credential persistence')
            if name in ('checks', 'test', 'container') and 'secrets.' in str(step):
                errors.append(f'{name}: validation must not receive secrets')
    return errors


def main():
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else '.')
    errors = []
    paths = sorted((root / '.github/workflows').glob('*.y*ml'))
    if not paths:
        errors.append('no workflows found')
    for path in paths:
        try:
            errors.extend(f'{path}: {e}' for e in validate(yaml.safe_load(path.read_text())))
        except yaml.YAMLError as e:
            errors.append(f'{path}: invalid YAML: {e}')
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print(f'Workflow security policy passed ({len(paths)} workflows)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
