import copy
import pathlib
import re
import json
import hashlib
import subprocess
import tempfile
import unittest
import yaml
from check_workflows import validate


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.good = {'permissions': {'contents': 'read'}, 'jobs': {'publish': {
            'permissions': {'contents': 'write'}, 'steps': [
                {'uses': 'actions/checkout@' + 'a' * 40,
                 'with': {'persist-credentials': False}},
                {'uses': 'owner/action@' + 'b' * 40,
                 'env': {'TOKEN': '${{ secrets.GITHUB_TOKEN }}'}},
            ]}}}

    def test_pinned_step_scoped_publisher(self):
        self.assertEqual([], validate(self.good))

    def test_local_reusable_workflow(self):
        self.good['jobs']['checks'] = {'uses': './.github/workflows/pr.yaml'}
        self.assertEqual([], validate(self.good))

    def test_mutable_and_malformed_refs(self):
        for ref in ['owner/action@v1.2.3', 'owner/action@main', 'owner/action@' + 'a'*39,
                    'owner/action@' + 'z'*40, 'docker://alpine:latest', '${{ inputs.action }}']:
            with self.subTest(ref=ref):
                doc = copy.deepcopy(self.good)
                doc['jobs']['publish']['steps'][1]['uses'] = ref
                self.assertTrue(validate(doc))

    def test_reusable_external_workflow_requires_sha(self):
        self.good['jobs']['checks'] = {'uses': 'owner/repo/.github/workflows/test.yml@main'}
        self.assertTrue(validate(self.good))

    def test_flow_and_quoted_yaml_cannot_hide_mutable_ref(self):
        doc = yaml.safe_load('permissions: {contents: read}\njobs: {test: {steps: [{"uses": "owner/action@v1"}]}}')
        self.assertTrue(validate(doc))

    def test_secrets_cannot_leak_to_checkout_via_env(self):
        for level in ['workflow', 'job']:
            doc = copy.deepcopy(self.good)
            target = doc if level == 'workflow' else doc['jobs']['publish']
            target['env'] = {'PASSWORD': '${{ secrets.DOCKER_PASSWORD }}'}
            self.assertTrue(validate(doc))

    def test_persisted_checkout_credentials_rejected(self):
        for value in [True, 'false', None]:
            doc = copy.deepcopy(self.good)
            doc['jobs']['publish']['steps'][0]['with']['persist-credentials'] = value
            self.assertTrue(validate(doc))

    def test_global_write_permissions_rejected(self):
        self.good['permissions'] = {'contents': 'write'}
        self.assertTrue(validate(self.good))

    def test_secret_in_validation_rejected(self):
        self.good['jobs']['test'] = {'steps': [{'run': 'test', 'env': {'TOKEN': '${{ secrets.TOKEN }}'}}]}
        self.assertTrue(validate(self.good))


class RepositoryGuards(unittest.TestCase):
    root = pathlib.Path(__file__).resolve().parents[2]

    def test_recorded_upstream_versions_and_sha_comments(self):
        pins = json.loads((self.root / '.github/action-pins.json').read_text())
        for path in (self.root / '.github/workflows').glob('*.yaml'):
            for repo, sha, version in re.findall(r'uses: ([^@\s]+)@([a-f0-9]{40}) # (v[^\s]+)', path.read_text()):
                self.assertEqual(pins[repo + '@' + version], sha)
            for line in path.read_text().splitlines():
                if 'uses:' in line and '@' in line:
                    self.assertRegex(line, r'@[a-f0-9]{40} # v[^\s]+$')

    def test_pr_has_no_private_credentials(self):
        text = (self.root / '.github/workflows/pr.yaml').read_text()
        self.assertNotIn('secrets.', text)
        self.assertNotIn('GOPRIVATE', text)

    def test_release_waits_for_checks(self):
        doc = yaml.safe_load((self.root / '.github/workflows/release.yaml').read_text())
        self.assertEqual('checks', doc['jobs']['release']['needs'])
        self.assertEqual({'contents': 'write'}, doc['jobs']['release']['permissions'])

    def test_update_writer_consumes_immutable_checksummed_snapshot(self):
        doc = yaml.safe_load((self.root / '.github/workflows/fetch_ips.yaml').read_text())
        self.assertNotIn('permissions', doc['jobs']['fetch'])
        writer = doc['jobs']['pr']
        self.assertEqual('fetch', writer['needs'])
        self.assertEqual({'contents': 'write', 'pull-requests': 'write'}, writer['permissions'])
        downloads = [step for step in writer['steps'] if step.get('uses', '').startswith('actions/download-artifact@')]
        self.assertEqual('${{ needs.fetch.outputs.artifact-id }}', downloads[0]['with']['artifact-ids'])
        verification = next(i for i, step in enumerate(writer['steps']) if 'sha256sum --check SHA256SUMS' in step.get('run', ''))
        publish = next(i for i, step in enumerate(writer['steps']) if step.get('uses', '').startswith('peter-evans/create-pull-request@'))
        self.assertLess(verification, publish)
        self.assertEqual('remote_ips/cloudflare_v4\nremote_ips/cloudflare_v6\n', writer['steps'][publish]['with']['add-paths'])

    def test_source_release_does_not_execute_build_hooks(self):
        doc = yaml.safe_load((self.root / '.github/workflows/release.yaml').read_text())
        runs = [s.get('run', '') for s in doc['jobs']['release']['steps']]
        self.assertIn('goreleaser release --clean --skip=before', runs)
        config = yaml.safe_load((self.root / '.goreleaser.yaml').read_text())
        self.assertTrue(all(build.get('skip') is True for build in config['builds']))

    def test_snapshot_accepts_valid_files_and_rejects_tampering(self):
        doc = yaml.safe_load((self.root / '.github/workflows/fetch_ips.yaml').read_text())
        command = next(s['run'] for s in doc['jobs']['pr']['steps'] if s.get('name') == 'Verify and copy provider snapshot')
        for tampered in [False, True]:
            with self.subTest(tampered=tampered), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                (root / 'remote_ips').mkdir()
                snapshot = root / 'snapshot'
                (snapshot / 'remote_ips').mkdir(parents=True)
                checksums = []
                for name, data in [('cloudflare_v4', '192.0.2.0/24\n'), ('cloudflare_v6', '2001:db8::/32\n')]:
                    (snapshot / 'remote_ips' / name).write_text(data)
                    checksums.append(hashlib.sha256(data.encode()).hexdigest() + '  remote_ips/' + name)
                (snapshot / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n')
                if tampered:
                    (snapshot / 'remote_ips/cloudflare_v4').write_text('0.0.0.0/0\n')
                result = subprocess.run(['bash', '-e', '-c', command], cwd=root, capture_output=True, text=True)
                if tampered:
                    self.assertNotEqual(0, result.returncode)
                    self.assertFalse((root / 'remote_ips/cloudflare_v4').exists())
                else:
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual('192.0.2.0/24\n', (root / 'remote_ips/cloudflare_v4').read_text())


if __name__ == '__main__':
    unittest.main()
