import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from encryption_claim_audit.audit import audit, extract_claims, extract_evidence, normalize
from encryption_claim_audit.__main__ import main

FIXTURES = Path(__file__).parent / 'fixtures'


class AuditTests(unittest.TestCase):
    def project(self, docs='Output is encrypted.', code='value = 1', extra=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / 'README.md').write_text(docs)
        if code is not None:
            (root / 'main.py').write_text(code)
        for name, content in (extra or {}).items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return root

    def cli(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = main(list(map(str, args)))
        return code, output.getvalue(), errors.getvalue()

    def test_normalization(self):
        self.assertEqual(normalize(" ISN'T  end-to-end\nEncrypted "), 'is not end to end encrypted')

    def test_fence(self):
        self.assertEqual(extract_claims('```text\nencrypted\n```\n'), [])

    def test_tilde_fence(self):
        self.assertEqual(extract_claims('~~~~\nplaintext\n~~~~\n'), [])

    def test_inline(self):
        self.assertEqual(extract_claims('`encrypted`')[0]['family'], 'encrypted')

    def test_wrapping(self):
        self.assertEqual(extract_claims('stored as\nplain text')[0]['family'], 'plaintext')

    def test_sentence_negation(self):
        self.assertEqual({c['family'] for c in extract_claims('Never send data. Output is encrypted.')}, {'encrypted'})

    def test_both_no_source(self):
        result = audit(self.project('encrypted. plaintext.', None))
        self.assertEqual(len(result['findings']), 2)
        self.assertTrue(all(f['evidence'] == [{'kind': 'no-source'}] for f in result['findings']))

    def test_production_all_evidence(self):
        result = audit(self.project('plaintext', 'import nacl\nAES()\nx.encrypt()'))
        self.assertEqual(len(result['findings'][0]['evidence']), 3)

    def test_ignore(self):
        root = self.project('plaintext', 'AES()')
        result = audit(root, ['main.py'])
        self.assertEqual(result['production_evidence'], [])
        self.assertEqual(result['findings'][0]['evidence'][0]['kind'], 'no-source')

    def test_ignore_cli(self):
        root = self.project('plaintext', 'x=1', {'cipher.py': 'AES()'})
        self.assertEqual(self.cli(root, '--ignore', 'cipher.py')[0], 0)

    def test_ignore_directory(self):
        root = self.project('plaintext', 'x=1', {'vendor/cipher.py': 'AES()'})
        self.assertEqual(audit(root, ['vendor'])['production_evidence'], [])

    def test_no_claim(self):
        self.assertEqual(audit(self.project('Notes', 'AES()'))['findings'], [])

    def test_testonly_plaintext(self):
        root = self.project('plaintext', 'x=1', {'tests/t.py': 'AES()'})
        finding = audit(root)['findings'][0]
        self.assertEqual(finding['rule'], 'documented-plaintext-claim-false-test-only')
        self.assertEqual(finding['severity'], 'MEDIUM')

    def test_production_over_testonly(self):
        root = self.project('encrypted', 'AES()', {'tests/t.py': 'AES()'})
        self.assertEqual(len(audit(root)['verified_claims']), 1)

    def test_no_source_precedence(self):
        root = self.project('encrypted', None, {'tests/t.py': 'AES()'})
        self.assertEqual(audit(root)['findings'][0]['severity'], 'HIGH')

    def test_docs_source(self):
        root = self.project('Notes', 'x=1', {'docs/nested/p.md': 'encrypted'})
        self.assertEqual(len(audit(root)['claims']), 1)

    def test_other_markdown_excluded(self):
        root = self.project('Notes', 'x=1', {'other.md': 'encrypted'})
        self.assertEqual(audit(root)['claims'], [])

    def test_symlink_file(self):
        root = self.project('plaintext', 'x=1')
        (root / 'link.py').symlink_to(root / 'main.py')
        self.assertEqual(audit(root)['production_evidence'], [])

    def test_symlink_directory(self):
        root = self.project('plaintext', 'x=1')
        (root / 'loop').symlink_to(root, target_is_directory=True)
        self.assertEqual(audit(root)['findings'], [])

    def test_env_not_opened(self):
        root = self.project('plaintext', 'x=1', {'.env': 'SECRET_MARKER'})
        original = Path.read_text
        def checked(path, *args, **kwargs):
            self.assertNotEqual(path.name, '.env')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'read_text', checked):
            code, output, _ = self.cli(root, '--json')
        self.assertEqual(code, 0)
        self.assertNotIn('SECRET_MARKER', output)

    def test_json_shape(self):
        code, output, _ = self.cli(FIXTURES / 'good/encrypted', '--json')
        result = json.loads(output)
        self.assertEqual(code, 0)
        self.assertIn('findings', result)
        self.assertEqual(result['verified_claims'][0]['family'], 'encrypted')

    def test_threshold(self):
        self.assertEqual(self.cli(FIXTURES / 'testonly/encrypted', '--fail-on', 'HIGH')[0], 0)
        self.assertEqual(self.cli(FIXTURES / 'testonly/encrypted')[0], 2)

    def test_version(self):
        with contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as exc:
            main(['--version'])
        self.assertEqual(exc.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), '0.1.0')

    def test_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
            main(['--unknown'])
        self.assertEqual(exc.exception.code, 1)

    def test_bad_root(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
            main(['/this/path/does/not/exist'])
        self.assertEqual(exc.exception.code, 1)

    def test_syntax_error(self):
        code, output, _ = self.cli(self.project('encrypted', 'def !'), '--json')
        self.assertEqual(code, 1)
        self.assertTrue(json.loads(output)['errors'])

    def test_dedupe(self):
        self.assertEqual(len(extract_evidence('AES(); AES()', 'a.py')), 1)

    def test_import_statement_dedupe(self):
        self.assertEqual(len(extract_evidence('import Crypto, nacl', 'a.py')), 1)

    def test_dead_code(self):
        self.assertEqual(len(extract_evidence('if False:\n    AES()', 'a.py')), 1)

    def test_self_audit(self):
        result = audit(Path(__file__).resolve().parents[1])
        self.assertEqual(result['claims'], [])
        self.assertEqual(result['findings'], [])


def claim_test(text, expected):
    def test(self):
        self.assertEqual({c['family'] for c in extract_claims(text)}, set(expected))
    return test


for index, (text, expected) in enumerate([
    ('encrypted', ['encrypted']), ('encrypts data', ['encrypted']),
    ('encryption at rest', ['encrypted']), ('end-to-end encrypted', ['encrypted']),
    ('encrypted at rest', ['encrypted']), ('plaintext', ['plaintext']),
    ('plain-text', ['plaintext']), ('unencrypted', ['plaintext']),
    ('not encrypted', ['plaintext']), ('is not encrypted', ['plaintext']),
    ('no encryption', ['plaintext']), ('never encrypted', ['plaintext']),
    ('does not encrypt', ['plaintext']), ("doesn't encrypt", ['plaintext']),
    ("isn't encrypted", ['plaintext']), ('stored in plaintext', ['plaintext']),
    ('stored as plain text', ['plaintext']), ('stored unencrypted', ['plaintext']),
    ('encryption', []), ('encrypt', []), ('reencrypted', []),
    ('without encrypted output', []), ('never encrypts', []),
    ('no plaintext', ['plaintext']), ('encrypted. plaintext.', ['encrypted', 'plaintext']),
]):
    setattr(AuditTests, 'test_claim_%02d' % index, claim_test(text, expected))


def evidence_test(code, count):
    def test(self):
        self.assertEqual(len(extract_evidence(code, 'main.py')), count)
    return test


for index, (code, count) in enumerate([
    ('import cryptography', 1), ('from Crypto.Cipher import AES', 1),
    ('import Cryptodome', 1), ('import nacl.secret', 1), ('obj.encrypt(data)', 1),
    ('encrypt(data)', 1), ('Fernet(data)', 1), ('AES()', 1), ('AESGCM()', 1),
    ('ChaCha20Poly1305()', 1), ('Cipher()', 1), ('import hashlib', 0),
    ('import base64', 0), ('import bcrypt', 0), ('import hmac', 0),
    ('import argon2', 0), ('import codecs', 0), ('"encrypt"', 0),
    ('# AES()\nx=1', 0), ('def encrypt(x):\n    return x\nencrypt(1)', 0),
    ('class encrypt: pass\nencrypt()', 0), ('def f(encrypt):\n    encrypt()', 0),
    ('async def encrypt(): pass\nencrypt()', 0),
    ('def encrypt(): pass\nobj.encrypt()', 1), ('from .Crypto import AES', 1),
]):
    setattr(AuditTests, 'test_evidence_%02d' % index, evidence_test(code, count))


def fixture_test(path, expected_code, rule):
    def test(self):
        code, output, _ = self.cli(FIXTURES / path, '--json')
        result = json.loads(output)
        self.assertEqual(code, expected_code)
        self.assertEqual([f['rule'] for f in result['findings']], [rule] if rule else [])
    return test


for index, (path, code, rule) in enumerate([
    ('good/encrypted', 0, None), ('good/plaintext', 0, None),
    ('bad/encrypted', 2, 'documented-encrypted-claim-false'),
    ('bad/plaintext', 2, 'documented-plaintext-claim-false'),
    ('testonly/encrypted', 2, 'documented-encrypted-claim-false-test-only'),
]):
    setattr(AuditTests, 'test_fixture_%02d' % index, fixture_test(path, code, rule))


def excluded_test(path, testonly):
    def test(self):
        result = audit(self.project('plaintext', 'x=1', {path: 'AES()'}))
        self.assertEqual(len(result['test_only_evidence']), int(testonly))
        self.assertEqual(result['production_evidence'], [])
    return test


for index, (path, testonly) in enumerate([
    ('tests/x.py', True), ('fixtures/x.py', True), ('test_x.py', True),
    ('x_test.py', True), ('docs/x.py', False), ('examples/x.py', False),
]):
    setattr(AuditTests, 'test_excluded_%02d' % index, excluded_test(path, testonly))


if __name__ == '__main__':
    unittest.main()
