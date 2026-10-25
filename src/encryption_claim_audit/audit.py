"""Offline documentation and AST comparison; audited code is never executed."""
import ast
import fnmatch
import os
from pathlib import Path
import re

PHRASES = {
    'encrypted': ('encrypted', 'encrypts', 'encryption at rest', 'end to end encrypted', 'encrypted at rest'),
    'plaintext': ('plaintext', 'plain text', 'unencrypted', 'not encrypted', 'no encryption', 'never encrypted', 'does not encrypt', 'stored in plaintext', 'stored as plain text', 'stored unencrypted'),
}
TEST_DIRS = {'tests', 'fixtures'}
EXCLUDED = {'docs', 'examples'}


def normalize(text):
    return ' '.join(text.lower().replace("n't", ' not').replace('-', ' ').split())


def extract_claims(text, path='README.md'):
    claims = []
    fence = None
    prose = []
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence) and not line[match.end():].strip():
                fence = None
            continue
        if fence is None:
            prose.append((number, line))
        else:
            prose.append((number, ''))
    # Paragraphs may wrap across lines; punctuation and blank lines end sentences.
    paragraph = []
    start = 1
    def consume(parts, lineno):
        for sentence in re.split(r'[.!?]+', ' '.join(parts)):
            value = normalize(sentence)
            negated = re.search(r'\b(no|not|never|without)\b', value)
            for family, phrases in PHRASES.items():
                if family == 'encrypted' and negated:
                    continue
                if any(re.search(r'\b' + re.escape(p) + r'\b', value) for p in phrases):
                    claims.append({'family': family, 'path': path, 'line': lineno, 'text': sentence.strip()})
    for number, line in prose + [(0, '')]:
        if not line.strip():
            consume(paragraph, start)
            paragraph = []
        else:
            if not paragraph:
                start = number
            paragraph.append(line)
    return claims


def extract_evidence(text, path):
    tree = ast.parse(text, filename=path)
    shadowed = any(
        (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == 'encrypt')
        or (isinstance(n, ast.arg) and n.arg == 'encrypt')
        for n in ast.walk(tree)
    )
    result = set()
    for node in ast.walk(tree):
        kind = None
        if isinstance(node, ast.Import):
            if any(a.name.split('.')[0] in {'cryptography', 'Crypto', 'Cryptodome', 'nacl'} for a in node.names):
                kind = 'encryption-import'
        elif isinstance(node, ast.ImportFrom):
            if (node.module or '').split('.')[0] in {'cryptography', 'Crypto', 'Cryptodome', 'nacl'}:
                kind = 'encryption-import'
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == 'encrypt':
                kind = 'encryption-call'
            elif isinstance(func, ast.Name):
                if func.id == 'encrypt' and not shadowed:
                    kind = 'encryption-call'
                elif func.id in {'Fernet', 'AES', 'AESGCM', 'ChaCha20Poly1305', 'Cipher'}:
                    kind = 'encryption-call'
        if kind:
            result.add((path, node.lineno, kind))
    return [dict(path=p, line=line, kind=kind) for p, line, kind in sorted(result)]


def audit(root, ignore=()):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError('audit root must be a directory')
    claims, production, testonly, errors = [], [], [], []
    source_count = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink()
                         and d not in {'.git', '__pycache__', '.venv', 'venv', 'build', 'dist'}
                         and not d.endswith('.egg-info')
                         and not any(fnmatch.fnmatch((Path(directory) / d).relative_to(root).as_posix(), g) for g in ignore))
        for name in sorted(files):
            file = Path(directory) / name
            rel = file.relative_to(root).as_posix()
            parts = file.relative_to(root).parts
            if file.is_symlink() or name == '.env' or name.startswith('.env.') or any(fnmatch.fnmatch(rel, g) for g in ignore):
                continue
            is_doc = rel == 'README.md' or (parts[0] == 'docs' and name.endswith('.md'))
            is_source = name.endswith('.py') and not (set(parts[:-1]) & EXCLUDED)
            if not (is_doc or is_source):
                continue
            try:
                text = file.read_text(encoding='utf-8')
                if is_doc:
                    claims.extend(extract_claims(text, rel))
                if is_source:
                    is_test = bool(set(parts[:-1]) & TEST_DIRS) or name.startswith('test_') or name.endswith('_test.py')
                    if not is_test:
                        source_count += 1
                    evidence = extract_evidence(text, rel)
                    (testonly if is_test else production).extend(evidence)
            except (OSError, UnicodeError, SyntaxError) as exc:
                errors.append({'path': rel, 'error': str(exc)})
    findings, verified = [], []
    for family in PHRASES:
        family_claims = [c for c in claims if c['family'] == family]
        if not family_claims:
            continue
        evidence, severity, suffix, note = [], 'HIGH', '', ''
        if not source_count:
            evidence = [{'kind': 'no-source'}]
            note = 'no production Python source'
        elif family == 'encrypted' and production:
            verified.append({'family': family, 'claims': family_claims, 'evidence': production})
            continue
        elif family == 'plaintext' and production:
            evidence = production
        elif testonly:
            evidence, severity, suffix = testonly, 'MEDIUM', '-test-only'
        elif family == 'plaintext':
            verified.append({'family': family, 'claims': family_claims, 'evidence': []})
            continue
        else:
            note = 'no encryption evidence'
        findings.append({'rule': 'documented-' + family + '-claim-false' + suffix,
                         'severity': severity, 'claims': family_claims, 'evidence': evidence, 'note': note})
    return {'claims': claims, 'findings': findings, 'verified_claims': verified,
            'errors': errors, 'production_evidence': production, 'test_only_evidence': testonly}
