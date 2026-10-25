# encryption-claim-audit

Offline audit of documented at-rest protection promises against Python source.

A dependency-free, standard-library CLI for Python 3.9 and later. It compares
root README.md and docs/**/*.md promises with static AST evidence. It executes
no audited code, uses no network, and never opens .env contents. Findings go to
stdout; analysis errors also appear on stderr. Symlink files and directories
are skipped, keeping analysis inside the selected tree.

## Usage

```sh
python3 -m pip install .
encryption-claim-audit /path/to/project
python3 -m encryption_claim_audit /path/to/project --json
encryption-claim-audit . --ignore 'vendor/*' --ignore 'generated/*' --verbose
encryption-claim-audit . --fail-on HIGH
encryption-claim-audit --version
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m build
```

The path defaults to the current directory. Repeat --ignore for relative-path
globs; matching directories are pruned. --verbose includes all collected
claims and evidence. JSON contains claims, findings, verified_claims,
production_evidence, test_only_evidence, and errors. Each finding includes
rule, severity, claims, evidence, and note. Exit codes are 0 for passing the
selected threshold, 2 for findings at that threshold, and 1 for usage or
analysis errors. The default threshold is MEDIUM; HIGH keeps lower severity
findings visible while allowing exit 0.

## Rules table

Rule identifiers and the exact phrase vocabulary are shown below. Each family
produces at most one finding, carrying every applicable evidence item.

```text
Rule                                                  Severity  Trigger
 documented-encrypted-claim-false                      HIGH      no evidence anywhere
 documented-encrypted-claim-false-test-only            MEDIUM    test-only evidence
 documented-plaintext-claim-false                      HIGH      production evidence
 documented-plaintext-claim-false-test-only            MEDIUM    test-only evidence

Family encrypted:
 encrypted | encrypts | encryption at rest | end to end encrypted | encrypted at rest
Family plaintext:
 plaintext | plain text | unencrypted | not encrypted | no encryption
 never encrypted | does not encrypt | stored in plaintext
 stored as plain text | stored unencrypted
```

The first family is verified by production evidence. The second is verified
when there is no evidence anywhere. With no production source, each claimed
family produces a HIGH finding with no-source evidence. Contradictory families
are evaluated independently. No claims means no findings, regardless of calls.

## Named evidence table

| Evidence kind | AST match |
| --- | --- |
| encryption-import | Import or ImportFrom rooted at cryptography, Crypto, Cryptodome, or nacl; one item per statement |
| encryption-call | Attribute call with attr encrypt, or unshadowed Name call encrypt |
| encryption-call | Name call Fernet, AES, AESGCM, ChaCha20Poly1305, or Cipher |

Evidence is deduplicated by relative file, line, and kind. Production excludes
tests/ and fixtures/ directories, test_*.py and *_test.py. Their evidence is
collected separately. docs/ and examples/ are excluded entirely. Build output,
virtual environments, Git internals, bytecode caches, and package metadata
folders are skipped. Syntax and text-decoding failures are reported as analysis
errors, preventing a successful exit for incomplete analysis.

## Differentiation

- security-claim-audit checks execution safety such as eval, shell, and pickle;
  it does not compare storage-protection promises.
- privacy-claim-audit checks network and telemetry presence.
- auth-claim-audit checks the credential requirement to run.
- readonly-claim-audit checks whether filesystem writes occur.
- bandit and ruff find code issues rather than documentation promises.
- cryptography and PyNaCl documentation describe cipher libraries rather than
  checking documentation against project code.

## Honest limitations

Claims use exact phrases with word boundaries, after lowercasing, expanding
n't to not, replacing hyphens with spaces, and collapsing whitespace.
Sentences end at punctuation or paragraph boundaries; wrapped lines remain
one paragraph. Fenced code blocks are excluded; inline code counts as prose.
Negation words no, not, never, and without suppress only the first family;
they do not suppress the second family's negative formulations. Bare
“encryption” and “encrypt” are excluded. The precise bare technical terms
listed in the vocabulary do count. No optional-middle-word matching is used.

Attribute receivers are not type-inferred: any receiver's encrypt method
counts. Name encrypt is suppressed by a file-local function, class, or
parameter of that name, even in another scope. Other cipher class names are
matched literally without alias tracking. Dead code counts, including calls
in functions never invoked. Imports alone count, so evidence establishes
cipher-use existence rather than proving that every output path uses it.

hashlib, hmac, bcrypt, and argon2 perform hashing or password hashing and are
not evidence. base64, codecs, and hex encoding are not cipher protection.
String literals and comments never supply source evidence. Key-management
checks, including safe storage, rotation, and strength, are out of scope.
No data-flow, runtime, algorithm-quality, or cryptographic correctness proof
is attempted. Only Markdown in the specified locations and Python source are
examined. The tool never reads data files or follows symlinks.

MIT licensed. Fixtures ship in the source distribution.
