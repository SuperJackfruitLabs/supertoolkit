#!/usr/bin/env bash
# Regenerate the docs-site pages that are derived from the repository's own
# documents, so the two cannot drift.
#
# docs/limitations.md and docs/measurements.md are the source of truth. The site
# wraps each in frontmatter and rewrites repository-relative links. Run this
# after editing either, and commit the result.
#
# --check writes nothing and fails if a generated page differs from what this
# would write. CI runs it (.forgejo/workflows/ci.yml, job docs), on every pull
# request, docs-only ones included.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
mode="${1:-write}"
case "$mode" in write|--check) ;; *) echo "usage: $0 [--check]" >&2; exit 2 ;; esac
python3 - "$root" "$mode" <<'PY'
import re, sys, pathlib
root = pathlib.Path(sys.argv[1])
check = sys.argv[2] == '--check'
stale = []
out_dir = root / 'docs-site/src/content/docs'

pages = [
    ('docs/limitations.md', 'Limitations',
     'What supertoolkit does not do, and why. Each entry is a decision or a measurement.',
     'This page is generated from `docs/limitations.md` in the repository. Where the two disagree, the repository wins.'),
    ('docs/measurements.md', 'What is measured',
     'Three roadmap items that read "untested" or "unproven", closed with numbers and the machine they came from.',
     'This page is generated from `docs/measurements.md` in the repository, with the machine each figure came from.'),
]
for src, title, desc, note in pages:
    body = (root / src).read_text()
    body = re.sub(r'\A# .*?\n', '', body, count=1).lstrip('\n')
    for a, b in [('(measurements.md)', '(/measurements/)'), ('(limitations.md)', '(/limitations/)')]:
        body = body.replace(a, b)
    dest = out_dir / (pathlib.Path(src).stem + '.md')
    page = f'---\ntitle: {title}\ndescription: {desc}\n---\n\n:::note\n{note}\n:::\n\n' + body
    if check:
        if not dest.exists() or dest.read_text() != page:
            stale.append(f'{dest.relative_to(root)} is not what {src} generates')
        continue
    dest.write_text(page)
    print('  wrote', dest.relative_to(root))
for line in stale:
    print(line, file=sys.stderr)
if stale:
    print('run scripts/sync-docs.sh and commit the result', file=sys.stderr)
    sys.exit(1)
if check:
    print('  generated pages are current')
PY
