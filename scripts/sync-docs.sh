#!/usr/bin/env bash
# Regenerate the docs-site pages that are derived from the repository's own
# documents, so the two cannot drift.
#
# docs/limitations.md and docs/measurements.md are the source of truth. The site
# wraps each in frontmatter and rewrites repository-relative links. Run this
# after editing either, and commit the result.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$root" <<'PY'
import re, sys, pathlib
root = pathlib.Path(sys.argv[1])
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
    dest.write_text(f'---\ntitle: {title}\ndescription: {desc}\n---\n\n:::note\n{note}\n:::\n\n' + body)
    print('  wrote', dest.relative_to(root))
PY
