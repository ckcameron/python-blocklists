#!/bin/sh
# Publish version-controlled manual pages without force-pushing wiki history.
# Requires authenticated Git write access and an already initialized GitHub wiki.
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -gt 1 ]; then
    echo "Usage: $0 [existing-wiki-checkout]" >&2
    exit 2
fi
if [ "$#" -eq 1 ]; then
    wiki=$(CDPATH= cd -- "$1" && pwd)
else
    workspace=$(mktemp -d)
    trap 'rm -rf "$workspace"' EXIT HUP INT TERM
    wiki="$workspace/wiki"
    git clone https://github.com/ckcameron/python-blocklists.wiki.git "$wiki" || {
        echo 'Initialize the wiki Home page on GitHub and ensure Git authentication is configured.' >&2
        exit 1
    }
fi
# Never overwrite uncommitted work or publish to an unrelated repository.
remote=$(git -C "$wiki" remote get-url origin)
case "$remote" in
    https://github.com/ckcameron/python-blocklists.wiki.git|git@github.com:ckcameron/python-blocklists.wiki.git) ;;
    *) echo 'Expected the python-blocklists wiki as origin.' >&2; exit 1 ;;
esac
if [ -n "$(git -C "$wiki" status --porcelain)" ]; then
    echo 'Wiki checkout has uncommitted changes; commit or stash them first.' >&2
    exit 1
fi
git -C "$wiki" pull --ff-only
# Repository links need .md; GitHub wiki routes use extensionless page names.
python3 - "$repo_root/docs/wiki" "$wiki" <<'PY'
from pathlib import Path
import re
import sys
source, target = map(Path, sys.argv[1:])
for page in source.glob('*.md'):
    text = re.sub(r'\]\(([A-Za-z0-9_-]+)\.md\)', r'](\1)', page.read_text())
    (target / page.name).write_text(text)
PY
# Only stage the manual pages. Preserve unrelated existing wiki pages.
for page in "$repo_root"/docs/wiki/*.md; do
    git -C "$wiki" add -- "$(basename "$page")"
done
if git -C "$wiki" diff --cached --quiet; then
    echo 'Wiki already matches docs/wiki.'
    exit 0
fi
git -C "$wiki" commit -m 'Update python-blocklists manual'
git -C "$wiki" push origin HEAD
