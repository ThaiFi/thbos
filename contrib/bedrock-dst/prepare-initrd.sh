#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source_initrd=${1:?Pass the Nix-built podman initrd}
output=${2:-$PWD/initrd.gz}
task_stage=$(mktemp -d)
trap 'chmod -R u+w "$task_stage"; find "$task_stage" -depth -delete' EXIT
cd "$task_stage"
gzip -dc "$source_initrd" | cpio -idm --quiet
chmod u+w init
python3 - <<'PY'
from pathlib import Path
p = Path('init')
s = p.read_text()
# Podman is Go; limit its runtime without changing Tempo's five-CPU affinity.
s = s.replace('# Stage 1:', 'export GOMAXPROCS=1\n\n# Stage 1:', 1)
# Make container startup visible while image loading is still in progress.
line = next(x for x in s.splitlines() if x.startswith('journalctl -f '))
s = s.replace(line + '\n', '')
s = s.replace('bedrock-pebs-register |', line + '\necho "Tempo guest: reported CPUs=$(nproc)"\nbedrock-pebs-register |', 1)
p.write_text(s)
PY
# Stable metadata and entry order make the cached initrd reproducible.
find . -exec touch -h -d @1 {} +
LC_ALL=C find . -print0 | sort -z | cpio --null --reproducible --owner=0:0 --quiet -o -H newc | gzip -n -1 > "$output.tmp.$$"
mv "$output.tmp.$$" "$output"
