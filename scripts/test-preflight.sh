#!/usr/bin/env bash

set -euo pipefail

readonly preflight=${1:-scripts/preflight.sh}
root=$(mktemp -d)
readonly root
trap 'rm -rf "$root"' EXIT

new_repo() {
  local name=$1
  local repo="$root/$name"
  git init -q "$repo"
  git -C "$repo" config user.name segh-validation
  git -C "$repo" config user.email segh-validation@example.invalid
  printf '%s\n' "$repo"
}

repo=$(new_repo symlink)
printf 'safe\n' > "$repo/real.txt"
ln -s real.txt "$repo/link.txt"
git -C "$repo" add real.txt link.txt
"$preflight" "$repo" > "$root/symlink.log"
[[ -f "$repo/real.txt" && ! -e "$repo/link.txt" ]]
grep -F 'Removed tracked symlink: link.txt' "$root/symlink.log" > /dev/null

repo=$(new_repo untracked)
printf 'safe\n' > "$repo/README.md"
printf 'ignored.txt\n' > "$repo/.gitignore"
git -C "$repo" add README.md .gitignore
printf 'generated\n' > "$repo/ignored.txt"
if "$preflight" "$repo" > "$root/untracked.log" 2>&1; then
  echo 'preflight accepted an ignored untracked path' >&2
  exit 1
fi
grep -F 'Rejected untracked path: ignored.txt' "$root/untracked.log" > /dev/null

repo=$(new_repo untracked-enumeration-failure)
printf 'safe\n' > "$repo/README.md"
git -C "$repo" add README.md
mkdir "$root/bin"
real_git=$(command -v git)
cat > "$root/bin/git" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${3:-} == ls-files && ${4:-} == --others && ${5:-} == -z ]]; then
  exit 42
fi
exec "$REAL_GIT" "$@"
WRAPPER
chmod +x "$root/bin/git"
if REAL_GIT="$real_git" PATH="$root/bin:$PATH" "$preflight" "$repo" > "$root/untracked-enumeration-failure.log" 2>&1; then
  echo 'preflight accepted a failed untracked-file enumeration' >&2
  exit 1
fi

repo=$(new_repo submodule)
printf 'safe\n' > "$repo/README.md"
git -C "$repo" add README.md
git -C "$repo" commit -qm fixture
commit=$(git -C "$repo" rev-parse HEAD)
git -C "$repo" update-index --add --cacheinfo 160000,"$commit",vendor/dependency
if "$preflight" "$repo" > "$root/submodule.log" 2>&1; then
  echo 'preflight accepted a tracked submodule' >&2
  exit 1
fi
grep -F 'Rejected unmaterialized submodule: vendor/dependency' "$root/submodule.log" > /dev/null

repo=$(new_repo lfs)
printf 'safe\n' > "$repo/README.md"
printf 'version https://git-lfs.github.com/spec/v1\noid sha256:%064d\nsize 1\n' 0 > "$repo/payload.bin"
git -C "$repo" add README.md payload.bin
if "$preflight" "$repo" > "$root/lfs.log" 2>&1; then
  echo 'preflight accepted an unmaterialized Git LFS pointer' >&2
  exit 1
fi
grep -F 'Rejected unmaterialized Git LFS pointer: payload.bin' "$root/lfs.log" > /dev/null

repo=$(new_repo no-exec)
printf '#!/bin/sh\ntouch executed.marker\n' > "$repo/install.sh"
chmod +x "$repo/install.sh"
printf 'safe\n' > "$repo/README.md"
git -C "$repo" add README.md install.sh
"$preflight" "$repo" > "$root/no-exec.log"
[[ ! -e "$repo/executed.marker" && ! -e executed.marker ]]

printf 'preflight boundary tests passed\n'
