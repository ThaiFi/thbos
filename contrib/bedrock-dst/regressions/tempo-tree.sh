# Used by regressions/build.sh (sourced): a Tempo
# source tree at a pinned revision that builds against a local reth checkout,
# in the shape the shared chef image (bedrock/tempo-chef:<tempo>-<reth>) was
# cooked from.

# tempo_tree_clone <dir> <tempo rev>: Tempo at <rev>, detached, in <dir>.
tempo_tree_clone() {
  git clone -q --filter=blob:none --no-checkout https://github.com/tempoxyz/tempo.git "$1"
  git -C "$1" checkout -q --detach "$2"
}

# tempo_tree_local_reth <dir> <reth rev>: clones reth at <rev> into <dir>/reth
# and points every reth crate of the Tempo tree at <dir> to it.
tempo_tree_local_reth() {
  local tempo=$1 rev=$2
  git clone -q --filter=blob:none --no-checkout https://github.com/paradigmxyz/reth.git "$tempo/reth"
  git -C "$tempo/reth" checkout -q --detach "$rev"
  # Point every reth crate at the local checkout. Tempo's commented patch
  # table does not list transitive crates, and Cargo must never mix local and
  # git copies of shared traits.
  sed -i 's/^exclude = \[/exclude = ["reth", /' "$tempo/Cargo.toml"
  python3 - "$tempo" <<'PY'
import pathlib, sys, tomllib
tempo = pathlib.Path(sys.argv[1])
manifest = tempo / "Cargo.toml"
text = manifest.read_text().split('# [patch."https://github.com/paradigmxyz/reth"]', 1)[0].rstrip()
crates = {}
for path in (tempo / "reth").rglob("Cargo.toml"):
    name = tomllib.loads(path.read_text()).get("package", {}).get("name")
    if name:
        crates[name] = path.parent.relative_to(tempo).as_posix()
text += '\n\n[patch."https://github.com/paradigmxyz/reth"]\n'
text += "".join(f'{n} = {{ path = "{p}" }}\n' for n, p in sorted(crates.items()))
manifest.write_text(text)
PY
  # cargo-chef's recipe omits path dependencies' sources; cook needs them.
  sed -i '/COPY --from=planner \/app\/recipe.json recipe.json/a COPY reth reth' "$tempo/Dockerfile.chef"
  sed -i '/COPY --from=planner \/app\/recipe.json recipe.json/i ENV VERGEN_IDEMPOTENT=1' "$tempo/Dockerfile.chef"
}
