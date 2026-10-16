# dhcpctl — working in this checkout

The distribution is **`pydhcpctl`** (`dhcpctl` was taken on PyPI); the import
package, and any command line, is **`dhcpctl`**.

| Shipped header | Covers |
| --- | --- |
| [`src/dhcpctl/AGENTS.md`](src/dhcpctl/AGENTS.md) | the public API; it ships in the wheel |

## Layout

| Path | What |
| ---- | ---- |
| `src/dhcpctl/` | the package: private `_*.py` modules, `exceptions.py` |
| `src/dhcpctl/backends/` | one private module per backend |
| `tests/` | pytest suite; nothing here talks to a real server |
| `docs/` + `mkdocs.yml` | the documentation site |

## Environment

Per-version venvs, gitignored: `.venv/<version>-<os>-<arch>/`. Develop on the
latest Python and also run the floor from `requires-python` (3.9) before
finishing a chunk of work.

```sh
python -m venv .venv/3.14-nt-arm64
.venv/3.14-nt-arm64/Scripts/python -m pip install -e ".[dev,docs]"   # dev pulls in every backend extra
```

The Windows backend's script tests run real PowerShell, so they skip off
Windows; everything else fakes the transport at `subprocess.run`,
`requests.post` or the `pypureomapi`/`winrm` modules.

## Checks

```sh
<venv>/python -m pytest -q -rs                 # the suite (skips are visible)
<venv>/python -m black src tests               # formatter; run before committing
<venv>/python -m mkdocs build --strict         # docs must build clean
<venv>/python -m build                         # sdist + wheel
```

## Conventions

LF everywhere, enforced by `.gitattributes` (`* text=auto eol=lf`).
Warnings are errors in the test run (`filterwarnings = ["error"]`).
What a backend sends a server is part of its contract: a change to a script, a
payload or a written file is a changelog entry.

## Releasing

Three workflows: `test.yml` (`workflow_dispatch` and `ci-*` tags),
`release.yml` (`v*` tags: test, floors, build, wheel smoke, docs gate, GitHub
release, PyPI) and `docs.yml` (every Pages deploy). Bump `version` in the same
commit as the `CHANGELOG.md` entry; the release body is scraped from the
matching `## [x.y.z]` section.
