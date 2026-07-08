# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- `lib/splunklib` is a vendored copy (currently 2.1.0), not pip-installed at runtime. `lib/requirements.txt`
  still declares `splunk-sdk>=2.1.1,<3` plus the app's real third-party deps (`requests`, `python-dateutil`)
  so tooling that resolves against the requirements file checks the same version line the vendored copy ships.
- `.gitignore` has `lib/` followed by `!lib/requirements.txt`, but git does not apply a negation pattern to
  a file inside a directory that is itself excluded. New files under `lib/` need `git add -f` to get staged.
- `inputs.conf` declares `python.required = 3.9, 3.13` alongside `python.version = python3` for the Splunk
  3.9->3.13 transition; keep both in sync if this stanza is edited or new Python-extension stanzas are added.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
