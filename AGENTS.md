# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- This app runs on `splunk_input_runtime` (https://github.com/Bre77/splunk-input-runtime), not `splunklib`/
  `splunk-sdk`. `lib/requirements.txt` pins it to an exact commit archive URL with a `sha256:` hash recorded
  in a comment above it (no PyPI package exists yet, so there is no `==version` line to pin against). Bump
  both the commit and the recorded hash together when the runtime releases a new version; never point at a
  branch.
- Credential handling goes through `self.context.credentials.protect_input_fields(...)` (see
  `bin/tenable_io_audit.py`), not manual `storage_passwords` list/delete/create calls. This app has two
  secret fields, `access_key` and `secret_key`; both are passed in one `protect_input_fields` call so the
  runtime writes both credentials and masks both stanza fields in a single update, never a partial one.
  This preserves the credential identity `(owner=nobody, app=TA_tenable_io_audit, realm=<stanza name>,
  username=<field name>)` that existing installs already have - do not change that tuple without a
  captain-level decision; it strands users' stored secrets.
- `.build.sh` vendors `lib/` fresh on every build (`pip install -t lib -r lib/requirements.txt
  --no-dependencies`); `lib/` is gitignored except `lib/requirements.txt`. Do not commit vendored packages
  into `lib/` - a vendored `lib/splunklib/` tree was committed by mistake and was removed as part of the
  `splunk_input_runtime` migration. `.gitignore` has `lib/` followed by `!lib/requirements.txt`, but git
  does not apply a negation pattern to a file inside a directory that is itself excluded, so any new file
  that legitimately needs tracking under `lib/` needs `git add -f`.
- The runner (`Script.run_script`) owns `EventWriter.close()`; app code must not call it explicitly.
  `splunk_input_runtime`'s `close()` is idempotent by design, but an explicit extra call is redundant.
- `inputs.conf` declares `python.required = 3.9, 3.13` alongside `python.version = python3` for the Splunk
  3.9->3.13 transition; keep both in sync if this stanza is edited or new Python-extension stanzas are added.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
