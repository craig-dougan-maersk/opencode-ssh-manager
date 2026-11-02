# opencode-ssh-manager

Manage a dedicated OpenSSH agent from OpenCode. Start and stop it, load keys
from disk, and load private keys from the
[opencode-env-manager](https://github.com/craig-dougan-maersk/opencode-env-manager)
encrypted secret store. While the agent runs, every shell command started by OpenCode
receives its `SSH_AUTH_SOCK`, so `git`, `ssh`, `scp`, deploy scripts and package
managers work without extra setup.

## Install

From GitHub:

```jsonc
{
  "plugins": ["github:craig-dougan-maersk/opencode-ssh-manager"]
}
```

Or vendor a checkout and reference its path:

```bash
git clone git@github.com:craig-dougan-maersk/opencode-ssh-manager.git ~/plugins/ssh-manager
```

```jsonc
{
  "plugins": ["/home/you/plugins/ssh-manager"]
}
```

Secret-store-backed keys additionally need `opencode-env-manager` **1.2.0 or newer**,
because the SSH manager reads entries through its `secretStoreGet` RPC method (the
pre-rename `vaultGet` is tried as a fallback).
Disk-backed keys work without env-manager.

The package ships compiled JavaScript in `dist/`, including the TUI bundle, so a
GitHub install needs no build step.

After changing `src/`, rebuild and commit `dist/`:

```bash
npm install
npm run typecheck
npm run compile
```

## Usage

- Command palette: **SSH keys & agent**
- Slash command: `/ssh` (alias `/ssh-agent`)

The menu can:

- start the agent and load the session's SSH profile
- start an empty agent
- stop or restart the agent
- select the SSH profile for the current session
- set the default profile for new sessions
- edit profile key membership
- add a private key from disk
- add a private key from the env-manager secret store, optionally with a secret-store
  passphrase entry
- load/unload individual keys, or unload every key
- show agent status, loaded fingerprints, inherited `SSH_AUTH_SOCK`, and secret-store
  layer status

### Sessions and profiles

An SSH profile is a named set of key IDs. A session remembers its selected
profile. When a session is viewed, or starts its first execution in an OpenCode
run, the plugin ensures the managed agent is running and loads any missing keys
from that profile. Loading is additive: keys already in the shared agent are
left alone, so another session in the same project is not disrupted.

New sessions use `defaultProfile` when one is configured. Without a default,
nothing is loaded until you choose a profile in `/ssh`.

Explicitly stopping the agent pauses auto-loading for the rest of that OpenCode
run. Starting or restarting the agent, loading a key, or switching profiles
resumes it.

The agent is scoped to the **project directory**. Sessions and OpenCode
instances in the same directory share one agent, one socket and one set of
loaded keys. Stopping the agent affects all of them.

## Configuration

Global defaults live at:

```
~/.config/opencode/ssh-manager.json
```

Project settings live at:

```
<workdir>/.opencode/ssh-keys.json
```

Project keys and profiles override global entries with the same ID/name. The
project file is only created when you change something in the UI. The plugin
never stores private key material or passphrases in either file.

```jsonc
{
  "version": 1,
  "defaultProfile": "work",

  "agent": {
    "lifetimeSeconds": 28800,
    "binaries": {
      "sshAgent": "ssh-agent",
      "sshAdd": "ssh-add",
      "sshKeygen": "ssh-keygen"
    }
  },

  "keys": {
    "work-github": {
      "source": "file",
      "path": "~/.ssh/id_ed25519_work",
      "label": "Work GitHub"
    },
    "deploy": {
      "source": "secret-store",
      "entry": "ssh/deploy-key",
      "format": "pem",
      "passphraseEntry": "ssh/deploy-passphrase",
      "label": "Deploy key"
    }
  },

  "profiles": {
    "work": {
      "description": "Work services",
      "keys": ["work-github", "deploy"]
    },
    "personal": {
      "keys": ["personal-github"]
    }
  }
}
```

### Agent settings

- `lifetimeSeconds` is passed to `ssh-agent -t`; default `28800` (8 hours).
  `0` disables the agent's own expiry. The agent is deliberately left running
  when OpenCode exits or a plugin hot reload happens, so existing SSH sessions
  are not interrupted.
- `binaries` allows non-standard OpenSSH paths.
- Use `/ssh` → **Stop agent** to stop it explicitly.

### Key settings

- `source: "file"` requires `path`. `~`, `$HOME/`, absolute paths and paths
  relative to the project directory are supported.
- `source: "secret-store"` (the pre-rename `"vault"` is still accepted) requires
  `entry`, the env-manager secret-store entry containing
  the private key itself. `format` is `"pem"` (default) or `"base64"`.
- `passphraseEntry` is an optional env-manager secret-store entry containing the
  passphrase for an encrypted key. It is read only when the key is loaded.
- `label` is display text; it does not change the key's own comment.

Disk keys must be regular files owned by you with no group/world permission
bits. The plugin refuses a key that is readable by other users and suggests
`chmod 600`.

### Secret-store key format

The env-manager secret store holds one `NAME=value` per line. Values are literal, so
a PEM/OpenSSH private key needs `\n` escapes in a double-quoted value:

```dotenv
ssh/deploy-key="-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA...\n-----END OPENSSH PRIVATE KEY-----\n"
ssh/deploy-passphrase="correct horse battery staple"
```

Alternatively, store the key as base64 and set `"format": "base64"` in the SSH
manager config:

```bash
base64 -w0 ~/.ssh/id_ed25519
```

The value can also start with `base64:` to enable base64 decoding without
changing the config.

Private keys are never returned by a tool or written to the transcript. To load
a secret-store key, the plugin asks env-manager for the entry, writes it to a `0600`
file inside the private runtime directory, runs `ssh-add`, and deletes the file
immediately.

## Runtime state

Agent processes do not survive a machine reboot, but they do survive OpenCode
restarts and hot reloads. State is kept outside the project:

```
$XDG_RUNTIME_DIR/opencode-ssh/<project-hash>/
  agent.sock
  agent.json
  loaded.json
  tmp/
```

When `XDG_RUNTIME_DIR` is unset, a `0700` per-user directory under the system
temporary directory is used. Stale state is cleaned on the next start. The
plugin refuses to kill a process unless its command line matches the managed
`ssh-agent` and socket.

## Security model

- Config contains key paths and secret-store entry names, never key material or
  passphrases.
- `ssh-add` is run without a shell. Passphrases are supplied through a temporary
  `SSH_ASKPASS` helper via the child environment, never on the command line.
- Secret-store keys exist in plugin memory and briefly in a `0600` temp file while
  `ssh-add` reads them.
- The agent socket is owned by your user. Any process running as you can use a
  loaded key, which is the normal ssh-agent trust model.
- While the agent runs, **every** shell command gets `SSH_AUTH_SOCK`, including
  commands proposed by the model. The model cannot start or load keys (there is
  no model-facing tool), but it can use keys you have loaded. Stop the agent
  when you do not need it.
- The plugin does not stop or modify an inherited agent from your terminal. It
  starts a separate managed agent and overrides `SSH_AUTH_SOCK` only for
  OpenCode shell commands.
- `env-manager`'s `secretStoreGet` (pre-rename `vaultGet`) is a plugin-to-plugin
  API. It is not exposed as a tool, so secret-store values never reach the model.

## Limitations

- The managed agent is Unix-only (Linux, macOS, WSL). Windows' OpenSSH agent
  service is not managed.
- Only shell commands started by OpenCode receive the socket. MCP servers,
  OpenCode's internal VCS operations and already-running commands do not.
- A session opening a profile starts the agent even if you only wanted to look
  at the session. This is the resume behavior; stop the agent to pause it for
  the rest of the run.
- Keys are shared by all sessions in a project because the agent is
  project-scoped.
- If `env-manager` is missing, disabled, or older than 1.2.0, secret-store-backed keys
  fail with an actionable error. Disk-backed keys are unaffected.

## Development

```bash
npm install
npm run typecheck
npm run compile
npm test
```

`npm test` starts a real isolated `ssh-agent` under a temporary
`XDG_RUNTIME_DIR`, generates disposable keys, and exercises disk loading,
secret-store key material, passphrase loading, unload and stop. It never prints key
material.

## License

MIT
