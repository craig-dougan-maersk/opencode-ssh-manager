import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import {
  agentStatus,
  cleanupRuntime,
  listLoadedKeys,
  parseFingerprintLine,
  projectRuntimeDir,
  socketPath,
  startAgent,
  stopAgent,
  unloadByPublicKey,
} from "../dist/agent.js"
import { decodeSecretStoreKey, loadKey } from "../dist/keys.js"
import { defaultAgentConfig, loadConfig, mutateProjectConfig, projectConfigPath } from "../dist/config.js"

const root = await fs.mkdtemp(path.join(os.tmpdir(), "opencode-ssh-test-"))
const project = path.join(root, "project")
const runtime = path.join(root, "runtime")
await fs.mkdir(project, { recursive: true })
process.env.XDG_RUNTIME_DIR = runtime

const keyDir = path.join(root, "keys")
await fs.mkdir(keyDir, { recursive: true, mode: 0o700 })
const keyFile = path.join(keyDir, "id_ed25519")
execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "ssh-manager-test", "-f", keyFile])

const config = defaultAgentConfig()
config.lifetimeSeconds = 120

try {
  await cleanupRuntime(project, config)
  const started = await startAgent(project, config)
  assert.ok(started.socket.startsWith(runtime), "socket should live in the test runtime dir")
  assert.ok(started.pid > 0, "agent should have a pid")

  const status = await agentStatus(project, config, false)
  assert.equal(status.running, true)
  assert.equal(status.loaded.length, 0)

  const result = await loadKey({
    agent: config,
    socket: started.socket,
    runtimeDir: await projectRuntimeDir(project),
    directory: project,
    key: { source: "file", path: keyFile },
  })
  assert.match(result.fingerprint, /^SHA256:/)

  const loaded = await listLoadedKeys(config, started.socket)
  assert.equal(loaded.length, 1)
  assert.equal(loaded[0].fingerprint, result.fingerprint)
  assert.ok(loaded[0].publicKey.startsWith("ssh-"))

  await unloadByPublicKey(config, started.socket, loaded[0].publicKey)
  assert.equal((await listLoadedKeys(config, started.socket)).length, 0)

  await stopAgent(project, config)
  await assert.rejects(fs.stat(socketPath(await projectRuntimeDir(project))))
  assert.equal((await agentStatus(project, config, false)).running, false)

  // Secret-store-sourced key material is written to a private temp file and removed.
  const storeAgent = await startAgent(project, config)
  const privateKey = await fs.readFile(keyFile, "utf8")
  const storeResult = await loadKey({
    agent: config,
    socket: storeAgent.socket,
    runtimeDir: await projectRuntimeDir(project),
    directory: project,
    key: { source: "secret-store", entry: "ssh/test-key", format: "base64" },
    secretStoreValues: { "ssh/test-key": Buffer.from(privateKey).toString("base64") },
  })
  assert.match(storeResult.fingerprint, /^SHA256:/)
  const storeLoaded = await listLoadedKeys(config, storeAgent.socket)
  assert.equal(storeLoaded.length, 1)
  const tmpEntries = await fs.readdir(path.join(await projectRuntimeDir(project), "tmp"))
  assert.deepEqual(tmpEntries, [], "secret-store key temp files should be removed")
  await unloadByPublicKey(config, storeAgent.socket, storeLoaded[0].publicKey)
  await stopAgent(project, config)

  // A passphrase-protected key can be loaded using a secret-store passphrase entry.
  // `source: "vault"` here also proves the pre-rename value is still accepted.
  const passAgent = await startAgent(project, config)
  const protectedKey = path.join(keyDir, "id_ed25519_protected")
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "correct horse", "-C", "pass-test", "-f", protectedKey])
  const protectedMaterial = await fs.readFile(protectedKey, "utf8")
  const passResult = await loadKey({
    agent: config,
    socket: passAgent.socket,
    runtimeDir: await projectRuntimeDir(project),
    directory: project,
    key: { source: "vault", entry: "ssh/pass-key", passphraseEntry: "ssh/passphrase" },
    secretStoreValues: {
      "ssh/pass-key": protectedMaterial,
      "ssh/passphrase": "correct horse",
    },
  })
  assert.match(passResult.fingerprint, /^SHA256:/)
  await stopAgent(project, config)

  // Configuration merge: project keys and profiles override global defaults.
  const parsed = parseFingerprintLine("256 SHA256:abc test key (ED25519)")
  assert.deepEqual(parsed, {
    bits: 256,
    fingerprint: "SHA256:abc",
    comment: "test key",
    type: "ED25519",
  })

  const decoded = decodeSecretStoreKey(Buffer.from("-----BEGIN OPENSSH PRIVATE KEY-----\na\n-----END OPENSSH PRIVATE KEY-----\n").toString("base64"), "base64")
  assert.match(decoded, /BEGIN OPENSSH PRIVATE KEY/)

  await fs.mkdir(path.dirname(projectConfigPath(project)), { recursive: true })
  await fs.writeFile(
    projectConfigPath(project),
    JSON.stringify({
      version: 1,
      defaultProfile: "work",
      keys: { work: { source: "file", path: keyFile, label: "Work" } },
      profiles: { work: { keys: ["work"] } },
    }),
    { mode: 0o600 },
  )
  const merged = await loadConfig(project)
  assert.equal(merged.defaultProfile, "work")
  assert.equal(merged.keys.work.label, "Work")
  assert.deepEqual(merged.profiles.work.keys, ["work"])

  await mutateProjectConfig(project, (next) => {
    next.keys.other = { source: "vault", entry: "ssh/other" }
    next.profiles.personal = { keys: ["other"] }
  })
  const changed = await loadConfig(project)
  assert.ok(changed.keys.other)
  assert.equal(changed.keys.other.source, "secret-store", "legacy source \"vault\" should normalise to \"secret-store\"")
  assert.deepEqual(changed.profiles.personal.keys, ["other"])

  // Exercise the server plugin with a minimal OpenCode-like context.
  const pluginProject = path.join(root, "plugin-project")
  await fs.mkdir(path.join(pluginProject, ".opencode"), { recursive: true })
  await fs.writeFile(
    path.join(pluginProject, ".opencode", "ssh-keys.json"),
    JSON.stringify({
      version: 1,
      defaultProfile: "work",
      keys: { work: { source: "file", path: keyFile, label: "Work" } },
      profiles: { work: { keys: ["work"] } },
    }),
    { mode: 0o600 },
  )

  let registered
  const store = new Map()
  let shellHook
  const fakeContext = {
    location: { directory: pluginProject },
    storage: {
      get: async (key) => store.get(key),
      set: async (key, value) => store.set(key, value),
      remove: async (key) => store.delete(key),
      scan: async () => ({ entries: [], next: undefined }),
    },
    rpc: Object.assign(() => {
      throw new Error("env-manager RPC should not be called by disk-key tests")
    }, {
      register: async (_definition, handlers) => {
        registered = handlers
        return { events: { emit: async () => undefined }, dispose: async () => undefined }
      },
    }),
    shell: {
      hook: async (_name, callback) => {
        shellHook = callback
        return { dispose: async () => undefined }
      },
    },
    event: {
      subscribe: () => ({
        async *[Symbol.asyncIterator]() {
          // No live events in this test.
        },
      }),
    },
    session: { get: async () => undefined },
  }

  const plugin = (await import("../dist/index.js")).default
  const cleanup = await plugin.setup(fakeContext)
  assert.ok(registered, "RPC handlers should be registered")

  let pluginState = await registered.start({ sessionID: "ses_test", loadProfile: true })
  assert.equal(pluginState.agent.running, true)
  assert.equal(pluginState.agent.loaded.length, 1)
  assert.equal(pluginState.activeProfile, "work")
  assert.equal(pluginState.keys.find((key) => key.id === "work").loaded, true)

  const hookEnv = {}
  shellHook({ command: "ssh -T git@github.com", cwd: pluginProject, timeout: 1000, shell: "bash", env: hookEnv })
  assert.equal(hookEnv.SSH_AUTH_SOCK, pluginState.agent.socket)
  assert.equal(hookEnv.SSH_AGENT_PID, String(pluginState.agent.pid))

  const fingerprint = pluginState.agent.loaded[0].fingerprint
  pluginState = await registered.unloadKey({ fingerprint })
  assert.equal(pluginState.agent.loaded.length, 0)

  pluginState = await registered.stop({})
  assert.equal(pluginState.agent.running, false)
  const pausedEnv = {}
  shellHook({ command: "ssh -T git@github.com", cwd: pluginProject, timeout: 1000, shell: "bash", env: pausedEnv })
  assert.equal(pausedEnv.SSH_AUTH_SOCK, undefined)

  pluginState = await registered.start({ loadProfile: false })
  assert.equal(pluginState.agent.running, true)
  assert.equal(pluginState.agent.loaded.length, 0)
  await registered.loadKey({ keyID: "work" })
  pluginState = await registered.state({ sessionID: "ses_test" })
  assert.equal(pluginState.agent.loaded.length, 1)

  await registered.setSessionProfile({ sessionID: "ses_test", profile: "work" })
  assert.deepEqual(store.get("ssh:session:" + pluginProject + ":ses_test"), { profile: "work" })

  await registered.stop({ force: true })
  await cleanup()

  // Exercise the TUI plugin's command registration with a minimal context.
  let tuiCommands = []
  const fakeTuiContext = {
    location: { directory: pluginProject },
    client: {
      rpc: () => ({
        state: async () => pluginState,
        ensureSession: async () => pluginState,
      }),
    },
    ui: {
      router: { current: () => ({ type: "session", sessionID: "ses_test" }) },
      panel: { current: () => undefined },
      toast: { show: () => undefined },
      dialog: {
        select: async () => undefined,
        confirm: async () => undefined,
        prompt: async () => undefined,
        alert: async () => undefined,
        clear: () => undefined,
      },
      slot: () => () => undefined,
    },
    keymap: {
      layer: (factory) => {
        const layer = factory()
        tuiCommands = layer.commands ?? []
      },
    },
    data: {
      location: { default: () => ({ directory: pluginProject }) },
      session: {
        get: () => ({ location: { directory: pluginProject } }),
        sync: async () => undefined,
      },
      on: () => () => undefined,
    },
  }
  const tuiPlugin = (await import("../dist/tui.js")).default
  const tuiCleanup = await tuiPlugin.setup(fakeTuiContext)
  assert.equal(tuiCommands.length, 1)
  assert.equal(tuiCommands[0].slash.name, "ssh")
  await tuiCommands[0].run()
  await tuiCleanup()

  console.log("all ssh-manager tests passed")
} finally {
  await stopAgent(project, config, { force: true }).catch(() => undefined)
  await fs.rm(root, { recursive: true, force: true }).catch(() => undefined)
}
