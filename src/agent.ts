import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { spawn } from "node:child_process"
import { describeFailure, run, runChecked } from "./exec.js"
import type { AgentConfig, AgentStateFile, AgentStatus, LoadedKey } from "./types.js"

const STATE_FILE = "agent.json"
const SOCKET_FILE = "agent.sock"
const LOCK_DIR = "lock"
const TMP_DIR = "tmp"
const CACHE_FILE = "loaded.json"
const STATE_VERSION = 1

export async function projectRuntimeDir(directory: string): Promise<string> {
  const root = await runtimeRoot()
  const hash = createHash("sha256").update(path.resolve(directory)).digest("hex").slice(0, 16)
  const dir = path.join(root, hash)
  await ensurePrivateDir(dir)
  await ensurePrivateDir(path.join(dir, TMP_DIR))
  return dir
}

export async function runtimeRoot(): Promise<string> {
  const base = process.env.XDG_RUNTIME_DIR || os.tmpdir()
  const name = process.env.XDG_RUNTIME_DIR ? "opencode-ssh" : `opencode-ssh-${uid()}`
  const dir = path.join(base, name)
  await ensurePrivateDir(dir)
  return dir
}

function uid(): number {
  return typeof process.getuid === "function" ? process.getuid() : 0
}

async function ensurePrivateDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true, mode: 0o700 })
  const stat = await fs.lstat(dir)
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`${dir} is not a private directory`)
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new Error(`${dir} is not owned by the current user`)
  }
  await fs.chmod(dir, 0o700)
}

export function socketPath(runtimeDir: string): string {
  return path.join(runtimeDir, SOCKET_FILE)
}

export function statePath(runtimeDir: string): string {
  return path.join(runtimeDir, STATE_FILE)
}

export function tempDir(runtimeDir: string): string {
  return path.join(runtimeDir, TMP_DIR)
}

export async function readKeyCache(runtimeDir: string): Promise<Record<string, string>> {
  try {
    const text = await fs.readFile(path.join(runtimeDir, CACHE_FILE), "utf8")
    const raw = JSON.parse(text)
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {}
    const cache: Record<string, string> = {}
    for (const [key, value] of Object.entries(raw)) {
      if (typeof value === "string") cache[key] = value
    }
    return cache
  } catch {
    return {}
  }
}

export async function writeKeyCache(runtimeDir: string, cache: Record<string, string>): Promise<void> {
  const file = path.join(runtimeDir, CACHE_FILE)
  const temporary = `${file}.tmp-${process.pid}-${Date.now()}`
  try {
    await fs.writeFile(temporary, `${JSON.stringify(cache, null, 2)}\n`, { mode: 0o600 })
    await fs.chmod(temporary, 0o600)
    await fs.rename(temporary, file)
  } catch (error) {
    await fs.unlink(temporary).catch(() => undefined)
    throw error
  }
}

function assertSocketLength(socket: string): void {
  // Linux allows about 108 bytes; macOS about 104. Leave room for the file name.
  if (Buffer.byteLength(socket) > 100) {
    throw new Error(`SSH agent socket path is too long (${socket}). Set XDG_RUNTIME_DIR to a shorter path.`)
  }
}

export async function readState(runtimeDir: string): Promise<AgentStateFile | undefined> {
  let text: string
  try {
    text = await fs.readFile(statePath(runtimeDir), "utf8")
  } catch (error: any) {
    if (error?.code === "ENOENT") return undefined
    throw error
  }
  try {
    const raw = JSON.parse(text)
    if (
      raw?.version === STATE_VERSION &&
      raw?.owner === "opencode-ssh-manager" &&
      typeof raw.pid === "number" &&
      typeof raw.socket === "string" &&
      typeof raw.startedAt === "number"
    ) {
      return raw as AgentStateFile
    }
  } catch {
    // A corrupt state file is treated as stale.
  }
  return undefined
}

async function writeState(runtimeDir: string, state: AgentStateFile): Promise<void> {
  const file = statePath(runtimeDir)
  const temporary = `${file}.tmp-${process.pid}-${Date.now()}`
  try {
    await fs.writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 })
    await fs.chmod(temporary, 0o600)
    await fs.rename(temporary, file)
  } catch (error) {
    await fs.unlink(temporary).catch(() => undefined)
    throw error
  }
}

async function removeState(runtimeDir: string): Promise<void> {
  await fs.unlink(statePath(runtimeDir)).catch(() => undefined)
  await fs.unlink(socketPath(runtimeDir)).catch(() => undefined)
}

export function processAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (error: any) {
    return error?.code === "EPERM"
  }
}

async function socketReachable(config: AgentConfig, socket: string): Promise<boolean> {
  try {
    const result = await run(config.binaries.sshAdd, ["-l"], {
      env: { SSH_AUTH_SOCK: socket, SSH_ASKPASS_REQUIRE: "never" },
      timeoutMs: 5000,
    })
    return result.code === 0 || result.code === 1
  } catch {
    return false
  }
}

/** Verify that a live PID really is our agent for this socket. */
export async function verifyAgentProcess(pid: number, socket: string): Promise<{ ok: boolean; reason?: string }> {
  if (!processAlive(pid)) return { ok: false, reason: "process is not running" }

  try {
    const stat = await fs.readFile(`/proc/${pid}/cmdline`, "utf8")
    const args = stat.split("\u0000").filter(Boolean)
    const looksLikeAgent = args.some((arg) => path.basename(arg) === "ssh-agent" || arg.endsWith("/ssh-agent"))
    const hasSocket = args.includes(socket)
    if (!looksLikeAgent || !hasSocket) {
      return { ok: false, reason: "process command line does not match the managed ssh-agent" }
    }
    return { ok: true }
  } catch {
    // Non-Linux platforms: fall back to ps.
  }

  try {
    const result = await run("ps", ["-p", String(pid), "-o", "command="], { timeoutMs: 3000 })
    const command = result.stdout.trim()
    if (result.code !== 0 || !command.includes("ssh-agent") || !command.includes(socket)) {
      return { ok: false, reason: "process command line does not match the managed ssh-agent" }
    }
    return { ok: true }
  } catch (error) {
    return { ok: false, reason: `cannot verify process: ${messageOf(error)}` }
  }
}

interface LockInfo {
  pid?: number
}

async function lockIsStale(lock: string): Promise<boolean> {
  try {
    const stat = await fs.stat(lock)
    const info = await readLock(lock)
    if (info.pid && processAlive(info.pid)) return false
    return Date.now() - stat.mtimeMs > 3000
  } catch {
    return true
  }
}

async function readLock(lock: string): Promise<LockInfo> {
  try {
    const text = await fs.readFile(path.join(lock, "pid"), "utf8")
    const pid = Number(text.trim())
    return Number.isInteger(pid) && pid > 0 ? { pid } : {}
  } catch {
    return {}
  }
}

async function withLock<T>(runtimeDir: string, operation: () => Promise<T>, timeoutMs = 15_000): Promise<T> {
  const lock = path.join(runtimeDir, LOCK_DIR)
  const started = Date.now()
  for (;;) {
    try {
      await fs.mkdir(lock, { mode: 0o700 })
      await fs.writeFile(path.join(lock, "pid"), String(process.pid), { mode: 0o600 })
      break
    } catch (error: any) {
      if (error?.code !== "EEXIST") throw error
      if (await lockIsStale(lock)) {
        await fs.rm(lock, { recursive: true, force: true }).catch(() => undefined)
        continue
      }
      if (Date.now() - started > timeoutMs) throw new Error("Timed out waiting for the SSH agent lock")
      await sleep(100)
    }
  }

  try {
    return await operation()
  } finally {
    await fs.rm(lock, { recursive: true, force: true }).catch(() => undefined)
  }
}

export interface StartResult {
  socket: string
  pid: number
  startedAt: number
  reused: boolean
}

export async function startAgent(
  directory: string,
  config: AgentConfig,
  onWarning?: (message: string) => void,
): Promise<StartResult> {
  const runtimeDir = await projectRuntimeDir(directory)
  const socket = socketPath(runtimeDir)
  assertSocketLength(socket)

  return withLock(runtimeDir, async () => {
    const existing = await readState(runtimeDir)
    if (existing) {
      const alive = processAlive(existing.pid) && (await socketReachable(config, existing.socket))
      const verified = alive ? await verifyAgentProcess(existing.pid, existing.socket) : { ok: false }
      if (alive && verified.ok) {
        return {
          socket: existing.socket,
          pid: existing.pid,
          startedAt: existing.startedAt,
          reused: true,
        }
      }
      if (alive) {
        throw new Error(
          `Refusing to replace the SSH agent at PID ${existing.pid}: ` +
            `${verified.reason ?? "ownership could not be verified"}. Stop it manually or remove ${existing.socket}.`,
        )
      }
      onWarning?.("Removed stale SSH agent state")
      await removeState(runtimeDir)
    } else {
      const socketExists = await exists(socket)
      if (socketExists) {
        if (await socketReachable(config, socket)) {
          throw new Error(
            `An SSH agent socket exists at ${socket} but is not managed by this plugin. ` +
              "Stop that agent or remove the stale socket before starting a managed agent.",
          )
        }
        await fs.unlink(socket).catch(() => undefined)
      }
    }

    const args = ["-D", "-a", socket]
    if (config.lifetimeSeconds > 0) args.push("-t", String(config.lifetimeSeconds))

    let stderr = ""
    let child
    try {
      child = spawn(config.binaries.sshAgent, args, {
        detached: true,
        stdio: ["ignore", "ignore", "pipe"],
        env: { ...process.env },
      })
    } catch (error) {
      throw new Error(`Cannot start ${config.binaries.sshAgent}: ${messageOf(error)}`)
    }

    const pid = child.pid
    if (!pid) throw new Error(`Cannot start ${config.binaries.sshAgent}: no process id`)

    let exited = false
    let exitCode: number | null = null
    child.stderr?.on("data", (chunk: Buffer) => {
      if (stderr.length < 8192) stderr += chunk.toString("utf8")
    })
    child.on("error", (error: any) => {
      exited = true
      if (error?.code === "ENOENT") stderr = `Command not found: ${config.binaries.sshAgent}`
      else stderr = messageOf(error)
    })
    child.on("exit", (code) => {
      exited = true
      exitCode = code
    })

    const deadline = Date.now() + 6000
    let ready = false
    while (Date.now() < deadline) {
      if (exited) break
      if (await socketReachable(config, socket)) {
        ready = true
        break
      }
      await sleep(100)
    }

    if (!ready) {
      if (processAlive(pid)) {
        try {
          process.kill(pid, "SIGTERM")
        } catch {
          // Best effort cleanup.
        }
      }
      await fs.unlink(socket).catch(() => undefined)
      const detail = stderr.trim() || (exited ? `exit code ${exitCode ?? "unknown"}` : "socket did not appear")
      throw new Error(`Cannot start SSH agent: ${detail}`)
    }

    const startedAt = Date.now()
    await writeState(runtimeDir, {
      version: STATE_VERSION,
      owner: "opencode-ssh-manager",
      pid,
      socket,
      startedAt,
      lifetimeSeconds: config.lifetimeSeconds,
    })

    child.stderr?.destroy()
    child.unref()

    return { socket, pid, startedAt, reused: false }
  })
}

export async function stopAgent(
  directory: string,
  config: AgentConfig,
  options: { force?: boolean } = {},
): Promise<void> {
  const runtimeDir = await projectRuntimeDir(directory)
  await withLock(runtimeDir, async () => {
    const state = await readState(runtimeDir)
    const socket = socketPath(runtimeDir)

    if (!state) {
      if (await exists(socket) && (await socketReachable(config, socket))) {
        throw new Error(
          `An SSH agent is listening at ${socket} but is not managed by this plugin. ` +
            "Refusing to remove its socket.",
        )
      }
      await fs.unlink(socket).catch(() => undefined)
      return
    }

    const verified = await verifyAgentProcess(state.pid, state.socket)
    if (!verified.ok && !options.force) {
      if (!processAlive(state.pid)) {
        await removeState(runtimeDir)
        return
      }
      throw new Error(
        `Refusing to stop PID ${state.pid}: ${verified.reason ?? "ownership could not be verified"}. ` +
          "Use force stop if you are sure.",
      )
    }

    if (processAlive(state.pid)) {
      try {
        process.kill(state.pid, "SIGTERM")
      } catch (error: any) {
        if (error?.code !== "ESRCH") throw error
      }
      const deadline = Date.now() + 2500
      while (processAlive(state.pid) && Date.now() < deadline) await sleep(100)
      if (processAlive(state.pid)) {
        try {
          process.kill(state.pid, "SIGKILL")
        } catch {
          // Best effort.
        }
      }
    }

    await removeState(runtimeDir)
  })
}

export async function cleanupRuntime(directory: string, config: AgentConfig): Promise<void> {
  const runtimeDir = await projectRuntimeDir(directory)
  const state = await readState(runtimeDir)
  if (state) {
    const alive = processAlive(state.pid) && (await socketReachable(config, state.socket))
    if (!alive) {
      await removeState(runtimeDir)
    }
  } else {
    const socket = socketPath(runtimeDir)
    if (await exists(socket)) {
      if (!(await socketReachable(config, socket))) await fs.unlink(socket).catch(() => undefined)
    }
  }
  await removeOldTempFiles(runtimeDir)
}

async function removeOldTempFiles(runtimeDir: string): Promise<void> {
  const dir = tempDir(runtimeDir)
  let entries
  try {
    entries = await fs.readdir(dir, { withFileTypes: true })
  } catch {
    return
  }
  const cutoff = Date.now() - 60 * 60 * 1000
  for (const entry of entries) {
    const full = path.join(dir, entry.name)
    try {
      const stat = await fs.stat(full)
      if (stat.mtimeMs < cutoff) await fs.rm(full, { recursive: true, force: true })
    } catch {
      // Ignore a file that disappeared while cleaning.
    }
  }
}

export function parseLoadedKeys(output: string): LoadedKey[] {
  const publicKeys = output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
  return publicKeys.map((publicKey) => {
    const parts = publicKey.split(/\s+/)
    return {
      publicKey,
      fingerprint: "",
      type: parts[0],
    }
  })
}

export async function listLoadedKeys(config: AgentConfig, socket: string): Promise<LoadedKey[]> {
  const result = await run(config.binaries.sshAdd, ["-L"], {
    env: { SSH_AUTH_SOCK: socket, SSH_ASKPASS_REQUIRE: "never" },
    timeoutMs: 5000,
  })
  if (result.code === 1) {
    // Both `ssh-add -l` and `ssh-add -L` use exit 1 for a reachable agent
    // with no identities, and print the notice to stdout or stderr depending
    // on the OpenSSH version.
    return []
  }
  if (result.code !== 0) throw new Error(describeFailure(result, "ssh-add -L"))

  const keys = parseLoadedKeys(result.stdout)
  if (!keys.length) return keys

  const fingerprintResult = await run(config.binaries.sshKeygen, ["-lf", "-"], {
    input: `${keys.map((key) => key.publicKey).join("\n")}\n`,
    timeoutMs: 5000,
  })
  if (fingerprintResult.code !== 0) {
    throw new Error(describeFailure(fingerprintResult, "ssh-keygen -lf -"))
  }

  const fingerprintLines = fingerprintResult.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)

  keys.forEach((key, index) => {
    const parsed = parseFingerprintLine(fingerprintLines[index] ?? "")
    if (parsed) {
      key.bits = parsed.bits
      key.fingerprint = parsed.fingerprint
      key.comment = parsed.comment
      key.type = parsed.type ?? key.type
    }
  })
  return keys
}

export interface ParsedFingerprint {
  bits: number
  fingerprint: string
  comment?: string
  type?: string
}

export function parseFingerprintLine(line: string): ParsedFingerprint | undefined {
  const match = /^(\d+)\s+(\S+)\s*(.*?)(?:\s+\(([^)]+)\))?\s*$/.exec(line.trim())
  if (!match) return undefined
  return {
    bits: Number(match[1]),
    fingerprint: match[2]!,
    comment: match[3]?.trim() || undefined,
    type: match[4]?.trim() || undefined,
  }
}

export async function fingerprintOfKeyFile(config: AgentConfig, file: string): Promise<{ fingerprint: string; bits?: number; comment?: string; type?: string }> {
  const result = await runChecked(config.binaries.sshKeygen, ["-lf", file], { timeoutMs: 5000 }, "ssh-keygen -lf")
  const parsed = parseFingerprintLine(result.stdout.trim())
  if (!parsed) throw new Error(`Cannot read fingerprint from ${file}`)
  return parsed
}

export async function keyNeedsPassphrase(config: AgentConfig, file: string): Promise<boolean> {
  const result = await run(config.binaries.sshKeygen, ["-y", "-P", "", "-f", file], {
    timeoutMs: 5000,
    detached: true,
    env: { SSH_ASKPASS_REQUIRE: "never", DISPLAY: "" },
  })
  if (result.code === 0) return false
  return /passphrase|encrypted|incorrect|bad passphrase/i.test(`${result.stderr} ${result.stdout}`) || result.code !== 0
}

export async function agentStatus(
  directory: string,
  config: AgentConfig,
  paused: boolean,
): Promise<AgentStatus> {
  const runtimeDir = await projectRuntimeDir(directory)
  const socket = socketPath(runtimeDir)
  const state = await readState(runtimeDir)
  const status: AgentStatus = { running: false, paused, loaded: [] }

  if (state) {
    const reachable = await socketReachable(config, state.socket)
    if (reachable) {
      const verified = await verifyAgentProcess(state.pid, state.socket)
      if (verified.ok) {
        status.running = true
        status.pid = state.pid
        status.socket = state.socket
        status.startedAt = state.startedAt
        status.lifetimeSeconds = state.lifetimeSeconds
        try {
          status.loaded = await listLoadedKeys(config, state.socket)
        } catch (error) {
          status.error = messageOf(error)
        }
      } else {
        status.stale = true
        status.error = verified.reason
      }
    } else {
      status.stale = true
      status.error = "The managed SSH agent is no longer running"
    }
  } else if (await exists(socket)) {
    status.stale = true
    status.error = "An agent socket exists without plugin state"
    if (await socketReachable(config, socket)) {
      status.socket = socket
      status.running = true
      status.error = "An unmanaged agent is listening on the plugin socket"
    }
  }

  const externalSocket = process.env.SSH_AUTH_SOCK
  if (externalSocket && externalSocket !== status.socket) {
    status.external = {
      socket: externalSocket,
      reachable: await socketReachable(config, externalSocket),
    }
  }

  return status
}

export async function unloadByPublicKey(config: AgentConfig, socket: string, publicKey: string): Promise<void> {
  const result = await run(config.binaries.sshAdd, ["-d", "-"], {
    env: { SSH_AUTH_SOCK: socket, SSH_ASKPASS_REQUIRE: "never" },
    input: `${publicKey}\n`,
    timeoutMs: 5000,
  })
  if (result.code !== 0) throw new Error(describeFailure(result, "ssh-add -d"))
}

export async function clearAgent(config: AgentConfig, socket: string): Promise<void> {
  const result = await run(config.binaries.sshAdd, ["-D"], {
    env: { SSH_AUTH_SOCK: socket, SSH_ASKPASS_REQUIRE: "never" },
    timeoutMs: 5000,
  })
  if (result.code !== 0) throw new Error(describeFailure(result, "ssh-add -D"))
}

export async function exists(file: string): Promise<boolean> {
  try {
    await fs.lstat(file)
    return true
  } catch {
    return false
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function messageOf(error: unknown): string {
  if (error instanceof Error) return error.message
  return String(error)
}
