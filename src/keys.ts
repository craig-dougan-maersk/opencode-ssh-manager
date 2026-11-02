import fs from "node:fs/promises"
import path from "node:path"
import { expandPath } from "./config.js"
import { fingerprintOfKeyFile, keyNeedsPassphrase, tempDir } from "./agent.js"
import { describeFailure, run } from "./exec.js"
import type { AgentConfig, KeyConfig } from "./types.js"

export interface LoadKeyInput {
  agent: AgentConfig
  socket: string
  runtimeDir: string
  directory: string
  key: KeyConfig
  /** Values fetched from the env-manager secret store, keyed by entry name. */
  secretStoreValues?: Record<string, string>
}

export interface LoadedKeyResult {
  fingerprint: string
  keyPath?: string
}

export async function loadKey(input: LoadKeyInput): Promise<LoadedKeyResult> {
  const passphrase = input.key.passphraseEntry
    ? requireValue(input.secretStoreValues, input.key.passphraseEntry, "passphrase")
    : undefined

  if (input.key.source === "file") {
    if (!input.key.path) throw new Error("Key has no path")
    const file = expandPath(input.key.path, input.directory)
    const real = await validatePrivateKeyFile(file)
    const fingerprint = await fingerprintOfKeyFile(input.agent, real)
    const needsPassphrase = await keyNeedsPassphrase(input.agent, real)
    if (needsPassphrase && !passphrase) {
      throw new Error(
        `Key ${input.key.path} is passphrase-protected. Add "passphraseEntry" pointing at a secret-store entry, then load it again.`,
      )
    }
    await sshAdd(input.agent, input.socket, real, passphrase, input.runtimeDir)
    return { fingerprint: fingerprint.fingerprint, keyPath: real }
  }

  if (!input.key.entry) throw new Error("Secret-store key has no entry")
  const value = requireValue(input.secretStoreValues, input.key.entry, "private key")
  const material = decodeSecretStoreKey(value, input.key.format)
  const temp = await writeTempKey(input.runtimeDir, material)
  try {
    await validatePrivateKeyFile(temp.file)
    const fingerprint = await fingerprintOfKeyFile(input.agent, temp.file)
    const needsPassphrase = await keyNeedsPassphrase(input.agent, temp.file)
    if (needsPassphrase && !passphrase) {
      throw new Error(
        `Secret-store key ${input.key.entry} is passphrase-protected. Add "passphraseEntry" pointing at a secret-store entry, then load it again.`,
      )
    }
    await sshAdd(input.agent, input.socket, temp.file, passphrase, input.runtimeDir)
    return { fingerprint: fingerprint.fingerprint }
  } finally {
    await fs.rm(temp.dir, { recursive: true, force: true }).catch(() => undefined)
  }
}

export function decodeSecretStoreKey(value: string, format: KeyConfig["format"]): string {
  let material = value
  const trimmed = value.trim()
  if (format === "base64" || trimmed.startsWith("base64:")) {
    const payload = trimmed.startsWith("base64:") ? trimmed.slice(7) : trimmed
    try {
      material = Buffer.from(payload.replace(/\s+/g, ""), "base64").toString("utf8")
    } catch {
      throw new Error("Secret store entry is not valid base64")
    }
  }

  if (!material.trim()) throw new Error("Secret store entry is empty")
  if (material.includes("\u0000")) throw new Error("Secret store entry contains a NUL byte")
  if (!/PRIVATE KEY-----/.test(material)) {
    throw new Error(
      "Secret store entry does not contain a private key. Store the key itself, or use source \"file\" for a path.",
    )
  }
  return material.endsWith("\n") ? material : `${material}\n`
}

async function validatePrivateKeyFile(file: string): Promise<string> {
  let real: string
  try {
    real = await fs.realpath(file)
  } catch (error: any) {
    if (error?.code === "ENOENT") throw new Error(`Private key not found: ${file}`)
    throw error
  }

  const stat = await fs.stat(real)
  if (!stat.isFile()) throw new Error(`Private key is not a regular file: ${file}`)
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new Error(`Private key is not owned by the current user: ${file}`)
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(`Private key permissions are too open: ${file}. Run: chmod 600 ${file}`)
  }
  return real
}

async function writeTempKey(runtimeDir: string, material: string): Promise<{ dir: string; file: string }> {
  const dir = await fs.mkdtemp(path.join(tempDir(runtimeDir), "key-"))
  await fs.chmod(dir, 0o700)
  const file = path.join(dir, "key")
  await fs.writeFile(file, material, { mode: 0o600, flag: "wx" })
  await fs.chmod(file, 0o600)
  return { dir, file }
}

async function sshAdd(
  agent: AgentConfig,
  socket: string,
  file: string,
  passphrase: string | undefined,
  runtimeDir: string,
): Promise<void> {
  let askpass: { dir: string; file: string } | undefined
  try {
    const env: Record<string, string> = {
      SSH_AUTH_SOCK: socket,
      SSH_ASKPASS_REQUIRE: passphrase ? "force" : "never",
      DISPLAY: "",
    }
    if (passphrase) {
      askpass = await writeAskpass(runtimeDir, passphrase)
      env.SSH_ASKPASS = askpass.file
      env.OPENCODE_SSH_PASSPHRASE = passphrase
    }

    const result = await run(agent.binaries.sshAdd, [file], {
      env,
      timeoutMs: 20_000,
      detached: true,
    })
    if (result.code !== 0) {
      const detail = describeFailure(result, "ssh-add")
      if (/passphrase|incorrect|encrypted/i.test(detail)) {
        throw new Error(`${detail}. Check the key's passphraseEntry in the SSH manager config.`)
      }
      throw new Error(detail)
    }
  } finally {
    if (askpass) await fs.rm(askpass.dir, { recursive: true, force: true }).catch(() => undefined)
  }
}

async function writeAskpass(runtimeDir: string, passphrase: string): Promise<{ dir: string; file: string }> {
  const dir = await fs.mkdtemp(path.join(tempDir(runtimeDir), "askpass-"))
  await fs.chmod(dir, 0o700)
  const file = path.join(dir, "askpass.sh")
  const script = `#!/bin/sh\nprintf '%s' "$OPENCODE_SSH_PASSPHRASE"\n`
  await fs.writeFile(file, script, { mode: 0o700, flag: "wx" })
  await fs.chmod(file, 0o700)
  return { dir, file }
}

function requireValue(values: Record<string, string> | undefined, entry: string, what: string): string {
  const value = values?.[entry]
  if (value === undefined) throw new Error(`Secret store ${what} entry not found: ${entry}`)
  return value
}
