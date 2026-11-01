import fs from "node:fs/promises";
import path from "node:path";
import { expandPath } from "./config.js";
import { fingerprintOfKeyFile, keyNeedsPassphrase, tempDir } from "./agent.js";
import { describeFailure, run } from "./exec.js";
export async function loadKey(input) {
    const passphrase = input.key.passphraseEntry
        ? requireValue(input.vaultValues, input.key.passphraseEntry, "passphrase")
        : undefined;
    if (input.key.source === "file") {
        if (!input.key.path)
            throw new Error("Key has no path");
        const file = expandPath(input.key.path, input.directory);
        const real = await validatePrivateKeyFile(file);
        const fingerprint = await fingerprintOfKeyFile(input.agent, real);
        const needsPassphrase = await keyNeedsPassphrase(input.agent, real);
        if (needsPassphrase && !passphrase) {
            throw new Error(`Key ${input.key.path} is passphrase-protected. Add "passphraseEntry" pointing at a vault entry, then load it again.`);
        }
        await sshAdd(input.agent, input.socket, real, passphrase, input.runtimeDir);
        return { fingerprint: fingerprint.fingerprint, keyPath: real };
    }
    if (!input.key.entry)
        throw new Error("Vault key has no entry");
    const value = requireValue(input.vaultValues, input.key.entry, "private key");
    const material = decodeVaultKey(value, input.key.format);
    const temp = await writeTempKey(input.runtimeDir, material);
    try {
        await validatePrivateKeyFile(temp.file);
        const fingerprint = await fingerprintOfKeyFile(input.agent, temp.file);
        const needsPassphrase = await keyNeedsPassphrase(input.agent, temp.file);
        if (needsPassphrase && !passphrase) {
            throw new Error(`Vault key ${input.key.entry} is passphrase-protected. Add "passphraseEntry" pointing at a vault entry, then load it again.`);
        }
        await sshAdd(input.agent, input.socket, temp.file, passphrase, input.runtimeDir);
        return { fingerprint: fingerprint.fingerprint };
    }
    finally {
        await fs.rm(temp.dir, { recursive: true, force: true }).catch(() => undefined);
    }
}
export function decodeVaultKey(value, format) {
    let material = value;
    const trimmed = value.trim();
    if (format === "base64" || trimmed.startsWith("base64:")) {
        const payload = trimmed.startsWith("base64:") ? trimmed.slice(7) : trimmed;
        try {
            material = Buffer.from(payload.replace(/\s+/g, ""), "base64").toString("utf8");
        }
        catch {
            throw new Error("Vault entry is not valid base64");
        }
    }
    if (!material.trim())
        throw new Error("Vault entry is empty");
    if (material.includes("\u0000"))
        throw new Error("Vault entry contains a NUL byte");
    if (!/PRIVATE KEY-----/.test(material)) {
        throw new Error("Vault entry does not contain a private key. Store the key itself, or use source \"file\" for a path.");
    }
    return material.endsWith("\n") ? material : `${material}\n`;
}
async function validatePrivateKeyFile(file) {
    let real;
    try {
        real = await fs.realpath(file);
    }
    catch (error) {
        if (error?.code === "ENOENT")
            throw new Error(`Private key not found: ${file}`);
        throw error;
    }
    const stat = await fs.stat(real);
    if (!stat.isFile())
        throw new Error(`Private key is not a regular file: ${file}`);
    if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
        throw new Error(`Private key is not owned by the current user: ${file}`);
    }
    if ((stat.mode & 0o077) !== 0) {
        throw new Error(`Private key permissions are too open: ${file}. Run: chmod 600 ${file}`);
    }
    return real;
}
async function writeTempKey(runtimeDir, material) {
    const dir = await fs.mkdtemp(path.join(tempDir(runtimeDir), "key-"));
    await fs.chmod(dir, 0o700);
    const file = path.join(dir, "key");
    await fs.writeFile(file, material, { mode: 0o600, flag: "wx" });
    await fs.chmod(file, 0o600);
    return { dir, file };
}
async function sshAdd(agent, socket, file, passphrase, runtimeDir) {
    let askpass;
    try {
        const env = {
            SSH_AUTH_SOCK: socket,
            SSH_ASKPASS_REQUIRE: passphrase ? "force" : "never",
            DISPLAY: "",
        };
        if (passphrase) {
            askpass = await writeAskpass(runtimeDir, passphrase);
            env.SSH_ASKPASS = askpass.file;
            env.OPENCODE_SSH_PASSPHRASE = passphrase;
        }
        const result = await run(agent.binaries.sshAdd, [file], {
            env,
            timeoutMs: 20_000,
            detached: true,
        });
        if (result.code !== 0) {
            const detail = describeFailure(result, "ssh-add");
            if (/passphrase|incorrect|encrypted/i.test(detail)) {
                throw new Error(`${detail}. Check the key's passphraseEntry in the SSH manager config.`);
            }
            throw new Error(detail);
        }
    }
    finally {
        if (askpass)
            await fs.rm(askpass.dir, { recursive: true, force: true }).catch(() => undefined);
    }
}
async function writeAskpass(runtimeDir, passphrase) {
    const dir = await fs.mkdtemp(path.join(tempDir(runtimeDir), "askpass-"));
    await fs.chmod(dir, 0o700);
    const file = path.join(dir, "askpass.sh");
    const script = `#!/bin/sh\nprintf '%s' "$OPENCODE_SSH_PASSPHRASE"\n`;
    await fs.writeFile(file, script, { mode: 0o700, flag: "wx" });
    await fs.chmod(file, 0o700);
    return { dir, file };
}
function requireValue(values, entry, what) {
    const value = values?.[entry];
    if (value === undefined)
        throw new Error(`Vault ${what} entry not found: ${entry}`);
    return value;
}
