import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
export const DEFAULT_PROFILE_LIFETIME_SECONDS = 8 * 60 * 60;
export const CONFIG_DIRECTORY = ".opencode";
export const CONFIG_FILENAME = "ssh-keys.json";
const KEY_ID = /^[A-Za-z0-9._-]+$/;
const PROFILE_NAME = /^[A-Za-z0-9._-]+$/;
const ENTRY_NAME = /^[A-Za-z0-9_][A-Za-z0-9_./-]*$/;
export function projectConfigPath(directory) {
    return path.join(directory, CONFIG_DIRECTORY, CONFIG_FILENAME);
}
export function globalConfigPath() {
    const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config");
    return path.join(base, "opencode", "ssh-manager.json");
}
export function defaultAgentConfig() {
    return {
        lifetimeSeconds: DEFAULT_PROFILE_LIFETIME_SECONDS,
        binaries: {
            sshAgent: "ssh-agent",
            sshAdd: "ssh-add",
            sshKeygen: "ssh-keygen",
        },
    };
}
export function emptyProjectConfig() {
    return { version: 1, keys: {}, profiles: {}, disabledKeys: [] };
}
export function isRecord(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
export function isValidKeyId(value) {
    return KEY_ID.test(value);
}
export function isValidProfileName(value) {
    return PROFILE_NAME.test(value);
}
export function isValidEntryName(value) {
    return ENTRY_NAME.test(value);
}
export function validateKeyId(value) {
    const trimmed = value.trim();
    if (!isValidKeyId(trimmed)) {
        throw new Error("Key IDs may contain letters, digits, dots, dashes and underscores");
    }
    return trimmed;
}
export function validateProfileName(value) {
    const trimmed = value.trim();
    if (!isValidProfileName(trimmed)) {
        throw new Error("Profile names may contain letters, digits, dots, dashes and underscores");
    }
    return trimmed;
}
export function validateEntryName(value) {
    const trimmed = value.trim();
    if (!isValidEntryName(trimmed)) {
        throw new Error("Secret store entry names may contain letters, digits, dots, dashes, slashes and underscores");
    }
    return trimmed;
}
/** Expand `~`, `$HOME/`, absolute and config-relative paths. */
export function expandPath(value, configDirectory) {
    const trimmed = value.trim();
    if (trimmed === "~")
        return os.homedir();
    if (trimmed.startsWith("~/"))
        return path.join(os.homedir(), trimmed.slice(2));
    if (trimmed.startsWith("$HOME/"))
        return path.join(os.homedir(), trimmed.slice(6));
    if (path.isAbsolute(trimmed))
        return trimmed;
    return path.resolve(configDirectory, trimmed);
}
async function readJson(file) {
    let text;
    try {
        text = await fs.readFile(file, "utf8");
    }
    catch (error) {
        if (error?.code === "ENOENT")
            return { missing: true };
        return { error: `Cannot read ${file}: ${messageOf(error)}` };
    }
    try {
        return { value: JSON.parse(text.replace(/^\uFEFF/, "")) };
    }
    catch (error) {
        return { error: `Cannot parse ${file}: ${messageOf(error)}` };
    }
}
function normalizeKey(value, warnings) {
    if (!isRecord(value)) {
        warnings.push("key entry is not an object");
        return undefined;
    }
    const source = value.source === "vault" || value.source === "secret-store"
        ? "secret-store"
        : value.source === "file"
            ? "file"
            : undefined;
    if (!source) {
        warnings.push('key source must be "file" or "secret-store"');
        return undefined;
    }
    const key = { source };
    if (source === "file") {
        if (typeof value.path !== "string" || !value.path.trim()) {
            warnings.push("file key is missing path");
            return undefined;
        }
        key.path = value.path.trim();
    }
    else {
        if (typeof value.entry !== "string" || !isValidEntryName(value.entry.trim())) {
            warnings.push("secret-store key is missing a valid entry name");
            return undefined;
        }
        key.entry = value.entry.trim();
    }
    if (value.format === "base64" || value.format === "pem")
        key.format = value.format;
    if (value.passphraseEntry !== undefined) {
        if (typeof value.passphraseEntry !== "string" || !isValidEntryName(value.passphraseEntry.trim())) {
            warnings.push("passphraseEntry is not a valid secret-store entry name");
        }
        else {
            key.passphraseEntry = value.passphraseEntry.trim();
        }
    }
    if (typeof value.label === "string" && value.label.trim())
        key.label = value.label.trim();
    return key;
}
function normalizeProfile(value, warnings) {
    if (!isRecord(value)) {
        warnings.push("profile entry is not an object");
        return undefined;
    }
    const keys = Array.isArray(value.keys)
        ? [...new Set(value.keys.filter((item) => typeof item === "string" && isValidKeyId(item.trim())).map((item) => item.trim()))]
        : [];
    return {
        description: typeof value.description === "string" ? value.description : undefined,
        keys,
    };
}
function normalizeAgent(value, warnings) {
    if (!isRecord(value))
        return {};
    const result = {};
    if (value.lifetimeSeconds !== undefined) {
        if (typeof value.lifetimeSeconds === "number" &&
            Number.isFinite(value.lifetimeSeconds) &&
            value.lifetimeSeconds >= 0) {
            result.lifetimeSeconds = Math.min(Math.floor(value.lifetimeSeconds), 7 * 24 * 60 * 60);
        }
        else {
            warnings.push(`agent.lifetimeSeconds must be a non-negative number`);
        }
    }
    if (isRecord(value.binaries)) {
        const binaries = { ...defaultAgentConfig().binaries };
        for (const name of ["sshAgent", "sshAdd", "sshKeygen"]) {
            const item = value.binaries[name];
            if (typeof item === "string" && item.trim())
                binaries[name] = item.trim();
        }
        result.binaries = binaries;
    }
    return result;
}
export function normalizeProjectConfig(raw, source = "config") {
    const warnings = [];
    const data = isRecord(raw) ? raw : {};
    const keys = {};
    if (isRecord(data.keys)) {
        for (const [id, value] of Object.entries(data.keys)) {
            if (!isValidKeyId(id)) {
                warnings.push(`${source}: invalid key id "${id}"`);
                continue;
            }
            const key = normalizeKey(value, warnings);
            if (key)
                keys[id] = key;
        }
    }
    const profiles = {};
    if (isRecord(data.profiles)) {
        for (const [name, value] of Object.entries(data.profiles)) {
            if (!isValidProfileName(name)) {
                warnings.push(`${source}: invalid profile name "${name}"`);
                continue;
            }
            const profile = normalizeProfile(value, warnings);
            if (profile)
                profiles[name] = profile;
        }
    }
    const disabledKeys = Array.isArray(data.disabledKeys)
        ? [...new Set(data.disabledKeys.filter((item) => typeof item === "string" && isValidKeyId(item.trim())).map((item) => item.trim()))]
        : [];
    const config = {
        version: 1,
        keys,
        profiles,
        disabledKeys,
    };
    if (typeof data.defaultProfile === "string" && data.defaultProfile.trim()) {
        const name = data.defaultProfile.trim();
        if (isValidProfileName(name))
            config.defaultProfile = name;
        else
            warnings.push(`${source}: invalid defaultProfile "${name}"`);
    }
    const agent = normalizeAgent(data.agent, warnings);
    if (Object.keys(agent).length)
        config.agent = agent;
    return { config, warnings };
}
export async function readProjectConfig(directory) {
    const file = projectConfigPath(directory);
    const result = await readJson(file);
    if (result.missing)
        return { config: emptyProjectConfig(), warnings: [], missing: true };
    if (result.error)
        throw new Error(result.error);
    const normalized = normalizeProjectConfig(result.value, path.basename(file));
    return { config: normalized.config, warnings: normalized.warnings, missing: false };
}
export async function loadConfig(directory) {
    const warnings = [];
    const globalResult = await readJson(globalConfigPath());
    if (globalResult.error)
        warnings.push(globalResult.error);
    const global = globalResult.error
        ? { config: emptyProjectConfig(), warnings: [] }
        : normalizeProjectConfig(globalResult.value ?? {}, "ssh-manager.json");
    warnings.push(...global.warnings);
    const projectResult = await readJson(projectConfigPath(directory));
    if (projectResult.error)
        warnings.push(projectResult.error);
    const project = projectResult.error
        ? { config: emptyProjectConfig(), warnings: [] }
        : normalizeProjectConfig(projectResult.value ?? {}, path.basename(projectConfigPath(directory)));
    warnings.push(...project.warnings);
    const disabled = new Set(global.config.disabledKeys);
    for (const id of project.config.disabledKeys)
        disabled.add(id);
    for (const id of [...disabled]) {
        if (project.config.keys[id])
            disabled.delete(id);
    }
    const keys = {};
    for (const [id, key] of Object.entries(global.config.keys)) {
        if (!disabled.has(id))
            keys[id] = key;
    }
    for (const [id, key] of Object.entries(project.config.keys))
        keys[id] = key;
    const profiles = {
        ...global.config.profiles,
        ...project.config.profiles,
    };
    const base = defaultAgentConfig();
    const globalAgent = global.config.agent ?? {};
    const projectAgent = project.config.agent ?? {};
    const agent = {
        lifetimeSeconds: projectAgent.lifetimeSeconds ?? globalAgent.lifetimeSeconds ?? base.lifetimeSeconds,
        binaries: {
            ...base.binaries,
            ...(globalAgent.binaries ?? {}),
            ...(projectAgent.binaries ?? {}),
        },
    };
    let defaultProfile = project.config.defaultProfile ?? global.config.defaultProfile;
    if (defaultProfile && !profiles[defaultProfile]) {
        warnings.push(`defaultProfile "${defaultProfile}" does not exist`);
        defaultProfile = undefined;
    }
    for (const [name, profile] of Object.entries(profiles)) {
        for (const id of profile.keys) {
            if (!keys[id])
                warnings.push(`profile "${name}" references missing key "${id}"`);
        }
    }
    return {
        version: 1,
        defaultProfile,
        agent,
        keys,
        profiles,
        disabledKeys: [...disabled],
        warnings,
    };
}
export async function writeProjectConfig(directory, config) {
    const file = projectConfigPath(directory);
    await fs.mkdir(path.dirname(file), { recursive: true });
    const temporary = `${file}.tmp-${process.pid}-${Date.now()}`;
    try {
        await fs.writeFile(temporary, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
        await fs.chmod(temporary, 0o600);
        await fs.rename(temporary, file);
    }
    catch (error) {
        await fs.unlink(temporary).catch(() => undefined);
        throw error;
    }
}
export async function mutateProjectConfig(directory, change) {
    const { config } = await readProjectConfig(directory);
    const next = structuredClone(config);
    await change(next);
    next.version = 1;
    // Drop empty optional fields so the file stays readable.
    if (!next.defaultProfile)
        delete next.defaultProfile;
    if (next.agent && !next.agent.lifetimeSeconds && !next.agent.binaries)
        delete next.agent;
    for (const [id, key] of Object.entries(next.keys)) {
        if (key.source === "file" && !key.path)
            delete next.keys[id];
        if (key.source === "secret-store" && !key.entry)
            delete next.keys[id];
    }
    await writeProjectConfig(directory, next);
    return next;
}
function messageOf(error) {
    if (error instanceof Error)
        return error.message;
    return String(error);
}
