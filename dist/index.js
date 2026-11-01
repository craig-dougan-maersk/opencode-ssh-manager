import fsSync from "node:fs";
import path from "node:path";
import { Plugin } from "@opencode/plugin";
import { expandPath, loadConfig, mutateProjectConfig, normalizeProjectConfig, projectConfigPath, globalConfigPath, validateKeyId, validateProfileName, } from "./config.js";
import { agentStatus, cleanupRuntime, clearAgent, fingerprintOfKeyFile, listLoadedKeys, projectRuntimeDir, readKeyCache, startAgent, stopAgent, unloadByPublicKey, writeKeyCache, } from "./agent.js";
import { loadKey } from "./keys.js";
import { vaultEntries, vaultGet } from "./env-manager.js";
import { SshManager } from "./rpc.js";
export default Plugin.define({
    id: "ssh.manager",
    async setup(ctx) {
        const directory = path.resolve(ctx.location.directory);
        const runtime = { paused: false };
        const ensured = new Set();
        let registration;
        const rpcCall = (definition) => ctx.rpc(definition);
        const vaultOptions = { rpc: rpcCall, directory };
        function storageKey(sessionID) {
            return `ssh:session:${directory}:${sessionID}`;
        }
        async function currentConfig() {
            return loadConfig(directory);
        }
        async function sessionProfile(config, sessionID) {
            if (!sessionID)
                return config.defaultProfile;
            try {
                const stored = await ctx.storage.get(storageKey(sessionID));
                if (typeof stored?.profile === "string" && config.profiles[stored.profile])
                    return stored.profile;
            }
            catch {
                // A missing or unreadable selection simply falls back to the default.
            }
            return config.defaultProfile;
        }
        async function notify() {
            try {
                await registration?.events.emit("changed", { directory });
            }
            catch {
                // Status events are best effort.
            }
        }
        async function refreshActive(config) {
            try {
                const status = await agentStatus(directory, config.agent, runtime.paused);
                runtime.activeSocket = status.running ? status.socket : undefined;
                runtime.activePid = status.running ? status.pid : undefined;
            }
            catch {
                runtime.activeSocket = undefined;
                runtime.activePid = undefined;
            }
        }
        async function collectVaultValues(key) {
            const entries = [];
            if (key.source === "vault" && key.entry)
                entries.push(key.entry);
            if (key.passphraseEntry)
                entries.push(key.passphraseEntry);
            if (!entries.length)
                return {};
            const result = await vaultGet(vaultOptions, entries);
            if (result.missing.length) {
                throw new Error(`Vault entr${result.missing.length === 1 ? "y" : "ies"} not found: ${result.missing.join(", ")}`);
            }
            return result.values;
        }
        async function loadConfiguredKey(config, keyID) {
            const key = config.keys[keyID];
            if (!key)
                throw new Error(`Unknown key: ${keyID}`);
            const runtimeDir = await projectRuntimeDir(directory);
            const values = await collectVaultValues(key);
            const socket = await ensureAgent(config.agent);
            const result = await loadKey({
                agent: config.agent,
                socket,
                runtimeDir,
                directory,
                key,
                vaultValues: values,
            });
            const cache = await readKeyCache(runtimeDir);
            cache[keyID] = result.fingerprint;
            await writeKeyCache(runtimeDir, cache);
            return result.fingerprint;
        }
        async function ensureAgent(config) {
            runtime.paused = false;
            const started = await startAgent(directory, config, (warning) => {
                runtime.lastError = warning;
            });
            runtime.activeSocket = started.socket;
            runtime.activePid = started.pid;
            return started.socket;
        }
        async function ensureProfileKeys(config, sessionID, manual) {
            const name = await sessionProfile(config, sessionID);
            if (!name)
                return [];
            if (runtime.paused && !manual)
                return [];
            const profile = config.profiles[name];
            if (!profile)
                return [];
            const warnings = [];
            const runtimeDir = await projectRuntimeDir(directory);
            const socket = await ensureAgent(config.agent);
            const live = await listLoadedKeys(config.agent, socket);
            const liveSet = new Set(live.map((key) => key.fingerprint).filter(Boolean));
            const cache = await readKeyCache(runtimeDir);
            for (const keyID of profile.keys) {
                const key = config.keys[keyID];
                if (!key) {
                    warnings.push(`Profile "${name}" references missing key "${keyID}"`);
                    continue;
                }
                try {
                    let fingerprint = cache[keyID];
                    if (key.source === "file" && key.path) {
                        fingerprint = (await fingerprintOfKeyFile(config.agent, expandPath(key.path, directory))).fingerprint;
                    }
                    if (fingerprint && liveSet.has(fingerprint))
                        continue;
                    const values = await collectVaultValues(key);
                    const loaded = await loadKey({
                        agent: config.agent,
                        socket,
                        runtimeDir,
                        directory,
                        key,
                        vaultValues: values,
                    });
                    cache[keyID] = loaded.fingerprint;
                    liveSet.add(loaded.fingerprint);
                }
                catch (error) {
                    warnings.push(`${keyID}: ${messageOf(error)}`);
                }
            }
            await writeKeyCache(runtimeDir, cache);
            if (warnings.length)
                runtime.lastError = warnings.join("; ");
            return warnings;
        }
        async function buildState(sessionID) {
            const config = await currentConfig();
            const status = await agentStatus(directory, config.agent, runtime.paused);
            if (status.running && status.socket) {
                runtime.activeSocket = status.socket;
                runtime.activePid = status.pid;
            }
            else if (!status.running) {
                runtime.activeSocket = undefined;
                runtime.activePid = undefined;
            }
            const runtimeDir = await projectRuntimeDir(directory);
            const cache = await readKeyCache(runtimeDir);
            const fingerprints = new Set();
            const keys = [];
            for (const [id, key] of Object.entries(config.keys)) {
                const item = {
                    id,
                    source: key.source,
                    label: key.label ?? id,
                    path: key.path,
                    entry: key.entry,
                    format: key.format,
                    passphraseEntry: key.passphraseEntry,
                    loaded: false,
                };
                if (key.source === "file" && key.path) {
                    try {
                        item.fingerprint = (await fingerprintOfKeyFile(config.agent, expandPath(key.path, directory))).fingerprint;
                    }
                    catch (error) {
                        item.error = messageOf(error);
                    }
                }
                else if (cache[id]) {
                    item.fingerprint = cache[id];
                }
                if (item.fingerprint) {
                    fingerprints.add(item.fingerprint);
                    item.loaded = status.loaded.some((loaded) => loaded.fingerprint === item.fingerprint);
                }
                keys.push(item);
            }
            const loadedExtras = status.loaded.filter((loaded) => loaded.fingerprint && !fingerprints.has(loaded.fingerprint));
            const activeProfile = await sessionProfile(config, sessionID);
            const profiles = Object.entries(config.profiles)
                .map(([name, profile]) => ({
                name,
                description: profile.description,
                keys: profile.keys,
                active: name === activeProfile,
                isDefault: name === config.defaultProfile,
            }))
                .sort((left, right) => left.name.localeCompare(right.name));
            return jsonSafe({
                directory,
                configPath: projectConfigPath(directory),
                globalConfigPath: globalConfigPath(),
                sessionID: sessionID ?? null,
                activeProfile,
                defaultProfile: config.defaultProfile,
                agent: status,
                keys,
                profiles,
                loadedExtras,
                warnings: config.warnings,
                lastError: runtime.lastError,
            });
        }
        const handlers = {
            state: async (input) => buildState(input?.sessionID),
            reload: async (input) => buildState(input?.sessionID),
            ensureSession: async (input) => {
                const sessionID = input?.sessionID;
                if (typeof sessionID !== "string")
                    throw new Error("A session is required");
                if (!ensured.has(sessionID)) {
                    const config = await currentConfig();
                    const profile = await sessionProfile(config, sessionID);
                    if (profile && !runtime.paused) {
                        ensured.add(sessionID);
                        try {
                            await ensureProfileKeys(config, sessionID, false);
                        }
                        catch (error) {
                            runtime.lastError = messageOf(error);
                        }
                    }
                }
                return buildState(sessionID);
            },
            start: async (input) => {
                const config = await currentConfig();
                runtime.paused = false;
                const started = await startAgent(directory, config.agent);
                runtime.activeSocket = started.socket;
                runtime.activePid = started.pid;
                if (input?.loadProfile !== false)
                    await ensureProfileKeys(config, input?.sessionID, true);
                await notify();
                return buildState(input?.sessionID);
            },
            stop: async (input) => {
                const config = await currentConfig();
                await stopAgent(directory, config.agent, { force: input?.force === true });
                runtime.paused = true;
                runtime.activeSocket = undefined;
                runtime.activePid = undefined;
                await notify();
                return buildState(input?.sessionID);
            },
            restart: async (input) => {
                const config = await currentConfig();
                runtime.paused = false;
                try {
                    await stopAgent(directory, config.agent);
                }
                catch {
                    // A stale or missing agent should not prevent a restart.
                }
                const started = await startAgent(directory, config.agent);
                runtime.activeSocket = started.socket;
                runtime.activePid = started.pid;
                if (input?.loadProfile !== false)
                    await ensureProfileKeys(config, input?.sessionID, true);
                await notify();
                return buildState(input?.sessionID);
            },
            setSessionProfile: async (input) => {
                const config = await currentConfig();
                const name = validateProfileName(String(input?.profile ?? ""));
                if (!config.profiles[name])
                    throw new Error(`Unknown profile: ${name}`);
                if (!input?.sessionID)
                    throw new Error("A session is required");
                await ctx.storage.set(storageKey(input.sessionID), { profile: name });
                ensured.add(input.sessionID);
                runtime.paused = false;
                await ensureProfileKeys(config, input.sessionID, true);
                await notify();
                return buildState(input.sessionID);
            },
            loadKey: async (input) => {
                const config = await currentConfig();
                const keyID = validateKeyId(String(input?.keyID ?? ""));
                await loadConfiguredKey(config, keyID);
                await notify();
                return buildState(input?.sessionID);
            },
            unloadKey: async (input) => {
                const config = await currentConfig();
                const fingerprint = String(input?.fingerprint ?? "");
                if (!fingerprint)
                    throw new Error("A fingerprint is required");
                const status = await agentStatus(directory, config.agent, runtime.paused);
                if (!status.running || !status.socket)
                    throw new Error("The SSH agent is not running");
                const loaded = status.loaded.find((key) => key.fingerprint === fingerprint);
                if (!loaded)
                    throw new Error("That key is not loaded in the agent");
                await unloadByPublicKey(config.agent, status.socket, loaded.publicKey);
                const runtimeDir = await projectRuntimeDir(directory);
                const cache = await readKeyCache(runtimeDir);
                for (const [id, value] of Object.entries(cache)) {
                    if (value === fingerprint)
                        delete cache[id];
                }
                await writeKeyCache(runtimeDir, cache);
                await notify();
                return buildState(input?.sessionID);
            },
            unloadAll: async (input) => {
                const config = await currentConfig();
                const status = await agentStatus(directory, config.agent, runtime.paused);
                if (!status.running || !status.socket)
                    throw new Error("The SSH agent is not running");
                await clearAgent(config.agent, status.socket);
                const runtimeDir = await projectRuntimeDir(directory);
                await writeKeyCache(runtimeDir, {});
                await notify();
                return buildState(input?.sessionID);
            },
            addKey: async (input) => {
                const keyID = validateKeyId(String(input?.keyID ?? ""));
                const normalized = normalizeProjectConfig({ keys: { [keyID]: input?.key } });
                const key = normalized.config.keys[keyID];
                if (!key)
                    throw new Error(normalized.warnings.join("; ") || "Invalid key");
                const profile = input?.profile ? validateProfileName(String(input.profile)) : undefined;
                const config = await currentConfig();
                if (profile && !config.profiles[profile]) {
                    // A new profile may be created on demand.
                }
                await mutateProjectConfig(directory, (project) => {
                    project.keys[keyID] = key;
                    project.disabledKeys = project.disabledKeys.filter((id) => id !== keyID);
                    if (profile) {
                        const current = config.profiles[profile]?.keys ?? [];
                        project.profiles[profile] = {
                            description: config.profiles[profile]?.description,
                            keys: [...new Set([...current, keyID])],
                        };
                    }
                });
                await notify();
                return buildState(input?.sessionID);
            },
            removeKey: async (input) => {
                const keyID = validateKeyId(String(input?.keyID ?? ""));
                const config = await currentConfig();
                await mutateProjectConfig(directory, (project) => {
                    delete project.keys[keyID];
                    if (!project.disabledKeys.includes(keyID))
                        project.disabledKeys.push(keyID);
                    for (const profile of Object.values(project.profiles)) {
                        profile.keys = profile.keys.filter((id) => id !== keyID);
                    }
                    for (const [name, profile] of Object.entries(config.profiles)) {
                        if (!profile.keys.includes(keyID))
                            continue;
                        project.profiles[name] = {
                            description: profile.description,
                            keys: profile.keys.filter((id) => id !== keyID),
                        };
                    }
                });
                await notify();
                return buildState(input?.sessionID);
            },
            saveProfile: async (input) => {
                const name = validateProfileName(String(input?.name ?? ""));
                const keys = [];
                const rawKeys = Array.isArray(input?.keys) ? input.keys : [];
                for (const id of rawKeys) {
                    if (typeof id !== "string")
                        continue;
                    const normalized = validateKeyId(id);
                    if (!keys.includes(normalized))
                        keys.push(normalized);
                }
                const config = await currentConfig();
                for (const id of keys) {
                    if (!config.keys[id])
                        throw new Error(`Unknown key: ${id}`);
                }
                await mutateProjectConfig(directory, (project) => {
                    project.profiles[name] = {
                        description: typeof input?.description === "string" ? input.description : config.profiles[name]?.description,
                        keys,
                    };
                });
                await notify();
                return buildState(input?.sessionID);
            },
            deleteProfile: async (input) => {
                const name = validateProfileName(String(input?.name ?? ""));
                const config = await currentConfig();
                if (!config.profiles[name])
                    throw new Error(`Unknown profile: ${name}`);
                await mutateProjectConfig(directory, (project) => {
                    if (!project.profiles[name]) {
                        throw new Error("That profile is defined globally; edit the global config to delete it");
                    }
                    delete project.profiles[name];
                    if (project.defaultProfile === name)
                        delete project.defaultProfile;
                });
                await notify();
                return buildState(input?.sessionID);
            },
            setDefaultProfile: async (input) => {
                const name = validateProfileName(String(input?.name ?? ""));
                const config = await currentConfig();
                if (!config.profiles[name])
                    throw new Error(`Unknown profile: ${name}`);
                await mutateProjectConfig(directory, (project) => {
                    project.defaultProfile = name;
                });
                await notify();
                return buildState(input?.sessionID);
            },
            vaultEntries: async () => jsonSafe(await vaultEntries(vaultOptions)),
        };
        registration = await ctx.rpc.register(SshManager, handlers);
        const shellHook = await ctx.shell.hook("create.before", (event) => {
            if (runtime.paused || !runtime.activeSocket)
                return;
            if (!fsSync.existsSync(runtime.activeSocket))
                return;
            event.env.SSH_AUTH_SOCK = runtime.activeSocket;
            if (runtime.activePid)
                event.env.SSH_AGENT_PID = String(runtime.activePid);
        });
        const controller = new AbortController();
        const monitor = setInterval(() => {
            void (async () => {
                try {
                    await refreshActive(await loadConfig(directory));
                }
                catch {
                    // A transient read error should not clear a working agent.
                }
            })();
        }, 60_000);
        monitor.unref?.();
        void (async () => {
            for await (const event of ctx.event.subscribe({
                types: ["session.viewed", "session.execution.started", "session.deleted"],
                signal: controller.signal,
            })) {
                const data = event.data;
                const sessionID = data?.sessionID;
                if (typeof sessionID !== "string")
                    continue;
                const location = event.location?.directory ?? data?.location?.directory;
                if (location && path.resolve(location) !== directory)
                    continue;
                if (event.type === "session.deleted") {
                    ensured.delete(sessionID);
                    await ctx.storage.remove(storageKey(sessionID)).catch(() => undefined);
                    continue;
                }
                void handlers.ensureSession({ sessionID }).catch(() => undefined);
            }
        })().catch(() => undefined);
        try {
            const config = await loadConfig(directory);
            await cleanupRuntime(directory, config.agent);
            await refreshActive(config);
        }
        catch (error) {
            console.error(`[ssh-manager] startup cleanup failed:`, error);
        }
        return () => {
            controller.abort();
            clearInterval(monitor);
            void shellHook.dispose();
            void registration?.dispose();
        };
    },
});
function messageOf(error) {
    if (error instanceof Error)
        return error.message;
    return String(error);
}
/** RPC outputs must be JSON; drop undefined object fields recursively. */
function jsonSafe(value) {
    if (Array.isArray(value))
        return value.map((item) => jsonSafe(item));
    if (value && typeof value === "object") {
        const output = {};
        for (const [key, item] of Object.entries(value)) {
            if (item !== undefined)
                output[key] = jsonSafe(item);
        }
        return output;
    }
    return value;
}
