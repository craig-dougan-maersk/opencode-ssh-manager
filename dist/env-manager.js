import { Rpc } from "@opencode/plugin/rpc";
const stringArray = { type: "array", items: { type: "string" }, maxItems: 128 };
const object = { type: "object", additionalProperties: true };
/**
 * Client-side view of the env-manager RPC. Only the methods this plugin uses
 * are listed; the server resolves the call by id and method name. The
 * `secretStore*` names are current; the `vault*` names are the pre-rename
 * aliases and are only tried as a fallback against an older env-manager.
 */
export const EnvManager = Rpc.define({
    id: "env.manager",
    events: {},
    methods: {
        secretStoreStatus: {
            input: { type: "object", properties: {}, additionalProperties: false },
            output: object,
        },
        secretStoreGet: {
            input: {
                type: "object",
                properties: { entries: stringArray },
                required: ["entries"],
                additionalProperties: false,
            },
            output: object,
        },
        vaultStatus: {
            input: { type: "object", properties: {}, additionalProperties: false },
            output: object,
        },
        vaultGet: {
            input: {
                type: "object",
                properties: { entries: stringArray },
                required: ["entries"],
                additionalProperties: false,
            },
            output: object,
        },
    },
});
function isRpcFailure(value) {
    return (!!value &&
        typeof value === "object" &&
        typeof value.type === "string" &&
        typeof value.message === "string" &&
        !("values" in value) &&
        !("entries" in value));
}
function isMethodNotFound(value) {
    const type = value?.type;
    const message = value?.message ?? (value instanceof Error ? value.message : "");
    return type === "rpc.method_not_found" || /method.*not found/i.test(message);
}
function friendlyError(error) {
    const value = error;
    const type = value?.type;
    const message = value?.message ?? (error instanceof Error ? error.message : String(error));
    if (isMethodNotFound(value)) {
        return new Error("env-manager does not provide secretStoreGet. Update opencode-env-manager to 1.2.0 or newer to load keys from its secret store.");
    }
    if (type === "rpc.unavailable" || /not (?:running|available|connected)/i.test(message)) {
        return new Error("The env-manager plugin is not available; install and enable it to use secret-store-backed keys.");
    }
    return new Error(`env-manager secret store request failed: ${message}`);
}
async function attempt(client, method, directory, input) {
    let result;
    try {
        result = await client[method](input, { location: { directory } });
    }
    catch (error) {
        if (isMethodNotFound(error))
            return { ok: false, reason: "method_not_found" };
        throw friendlyError(error);
    }
    if (isRpcFailure(result)) {
        if (isMethodNotFound(result))
            return { ok: false, reason: "method_not_found" };
        throw friendlyError(result);
    }
    return { ok: true, value: result };
}
/**
 * Call the current method, falling back to the legacy name when the running
 * env-manager predates the rename and does not know it.
 */
async function call(options, method, legacy, input) {
    const client = options.rpc(EnvManager);
    const first = await attempt(client, method, options.directory, input);
    if (first.ok)
        return first.value;
    const second = await attempt(client, legacy, options.directory, input);
    if (second.ok)
        return second.value;
    throw friendlyError({ type: "rpc.method_not_found", message: `${method} not found` });
}
export async function secretStoreEntries(options) {
    try {
        const status = await call(options, "secretStoreStatus", "vaultStatus", {});
        return {
            ok: status?.ok === true,
            entries: Array.isArray(status?.entries) ? status.entries : [],
            layers: Array.isArray(status?.layers) ? status.layers : [],
            warnings: Array.isArray(status?.warnings) ? status.warnings : [],
        };
    }
    catch (error) {
        return {
            ok: false,
            entries: [],
            layers: [],
            warnings: [],
            error: error instanceof Error ? error.message : String(error),
        };
    }
}
export async function secretStoreGet(options, entries) {
    const unique = [...new Set(entries)];
    if (!unique.length)
        return { values: {}, missing: [], warnings: [], searched: [] };
    const result = await call(options, "secretStoreGet", "vaultGet", { entries: unique });
    return {
        values: result?.values && typeof result.values === "object" ? result.values : {},
        missing: Array.isArray(result?.missing) ? result.missing : [],
        warnings: Array.isArray(result?.warnings) ? result.warnings : [],
        searched: Array.isArray(result?.searched) ? result.searched : [],
    };
}
