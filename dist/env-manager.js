import { Rpc } from "@opencode/plugin/rpc";
const stringArray = { type: "array", items: { type: "string" }, maxItems: 128 };
const object = { type: "object", additionalProperties: true };
/**
 * Client-side view of the env-manager RPC. Only the methods this plugin uses
 * are listed; the server resolves the call by id and method name.
 */
export const EnvManager = Rpc.define({
    id: "env.manager",
    events: {},
    methods: {
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
function friendlyError(error) {
    const value = error;
    const type = value?.type;
    const message = value?.message ?? (error instanceof Error ? error.message : String(error));
    if (type === "rpc.method_not_found" || /method.*not found/i.test(message)) {
        return new Error("env-manager does not provide vaultGet. Update opencode-env-manager to 1.1.0 or newer to load keys from its vault.");
    }
    if (type === "rpc.unavailable" || /not (?:running|available|connected)/i.test(message)) {
        return new Error("The env-manager plugin is not available; install and enable it to use vault-backed keys.");
    }
    return new Error(`env-manager vault request failed: ${message}`);
}
async function call(options, method, input) {
    const client = options.rpc(EnvManager);
    let result;
    try {
        result = await client[method](input, { location: { directory: options.directory } });
    }
    catch (error) {
        throw friendlyError(error);
    }
    if (isRpcFailure(result))
        throw friendlyError(result);
    return result;
}
export async function vaultEntries(options) {
    try {
        const status = await call(options, "vaultStatus", {});
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
export async function vaultGet(options, entries) {
    const unique = [...new Set(entries)];
    if (!unique.length)
        return { values: {}, missing: [], warnings: [], searched: [] };
    const result = await call(options, "vaultGet", { entries: unique });
    return {
        values: result?.values && typeof result.values === "object" ? result.values : {},
        missing: Array.isArray(result?.missing) ? result.missing : [],
        warnings: Array.isArray(result?.warnings) ? result.warnings : [],
        searched: Array.isArray(result?.searched) ? result.searched : [],
    };
}
