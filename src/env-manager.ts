import { Rpc } from "@opencode/plugin/rpc"
import type { VaultEntriesResult } from "./types.js"

const stringArray = { type: "array", items: { type: "string" }, maxItems: 128 } as const
const object = { type: "object", additionalProperties: true } as const

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
}) as unknown as Rpc.PortableDefinition

export interface VaultGetResult {
  values: Record<string, string>
  missing: string[]
  warnings: string[]
  searched: string[]
}

interface CallOptions {
  rpc: (definition: Rpc.PortableDefinition) => any
  directory: string
}

function isRpcFailure(value: unknown): value is { type: string; message: string } {
  return (
    !!value &&
    typeof value === "object" &&
    typeof (value as any).type === "string" &&
    typeof (value as any).message === "string" &&
    !("values" in (value as any)) &&
    !("entries" in (value as any))
  )
}

function friendlyError(error: unknown): Error {
  const value = error as any
  const type = value?.type
  const message = value?.message ?? (error instanceof Error ? error.message : String(error))
  if (type === "rpc.method_not_found" || /method.*not found/i.test(message)) {
    return new Error(
      "env-manager does not provide vaultGet. Update opencode-env-manager to 1.1.0 or newer to load keys from its vault.",
    )
  }
  if (type === "rpc.unavailable" || /not (?:running|available|connected)/i.test(message)) {
    return new Error("The env-manager plugin is not available; install and enable it to use vault-backed keys.")
  }
  return new Error(`env-manager vault request failed: ${message}`)
}

async function call<T>(options: CallOptions, method: "vaultStatus" | "vaultGet", input: unknown): Promise<T> {
  const client = options.rpc(EnvManager)
  let result: unknown
  try {
    result = await client[method](input, { location: { directory: options.directory } })
  } catch (error) {
    throw friendlyError(error)
  }
  if (isRpcFailure(result)) throw friendlyError(result)
  return result as T
}

export async function vaultEntries(options: CallOptions): Promise<VaultEntriesResult> {
  try {
    const status = await call<any>(options, "vaultStatus", {})
    return {
      ok: status?.ok === true,
      entries: Array.isArray(status?.entries) ? status.entries : [],
      layers: Array.isArray(status?.layers) ? status.layers : [],
      warnings: Array.isArray(status?.warnings) ? status.warnings : [],
    }
  } catch (error) {
    return {
      ok: false,
      entries: [],
      layers: [],
      warnings: [],
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

export async function vaultGet(options: CallOptions, entries: readonly string[]): Promise<VaultGetResult> {
  const unique = [...new Set(entries)]
  if (!unique.length) return { values: {}, missing: [], warnings: [], searched: [] }
  const result = await call<VaultGetResult>(options, "vaultGet", { entries: unique })
  return {
    values: result?.values && typeof result.values === "object" ? result.values : {},
    missing: Array.isArray(result?.missing) ? result.missing : [],
    warnings: Array.isArray(result?.warnings) ? result.warnings : [],
    searched: Array.isArray(result?.searched) ? result.searched : [],
  }
}
