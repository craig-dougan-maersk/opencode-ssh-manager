import { Rpc } from "@opencode/plugin/rpc"

const string = { type: "string" } as const
const boolean = { type: "boolean" } as const
const result = { type: "object", additionalProperties: true } as const

const keyInput = {
  type: "object",
  properties: {
    source: { type: "string", enum: ["file", "vault"] },
    path: string,
    entry: string,
    format: { type: "string", enum: ["pem", "base64"] },
    passphraseEntry: string,
    label: string,
  },
  required: ["source"],
  additionalProperties: false,
} as const

export const SshManager = Rpc.define({
  id: "ssh.manager",
  events: {
    changed: {
      schema: {
        type: "object",
        properties: { directory: string },
        additionalProperties: false,
      },
    },
  },
  methods: {
    state: {
      input: {
        type: "object",
        properties: { sessionID: string, directory: string },
        additionalProperties: false,
      },
      output: result,
    },
    ensureSession: {
      input: {
        type: "object",
        properties: { sessionID: string, directory: string },
        required: ["sessionID"],
        additionalProperties: false,
      },
      output: result,
    },
    start: {
      input: {
        type: "object",
        properties: { sessionID: string, loadProfile: boolean, directory: string },
        additionalProperties: false,
      },
      output: result,
    },
    stop: {
      input: {
        type: "object",
        properties: { sessionID: string, force: boolean, directory: string },
        additionalProperties: false,
      },
      output: result,
    },
    restart: {
      input: {
        type: "object",
        properties: { sessionID: string, loadProfile: boolean, directory: string },
        additionalProperties: false,
      },
      output: result,
    },
    setSessionProfile: {
      input: {
        type: "object",
        properties: { sessionID: string, profile: string, directory: string },
        required: ["sessionID", "profile"],
        additionalProperties: false,
      },
      output: result,
    },
    loadKey: {
      input: {
        type: "object",
        properties: { sessionID: string, keyID: string, directory: string },
        required: ["keyID"],
        additionalProperties: false,
      },
      output: result,
    },
    unloadKey: {
      input: {
        type: "object",
        properties: { sessionID: string, fingerprint: string, directory: string },
        required: ["fingerprint"],
        additionalProperties: false,
      },
      output: result,
    },
    unloadAll: {
      input: {
        type: "object",
        properties: { sessionID: string, directory: string },
        additionalProperties: false,
      },
      output: result,
    },
    addKey: {
      input: {
        type: "object",
        properties: { keyID: string, key: keyInput, profile: string, directory: string },
        required: ["keyID", "key"],
        additionalProperties: false,
      },
      output: result,
    },
    removeKey: {
      input: {
        type: "object",
        properties: { keyID: string, directory: string },
        required: ["keyID"],
        additionalProperties: false,
      },
      output: result,
    },
    saveProfile: {
      input: {
        type: "object",
        properties: { name: string, description: string, keys: { type: "array", items: string }, directory: string },
        required: ["name", "keys"],
        additionalProperties: false,
      },
      output: result,
    },
    deleteProfile: {
      input: {
        type: "object",
        properties: { name: string, directory: string },
        required: ["name"],
        additionalProperties: false,
      },
      output: result,
    },
    setDefaultProfile: {
      input: {
        type: "object",
        properties: { name: string, directory: string },
        additionalProperties: false,
      },
      output: result,
    },
    vaultEntries: {
      input: {
        type: "object",
        properties: { directory: string },
        additionalProperties: false,
      },
      output: result,
    },
    reload: {
      input: {
        type: "object",
        properties: { sessionID: string, directory: string },
        additionalProperties: false,
      },
      output: result,
    },
  },
}) as unknown as Rpc.PortableDefinition
