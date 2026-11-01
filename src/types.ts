export type KeySource = "file" | "vault"
export type KeyFormat = "pem" | "base64"

export interface KeyConfig {
  source: KeySource
  path?: string
  entry?: string
  format?: KeyFormat
  passphraseEntry?: string
  label?: string
}

export interface ProfileConfig {
  description?: string
  keys: string[]
}

export interface Binaries {
  sshAgent: string
  sshAdd: string
  sshKeygen: string
}

export interface AgentConfig {
  lifetimeSeconds: number
  binaries: Binaries
}

export interface ProjectConfig {
  version: 1
  defaultProfile?: string
  agent?: Partial<AgentConfig>
  keys: Record<string, KeyConfig>
  profiles: Record<string, ProfileConfig>
  disabledKeys: string[]
}

export interface Config {
  version: 1
  defaultProfile?: string
  agent: AgentConfig
  keys: Record<string, KeyConfig>
  profiles: Record<string, ProfileConfig>
  disabledKeys: string[]
  warnings: string[]
}

export interface AgentStateFile {
  version: 1
  owner: "opencode-ssh-manager"
  pid: number
  socket: string
  startedAt: number
  lifetimeSeconds: number
}

export interface LoadedKey {
  fingerprint: string
  publicKey: string
  bits?: number
  comment?: string
  type?: string
}

export interface AgentStatus {
  running: boolean
  paused: boolean
  socket?: string
  pid?: number
  startedAt?: number
  lifetimeSeconds?: number
  stale?: boolean
  error?: string
  loaded: LoadedKey[]
  external?: {
    socket: string
    reachable: boolean
  }
}

export interface KeyStatus {
  id: string
  source: KeySource
  label: string
  path?: string
  entry?: string
  format?: KeyFormat
  passphraseEntry?: string
  fingerprint?: string
  loaded: boolean
  error?: string
}

export interface ProfileStatus {
  name: string
  description?: string
  keys: string[]
  active: boolean
  isDefault: boolean
}

export interface SessionState {
  directory: string
  configPath: string
  globalConfigPath: string
  sessionID: string | null
  activeProfile?: string
  defaultProfile?: string
  agent: AgentStatus
  keys: KeyStatus[]
  profiles: ProfileStatus[]
  loadedExtras: LoadedKey[]
  warnings: string[]
  lastError?: string
}

export interface VaultEntriesResult {
  ok: boolean
  entries: string[]
  layers: Array<{
    store?: string
    provider: string
    ok: boolean
    missing?: boolean
    entries: string[]
    warnings: string[]
    error?: string
  }>
  warnings: string[]
  error?: string
}
