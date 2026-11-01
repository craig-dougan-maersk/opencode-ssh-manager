import { Plugin } from "@opencode/plugin/tui"
import { createEffect, on } from "solid-js"
import { SshManager } from "./rpc.js"
import type { ProfileStatus, SessionState } from "./types.js"

export default Plugin.define({
  id: "ssh.manager.tui",
  async setup(context) {
    const client = context.client.rpc(SshManager) as any
    const ensured = new Set<string>()

    function toast(message: string, variant: "info" | "success" | "warning" | "error" = "info") {
      context.ui.toast.show({
        title: "SSH",
        message,
        variant,
        duration: variant === "error" ? 7000 : 3500,
      })
    }

    function toastError(prefix: string, error: unknown) {
      toast(`${prefix}: ${errorMessage(error)}`, "error")
    }

    function currentSessionID(): string | undefined {
      try {
        const route = context.ui.router.current()
        if (route.type === "session") return route.sessionID
      } catch {
        // The router may not be ready during early setup.
      }
      return context.ui.panel.current()?.sessionID
    }

    async function sessionLocation(sessionID?: string): Promise<any> {
      if (!sessionID) return context.location ?? context.data.location.default()
      let info = context.data.session.get(sessionID)
      if (!info) {
        await context.data.session.sync(sessionID).catch(() => undefined)
        info = context.data.session.get(sessionID)
      }
      return info?.location ?? context.location ?? context.data.location.default()
    }

    async function getState(sessionID?: string): Promise<SessionState> {
      const location = await sessionLocation(sessionID)
      return (await client.state({ sessionID }, { location })) as SessionState
    }

    async function call<T = SessionState>(method: string, input: unknown, sessionID?: string): Promise<T> {
      const location = await sessionLocation(sessionID)
      return (await client[method](input, { location })) as T
    }

    async function ensure(sessionID: string) {
      if (ensured.has(sessionID)) return
      ensured.add(sessionID)
      try {
        await call("ensureSession", { sessionID }, sessionID)
      } catch (error) {
        ensured.delete(sessionID)
        console.error("[ssh-manager] session ensure failed", error)
      }
    }

    function keyDescription(key: SessionState["keys"][number]): string {
      const parts: string[] = []
      parts.push(key.source === "vault" ? `vault ${key.entry ?? ""}` : key.path ?? "file")
      if (key.fingerprint) parts.push(key.fingerprint)
      if (key.loaded) parts.push("loaded")
      if (key.error) parts.push(`⚠ ${key.error}`)
      return parts.join(" · ")
    }

    function profileDescription(profile: ProfileStatus): string {
      const parts = [`${profile.keys.length} key${profile.keys.length === 1 ? "" : "s"}`]
      if (profile.isDefault) parts.push("default")
      if (profile.active) parts.push("active")
      if (profile.description) parts.push(profile.description)
      return parts.join(" · ")
    }

    async function showStatus(state: SessionState): Promise<void> {
      const lines: string[] = []
      lines.push(`Directory: ${state.directory}`)
      lines.push(`Config: ${state.configPath}`)
      lines.push(`Global: ${state.globalConfigPath}`)
      lines.push("")
      lines.push(`Agent: ${state.agent.running ? "running" : state.agent.stale ? "stale" : "stopped"}`)
      if (state.agent.paused) lines.push("Auto-start is paused for this OpenCode run")
      if (state.agent.socket) lines.push(`Socket: ${state.agent.socket}`)
      if (state.agent.pid) lines.push(`PID: ${state.agent.pid}`)
      if (state.agent.lifetimeSeconds) lines.push(`Lifetime: ${state.agent.lifetimeSeconds}s`)
      if (state.agent.error) lines.push(`⚠ ${state.agent.error}`)
      if (state.agent.external) {
        lines.push(
          `Inherited SSH_AUTH_SOCK: ${state.agent.external.socket} (${
            state.agent.external.reachable ? "reachable" : "not reachable"
          })`,
        )
      }
      lines.push(`Profile: ${state.activeProfile ?? "none"}`)
      lines.push("")
      lines.push(`Loaded keys (${state.agent.loaded.length}):`)
      if (!state.agent.loaded.length) lines.push("  none")
      for (const key of state.agent.loaded) {
        lines.push(`  ${key.fingerprint || "?"} ${key.comment ?? ""}`.trim())
      }
      if (state.loadedExtras.length) {
        lines.push("", "Loaded but not configured:")
        for (const key of state.loadedExtras) lines.push(`  ${key.fingerprint || "?"} ${key.comment ?? ""}`.trim())
      }
      if (state.lastError) lines.push("", `Last error: ${state.lastError}`)
      if (state.warnings.length) {
        lines.push("", "Warnings:")
        for (const warning of state.warnings) lines.push(`  ⚠ ${warning}`)
      }

      await context.ui.dialog.alert({ title: "SSH agent status", message: lines.join("\n") })
    }

    async function pickProfile(state: SessionState, title: string): Promise<string | undefined> {
      return context.ui.dialog.select({
        title,
        current: state.activeProfile,
        options: state.profiles.map((profile) => ({
          title: profile.name,
          value: profile.name,
          description: profileDescription(profile),
          category: profile.active ? "Active" : undefined,
        })),
      })
    }

    async function startAgent(sessionID: string | undefined, loadProfile: boolean) {
      const state = await call("start", { sessionID, loadProfile }, sessionID)
      if (state.lastError) {
        toast(`SSH agent started, but some keys failed: ${state.lastError}`, "warning")
      } else {
        toast(loadProfile ? "SSH agent started and profile loaded" : "SSH agent started", "success")
      }
      return state
    }

    async function stopAgent(sessionID: string | undefined) {
      const confirmed = await context.ui.dialog.confirm({
        title: "Stop SSH agent",
        message:
          "Stop the managed SSH agent? Keys disappear from the agent and commands that rely on it will fail until it is started again.",
        label: { confirm: "Stop", cancel: "Cancel" },
      })
      if (!confirmed) return false
      await call("stop", { sessionID }, sessionID)
      toast("SSH agent stopped", "warning")
      return true
    }

    async function selectProfile(sessionID: string | undefined, state: SessionState) {
      const name = await pickProfile(state, "SSH profile for this session")
      if (!name) return
      const next = await call<SessionState>("setSessionProfile", { sessionID, profile: name }, sessionID)
      if (next.lastError) {
        toast(`Profile set to ${name}, but some keys failed: ${next.lastError}`, "warning")
      } else {
        toast(`SSH profile set to ${name}`, "success")
      }
    }

    async function setDefaultProfile(state: SessionState) {
      const name = await pickProfile(state, "Default SSH profile")
      if (!name) return
      await call("setDefaultProfile", { name })
      toast(`Default SSH profile is now ${name}`, "success")
    }

    async function keyMenu(sessionID: string | undefined, state: SessionState): Promise<boolean> {
      if (!state.keys.length) {
        await context.ui.dialog.alert({
          title: "No SSH keys",
          message: "Add a key from disk or from the env-manager vault first.",
        })
        return false
      }
      const choice = await context.ui.dialog.select({
        title: "SSH keys",
        placeholder: "Search keys",
        options: [
          ...state.keys.map((key) => ({
            title: `${key.loaded ? "●" : "○"} ${key.label}`,
            value: `key:${key.id}`,
            description: keyDescription(key),
            category: key.source === "vault" ? "Vault" : "Disk",
          })),
          ...state.loadedExtras.map((key) => ({
            title: `● ${key.comment || key.fingerprint}`,
            value: `extra:${key.fingerprint}`,
            description: `${key.fingerprint} · loaded, not configured`,
            category: "Loaded extras",
          })),
          {
            title: "Unload all keys",
            value: "unload-all",
            description: "Clear every identity from the managed agent",
            category: "Actions",
          },
        ],
        search: (query, available) => {
          const needle = query.trim().toLowerCase()
          if (!needle) return available
          return available.filter(
            (option) =>
              option.title.toLowerCase().includes(needle) ||
              (option.description ?? "").toLowerCase().includes(needle),
          )
        },
      })
      if (!choice) return false

      if (choice === "unload-all") {
        const confirmed = await context.ui.dialog.confirm({
          title: "Unload all SSH keys",
          message: "Remove every identity from the managed agent?",
          label: { confirm: "Unload all", cancel: "Cancel" },
        })
        if (!confirmed) return false
        await call("unloadAll", { sessionID }, sessionID)
        toast("All keys unloaded", "warning")
        return true
      }

      if (choice.startsWith("extra:")) {
        const fingerprint = choice.slice(6)
        await call("unloadKey", { sessionID, fingerprint }, sessionID)
        toast("Key unloaded", "success")
        return true
      }

      const keyID = choice.slice(4)
      const key = state.keys.find((item) => item.id === keyID)
      if (!key) return false
      return keyActions(sessionID, state, keyID, Boolean(key.loaded))
    }

    async function keyActions(
      sessionID: string | undefined,
      state: SessionState,
      keyID: string,
      loaded: boolean,
    ): Promise<boolean> {
      const key = state.keys.find((item) => item.id === keyID)
      if (!key) return false
      const options = [
        ...(!loaded
          ? [{ title: "Load into agent", value: "load", description: keyDescription(key) }]
          : []),
        ...(loaded && key.fingerprint
          ? [{ title: "Unload from agent", value: "unload", description: key.fingerprint }]
          : []),
        { title: "Remove key from config", value: "remove", description: "Does not unload a key already in the agent" },
        { title: "Back", value: "back" },
      ]
      const action = await context.ui.dialog.select({ title: key.label, options })
      if (!action || action === "back") return false
      if (action === "load") {
        await call("loadKey", { sessionID, keyID }, sessionID)
        toast(`${key.label} loaded`, "success")
        return true
      }
      if (action === "unload") {
        if (!key.fingerprint) return false
        await call("unloadKey", { sessionID, fingerprint: key.fingerprint }, sessionID)
        toast(`${key.label} unloaded`, "success")
        return true
      }
      if (action === "remove") {
        const confirmed = await context.ui.dialog.confirm({
          title: "Remove SSH key",
          message: `Remove "${key.label}" from the config? The key in the agent is not unloaded.`,
          label: { confirm: "Remove", cancel: "Cancel" },
        })
        if (!confirmed) return false
        await call("removeKey", { keyID })
        toast(`${key.label} removed from config`, "warning")
        return true
      }
      return false
    }

    async function addFileKey(sessionID: string | undefined, state: SessionState): Promise<boolean> {
      const path = await context.ui.dialog.prompt({
        title: "Add SSH key from disk",
        description: "Private key path (~, $HOME/ and relative paths are supported)",
        placeholder: "~/.ssh/id_ed25519",
      })
      if (!path?.trim()) return false

      const suggested = path
        .split("/")
        .pop()!
        .replace(/[^A-Za-z0-9._-]+/g, "-")
        .replace(/^-+|-+$/g, "") || "key"
      const keyID = await context.ui.dialog.prompt({
        title: "Key ID",
        description: "Letters, digits, dots, dashes and underscores",
        value: suggested,
      })
      if (!keyID?.trim()) return false

      const label = await context.ui.dialog.prompt({
        title: "Key label",
        description: "Optional name shown in the menu",
        value: keyID.trim(),
      })

      let profile: string | undefined = state.activeProfile
      if (state.profiles.length) {
        const add = await context.ui.dialog.confirm({
          title: "Add to profile",
          message: state.activeProfile
            ? `Add this key to the active SSH profile "${state.activeProfile}"?`
            : "Add this key to the default profile?",
          label: { confirm: "Add to profile", cancel: "Just save" },
        })
        if (!add) profile = undefined
      }

      await call(
        "addKey",
        {
          keyID: keyID.trim(),
          key: { source: "file", path: path.trim(), label: label?.trim() || undefined },
          profile,
        },
        sessionID,
      )
      toast(`Added disk key ${keyID.trim()}`, "success")
      return true
    }

    async function vaultEntries(sessionID: string | undefined): Promise<{ ok: boolean; entries: string[]; error?: string }> {
      return (await call("vaultEntries", {}, sessionID)) as any
    }

    async function addVaultKey(sessionID: string | undefined, state: SessionState): Promise<boolean> {
      const vault = await vaultEntries(sessionID)
      if (!vault.ok) {
        const manual = await context.ui.dialog.confirm({
          title: "env-manager vault unavailable",
          message:
            vault.error ??
            "The env-manager vault could not be read. You can still type the vault entry name manually.",
          label: { confirm: "Enter entry manually", cancel: "Cancel" },
        })
        if (!manual) return false
      }

      let entry: string | undefined
      if (vault.ok && vault.entries.length) {
        entry = await context.ui.dialog.select({
          title: "Vault entry containing the private key",
          placeholder: "Search vault entries",
          options: vault.entries.map((name) => ({
            title: name,
            value: name,
            description: "Private key material",
          })),
          search: (query, available) => {
            const needle = query.trim().toLowerCase()
            if (!needle) return available
            return available.filter((option) => option.title.toLowerCase().includes(needle))
          },
        })
      } else {
        entry = await context.ui.dialog.prompt({
          title: "Vault entry containing the private key",
          description: "Exact entry name in the env-manager vault",
          placeholder: "ssh/deploy-key",
        })
      }
      if (!entry?.trim()) return false

      const suggested = entry
        .trim()
        .split("/")
        .pop()!
        .replace(/[^A-Za-z0-9._-]+/g, "-") || "vault-key"
      const keyID = await context.ui.dialog.prompt({
        title: "Key ID",
        description: "Letters, digits, dots, dashes and underscores",
        value: suggested,
      })
      if (!keyID?.trim()) return false

      let passphraseEntry: string | undefined
      if (vault.ok && vault.entries.length) {
        const choice = await context.ui.dialog.select({
          title: "Passphrase entry",
          placeholder: "Search vault entries",
          options: [
            { title: "(none)", value: "", description: "Key is not passphrase-protected" },
            ...vault.entries
              .filter((name) => name !== entry)
              .map((name) => ({ title: name, value: name, description: "Passphrase for this key" })),
          ],
          search: (query, available) => {
            const needle = query.trim().toLowerCase()
            if (!needle) return available
            return available.filter((option) => option.title.toLowerCase().includes(needle))
          },
        })
        passphraseEntry = choice || undefined
      } else {
        const answer = await context.ui.dialog.prompt({
          title: "Passphrase entry",
          description: "Optional env-manager vault entry holding the passphrase",
          placeholder: "ssh/deploy-passphrase",
        })
        passphraseEntry = answer?.trim() || undefined
      }

      let profile: string | undefined = state.activeProfile
      if (state.profiles.length) {
        const add = await context.ui.dialog.confirm({
          title: "Add to profile",
          message: state.activeProfile
            ? `Add this key to the active SSH profile "${state.activeProfile}"?`
            : "Add this key to a new profile?",
          label: { confirm: "Add to profile", cancel: "Just save" },
        })
        if (!add) profile = undefined
      }

      await call(
        "addKey",
        {
          keyID: keyID.trim(),
          key: {
            source: "vault",
            entry: entry.trim(),
            passphraseEntry,
            label: keyID.trim(),
          },
          profile,
        },
        sessionID,
      )
      toast(`Added vault key ${keyID.trim()}`, "success")
      return true
    }

    async function showVaultStatus(sessionID: string | undefined): Promise<void> {
      const vault = (await vaultEntries(sessionID)) as any
      if (!vault.ok && !vault.layers?.length) {
        await context.ui.dialog.alert({
          title: "Vault unavailable",
          message: vault.error ?? "The env-manager vault could not be read.",
        })
        return
      }
      const lines: string[] = []
      for (const [index, layer] of (vault.layers ?? []).entries()) {
        lines.push(`${index + 1}. ${layer.store ?? layer.provider}`)
        if (layer.ok) lines.push(`   ok · ${layer.entries.length} entries`)
        else if (layer.missing) lines.push("   not created yet")
        else lines.push(`   failed: ${layer.error}`)
        if (layer.ok && layer.entries.length) lines.push(`   ${layer.entries.join(", ")}`)
        for (const warning of layer.warnings ?? []) lines.push(`   ⚠ ${warning}`)
      }
      for (const warning of vault.warnings ?? []) lines.push(`⚠ ${warning}`)
      if (vault.error) lines.push(`⚠ ${vault.error}`)
      await context.ui.dialog.alert({
        title: `env-manager vault — ${(vault.entries ?? []).length} entries`,
        message: lines.join("\n") || "No vault layers configured.",
      })
    }

    async function editProfile(sessionID: string | undefined, state: SessionState): Promise<boolean> {
      const options = [
        ...state.profiles.map((profile) => ({
          title: profile.name,
          value: profile.name,
          description: profileDescription(profile),
          category: "Profiles",
        })),
        { title: "New profile…", value: "__new__", description: "Create a profile", category: "Actions" },
      ]
      let name = await context.ui.dialog.select({ title: "Edit SSH profile", options })
      if (!name) return false
      if (name === "__new__") {
        const answer = await context.ui.dialog.prompt({
          title: "New profile name",
          description: "Letters, digits, dots, dashes and underscores",
        })
        if (!answer?.trim()) return false
        name = answer.trim()
        await call("saveProfile", { name, keys: [] }, sessionID)
      }

      const current = state.profiles.find((profile) => profile.name === name)
      const selected = new Set(current?.keys ?? [])
      for (;;) {
        const options = [
          ...[...selected].map((id) => ({
            title: `✓ ${state.keys.find((key) => key.id === id)?.label ?? id}`,
            value: `remove:${id}`,
            description: "Included; select to remove",
            category: "Included",
          })),
          ...state.keys
            .filter((key) => !selected.has(key.id))
            .map((key) => ({
              title: `+ ${key.label}`,
              value: `add:${key.id}`,
              description: keyDescription(key),
              category: "Available",
            })),
          { title: "Save profile", value: "__save__", category: "Actions" },
          ...(current && state.profiles.some((profile) => profile.name === name)
            ? [{ title: "Delete profile", value: "__delete__", category: "Actions" }]
            : []),
        ]
        const action = await context.ui.dialog.select({ title: `Profile ${name}`, options })
        if (!action) return false
        if (action === "__save__") {
          await call("saveProfile", { name, keys: [...selected] }, sessionID)
          toast(`Saved profile ${name}`, "success")
          return true
        }
        if (action === "__delete__") {
          const confirmed = await context.ui.dialog.confirm({
            title: "Delete SSH profile",
            message: `Delete profile "${name}"?`,
            label: { confirm: "Delete", cancel: "Cancel" },
          })
          if (!confirmed) continue
          await call("deleteProfile", { name })
          toast(`Deleted profile ${name}`, "warning")
          return true
        }
        if (action.startsWith("remove:")) selected.delete(action.slice(7))
        if (action.startsWith("add:")) selected.add(action.slice(4))
      }
    }

    async function showMenu() {
      const sessionID = currentSessionID()
      let state = await getState(sessionID)

      const options: Array<{ title: string; value: string; description?: string; category?: string }> = []
      if (!state.agent.running) {
        options.push({
          title: "Start agent and load profile",
          value: "start",
          description: state.activeProfile ? `Profile: ${state.activeProfile}` : "No profile assigned",
          category: "Agent",
        })
        options.push({ title: "Start agent without keys", value: "start-empty", category: "Agent" })
      } else {
        options.push({
          title: "Stop agent",
          value: "stop",
          description: `${state.agent.loaded.length} keys loaded`,
          category: "Agent",
        })
        options.push({ title: "Restart agent", value: "restart", category: "Agent" })
      }
      options.push(
        {
          title: "SSH profiles…",
          value: "profiles",
          description: state.activeProfile ? `Active: ${state.activeProfile}` : "No profile assigned",
          category: "Profiles",
        },
        { title: "Set default profile…", value: "default-profile", category: "Profiles" },
        { title: "Edit profile keys…", value: "edit-profile", category: "Profiles" },
        { title: "Manage keys…", value: "keys", description: `${state.keys.length} configured`, category: "Keys" },
        { title: "Add key from disk…", value: "add-file", category: "Keys" },
        { title: "Add key from env-manager vault…", value: "add-vault", category: "Keys" },
        { title: "Vault status…", value: "vault", category: "Vault" },
        { title: "Agent status…", value: "status", category: "Agent" },
      )

      const choice = await context.ui.dialog.select({
        title: `SSH — ${state.agent.running ? "agent running" : "agent stopped"}`,
        placeholder: "Search SSH actions",
        options,
        search: (query, available) => {
          const needle = query.trim().toLowerCase()
          if (!needle) return available
          return available.filter(
            (option) =>
              option.title.toLowerCase().includes(needle) ||
              (option.description ?? "").toLowerCase().includes(needle),
          )
        },
      })
      if (!choice) return

      switch (choice) {
        case "start":
          await startAgent(sessionID, true)
          break
        case "start-empty":
          await startAgent(sessionID, false)
          break
        case "stop":
          await stopAgent(sessionID)
          break
        case "restart": {
          const next = await call<SessionState>("restart", { sessionID, loadProfile: true }, sessionID)
          if (next.lastError) toast(`SSH agent restarted, but some keys failed: ${next.lastError}`, "warning")
          else toast("SSH agent restarted", "success")
          break
        }
        case "profiles":
          state = await getState(sessionID)
          await selectProfile(sessionID, state)
          break
        case "default-profile":
          state = await getState(sessionID)
          await setDefaultProfile(state)
          break
        case "edit-profile":
          state = await getState(sessionID)
          await editProfile(sessionID, state)
          break
        case "keys":
          state = await getState(sessionID)
          await keyMenu(sessionID, state)
          break
        case "add-file":
          state = await getState(sessionID)
          await addFileKey(sessionID, state)
          break
        case "add-vault":
          state = await getState(sessionID)
          await addVaultKey(sessionID, state)
          break
        case "vault":
          await showVaultStatus(sessionID)
          break
        case "status":
          state = await getState(sessionID)
          await showStatus(state)
          break
      }

      await showMenu()
    }

    const unregisterSlot = context.ui.slot({
      append: "session.composer.top",
      render: (props) => {
        createEffect(
          on(
            () => props.sessionID,
            (sessionID) => {
              if (sessionID) void ensure(sessionID)
            },
            { defer: false },
          ),
        )
        return null as any
      },
    })

    const unsubscribeCreated = context.data.on("session.created", (event: any) => {
      const sessionID = event?.data?.sessionID
      if (typeof sessionID === "string") void ensure(sessionID)
    })

    context.keymap.layer(() => ({
      mode: "global",
      priority: 20,
      commands: [
        {
          id: "ssh.manager.menu",
          title: "SSH keys & agent",
          description: "Start or stop the SSH agent and manage keys",
          group: "SSH",
          palette: true,
          slash: { name: "ssh", aliases: ["ssh-agent"] },
          run: async () => {
            try {
              await showMenu()
            } catch (error) {
              toastError("SSH", error)
            }
          },
        },
      ],
    }))

    const sessionID = currentSessionID()
    if (sessionID) void ensure(sessionID)

    return () => {
      unregisterSlot()
      unsubscribeCreated()
    }
  },
})

function errorMessage(error: unknown): string {
  if (error && typeof error === "object" && "message" in error) return String((error as any).message)
  if (error instanceof Error) return error.message
  return String(error)
}
