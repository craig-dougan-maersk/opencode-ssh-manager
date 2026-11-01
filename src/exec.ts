import { spawn } from "node:child_process"

export interface RunOptions {
  cwd?: string
  env?: Record<string, string | undefined>
  timeoutMs?: number
  input?: string
  maxBytes?: number
  /** Start in a new session so no controlling terminal is available. */
  detached?: boolean
}

export interface RunResult {
  file: string
  code: number | null
  signal: NodeJS.Signals | null
  stdout: string
  stderr: string
  timedOut: boolean
}

/** Run a command without a shell, capturing output and returning its exit code. */
export function run(file: string, args: readonly string[], options: RunOptions = {}): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    let child
    try {
      child = spawn(file, args, {
        cwd: options.cwd,
        env: { ...process.env, ...options.env } as NodeJS.ProcessEnv,
        stdio: ["pipe", "pipe", "pipe"],
        detached: options.detached ?? false,
      })
    } catch (error) {
      reject(error)
      return
    }

    const chunksOut: Buffer[] = []
    const chunksErr: Buffer[] = []
    const maxBytes = options.maxBytes ?? 8 * 1024 * 1024
    let size = 0
    let timedOut = false
    let settled = false

    const timer = options.timeoutMs
      ? setTimeout(() => {
          timedOut = true
          child.kill("SIGTERM")
          setTimeout(() => child.kill("SIGKILL"), 1000).unref?.()
        }, options.timeoutMs)
      : undefined

    const finish = (result: RunResult) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      resolve(result)
    }

    const fail = (error: Error) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      reject(error)
    }

    child.on("error", (error: any) => {
      if (error?.code === "ENOENT") {
        fail(new Error(`Command not found: ${file}`))
      } else {
        fail(error instanceof Error ? error : new Error(String(error)))
      }
    })

    child.stdout?.on("data", (chunk: Buffer) => {
      size += chunk.length
      if (size <= maxBytes) chunksOut.push(chunk)
      else child.kill("SIGKILL")
    })
    child.stderr?.on("data", (chunk: Buffer) => {
      size += chunk.length
      if (size <= maxBytes) chunksErr.push(chunk)
      else child.kill("SIGKILL")
    })

    child.on("close", (code, signal) => {
      finish({
        file,
        code,
        signal,
        stdout: Buffer.concat(chunksOut).toString("utf8"),
        stderr: Buffer.concat(chunksErr).toString("utf8"),
        timedOut,
      })
    })

    if (options.input !== undefined) child.stdin?.end(options.input)
    else child.stdin?.end()
  })
}

export async function runChecked(
  file: string,
  args: readonly string[],
  options: RunOptions = {},
  label = file,
): Promise<RunResult> {
  const result = await run(file, args, options)
  if (result.code !== 0) {
    throw new Error(describeFailure(result, label))
  }
  return result
}

export function describeFailure(result: RunResult, label = result.file): string {
  if (result.timedOut) return `${label} timed out`
  const stderr = result.stderr.trim()
  const stdout = result.stdout.trim()
  const detail = stderr || stdout
  return detail ? `${label} failed: ${detail}` : `${label} failed with exit code ${result.code ?? "unknown"}`
}

export function firstLine(value: string): string {
  return value.trim().split(/\r?\n/)[0] ?? ""
}
