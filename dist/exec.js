import { spawn } from "node:child_process";
/** Run a command without a shell, capturing output and returning its exit code. */
export function run(file, args, options = {}) {
    return new Promise((resolve, reject) => {
        let child;
        try {
            child = spawn(file, args, {
                cwd: options.cwd,
                env: { ...process.env, ...options.env },
                stdio: ["pipe", "pipe", "pipe"],
                detached: options.detached ?? false,
            });
        }
        catch (error) {
            reject(error);
            return;
        }
        const chunksOut = [];
        const chunksErr = [];
        const maxBytes = options.maxBytes ?? 8 * 1024 * 1024;
        let size = 0;
        let timedOut = false;
        let settled = false;
        const timer = options.timeoutMs
            ? setTimeout(() => {
                timedOut = true;
                child.kill("SIGTERM");
                setTimeout(() => child.kill("SIGKILL"), 1000).unref?.();
            }, options.timeoutMs)
            : undefined;
        const finish = (result) => {
            if (settled)
                return;
            settled = true;
            if (timer)
                clearTimeout(timer);
            resolve(result);
        };
        const fail = (error) => {
            if (settled)
                return;
            settled = true;
            if (timer)
                clearTimeout(timer);
            reject(error);
        };
        child.on("error", (error) => {
            if (error?.code === "ENOENT") {
                fail(new Error(`Command not found: ${file}`));
            }
            else {
                fail(error instanceof Error ? error : new Error(String(error)));
            }
        });
        child.stdout?.on("data", (chunk) => {
            size += chunk.length;
            if (size <= maxBytes)
                chunksOut.push(chunk);
            else
                child.kill("SIGKILL");
        });
        child.stderr?.on("data", (chunk) => {
            size += chunk.length;
            if (size <= maxBytes)
                chunksErr.push(chunk);
            else
                child.kill("SIGKILL");
        });
        child.on("close", (code, signal) => {
            finish({
                file,
                code,
                signal,
                stdout: Buffer.concat(chunksOut).toString("utf8"),
                stderr: Buffer.concat(chunksErr).toString("utf8"),
                timedOut,
            });
        });
        if (options.input !== undefined)
            child.stdin?.end(options.input);
        else
            child.stdin?.end();
    });
}
export async function runChecked(file, args, options = {}, label = file) {
    const result = await run(file, args, options);
    if (result.code !== 0) {
        throw new Error(describeFailure(result, label));
    }
    return result;
}
export function describeFailure(result, label = result.file) {
    if (result.timedOut)
        return `${label} timed out`;
    const stderr = result.stderr.trim();
    const stdout = result.stdout.trim();
    const detail = stderr || stdout;
    return detail ? `${label} failed: ${detail}` : `${label} failed with exit code ${result.code ?? "unknown"}`;
}
export function firstLine(value) {
    return value.trim().split(/\r?\n/)[0] ?? "";
}
