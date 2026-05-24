/**
 * MCP OAuth Callback Server
 * 
 * HTTP server that handles OAuth callbacks from the authorization server.
 * Uses Node.js http module for compatibility.
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from "http"
import * as net from "node:net"
import {
  OAUTH_CALLBACK_PATH,
  getConfiguredOAuthCallbackPort,
  getOAuthCallbackPort,
  setOAuthCallbackPort,
} from "./mcp-oauth-provider.ts"

// HTML templates for callback responses
const HTML_SUCCESS = `<!DOCTYPE html>
<html>
<head>
  <title>Pi - Authorization Successful</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #1a1a2e; color: #eee; }
    .container { text-align: center; padding: 2rem; }
    h1 { color: #4ade80; margin-bottom: 1rem; }
    p { color: #aaa; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Authorization Successful</h1>
    <p>You can close this window and return to Pi.</p>
  </div>
  <script>setTimeout(() => window.close(), 2000);</script>
</body>
</html>`

const HTML_ERROR = (error: string) => `<!DOCTYPE html>
<html>
<head>
  <title>Pi - Authorization Failed</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #1a1a2e; color: #eee; }
    .container { text-align: center; padding: 2rem; }
    h1 { color: #f87171; margin-bottom: 1rem; }
    p { color: #aaa; }
    .error { color: #fca5a5; font-family: monospace; margin-top: 1rem; padding: 1rem; background: rgba(248,113,113,0.1); border-radius: 0.5rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Authorization Failed</h1>
    <p>An error occurred during authorization.</p>
    <div class="error">${error}</div>
  </div>
</body>
</html>`

/** Pending authorization request */
interface PendingAuth {
  resolve: (code: string) => void
  reject: (error: Error) => void
  timeout: ReturnType<typeof setTimeout>
}

/** Per-port server state */
interface PortState {
  server: Server
  pendingAuths: Map<string, PendingAuth>
}

const portServers = new Map<number, PortState>()

/** Legacy single-server state (shared/global port) */
const pendingAuths = new Map<string, PendingAuth>()
let server: Server | undefined

/** Timeout for callback completion (5 minutes) */
const CALLBACK_TIMEOUT_MS = 5 * 60 * 1000

const MAX_PORT_SCAN_ATTEMPTS = 25

interface EnsureCallbackServerOptions {
  strictPort?: boolean
  /** If set, start (or reuse) a dedicated server on this specific port */
  port?: number
}

/** Obtain a random available local port by binding to port 0. */
async function getRandomPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.listen(0, "localhost", () => {
      const addr = srv.address() as net.AddressInfo
      srv.close(() => resolve(addr.port))
    })
    srv.on("error", reject)
  })
}

/**
 * Build a request handler bound to a specific pendingAuths map.
 */
function makeHandleRequest(auths: Map<string, PendingAuth>) {
  return function handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(req.url || "/", `http://${req.headers.host}`)

    // Only handle the callback path
    if (url.pathname !== OAUTH_CALLBACK_PATH) {
      res.writeHead(404, { "Content-Type": "text/plain" })
      res.end("Not found")
      return
    }

    const code = url.searchParams.get("code")
    const state = url.searchParams.get("state")
    const error = url.searchParams.get("error")
    const errorDescription = url.searchParams.get("error_description")

    // Enforce state parameter presence for CSRF protection
    if (!state) {
      const errorMsg = "Missing required state parameter - potential CSRF attack"
      res.writeHead(400, { "Content-Type": "text/html" })
      res.end(HTML_ERROR(errorMsg))
      return
    }

    // Handle OAuth errors
    if (error) {
      const errorMsg = errorDescription || error
      res.writeHead(200, { "Content-Type": "text/html" })
      res.end(HTML_ERROR(errorMsg))
      if (auths.has(state)) {
        const pending = auths.get(state)!
        clearTimeout(pending.timeout)
        auths.delete(state)
        setTimeout(() => pending.reject(new Error(errorMsg)), 0)
      }
      return
    }

    // Require authorization code
    if (!code) {
      res.writeHead(400, { "Content-Type": "text/html" })
      res.end(HTML_ERROR("No authorization code provided"))
      return
    }

    // Validate state parameter
    if (!auths.has(state)) {
      const errorMsg = "Invalid or expired state parameter - potential CSRF attack"
      res.writeHead(400, { "Content-Type": "text/html" })
      res.end(HTML_ERROR(errorMsg))
      return
    }

    const pending = auths.get(state)!
    clearTimeout(pending.timeout)
    auths.delete(state)
    pending.resolve(code)

    res.writeHead(200, { "Content-Type": "text/html" })
    res.end(HTML_SUCCESS)
  }
}

/**
 * Start a callback server on a specific port (strict — no port scanning).
 * Reuses an existing server on that port if already running.
 */
async function ensurePortServer(port: number): Promise<PortState> {
  const existing = portServers.get(port)
  if (existing) return existing

  const auths = new Map<string, PendingAuth>()
  const srv = createServer(makeHandleRequest(auths))

  await new Promise<void>((resolve, reject) => {
    srv.once("error", reject)
    srv.listen(port, "localhost", resolve)
  }).catch((err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      throw new Error(
        `OAuth callback port ${port} is already in use. Pre-registered OAuth clients require an exact redirect URI; ensure port ${port} is free or change callbackPort in your config.`,
        { cause: err },
      )
    }
    throw err
  })

  srv.unref()
  const state: PortState = { server: srv, pendingAuths: auths }
  portServers.set(port, state)
  return state
}

/**
 * Ensure the callback server is running.
 * - If options.port is set, starts (or reuses) a dedicated server on that exact port.
 * - Otherwise falls back to the global shared server behaviour.
 * If strictPort is true, requires binding on the configured callback port.
 * If strictPort is false, scans forward for an available local port.
 */
export async function ensureCallbackServer(options: EnsureCallbackServerOptions = {}): Promise<void> {
  // Per-server dedicated port path
  if (options.port !== undefined) {
    await ensurePortServer(options.port)
    return
  }

  // Global shared server path (legacy behaviour)
  const configuredPort = getConfiguredOAuthCallbackPort()
  const strictPort = options.strictPort === true

  if (server) {
    if (!strictPort || getOAuthCallbackPort() === configuredPort) return

    if (pendingAuths.size > 0) {
      throw new Error(
        `OAuth callback server is running on port ${getOAuthCallbackPort()}, but strict callback port ${configuredPort} is required and cannot be switched while authorizations are pending`
      )
    }

    await stopCallbackServer()
  }

  let lastError: Error | undefined

  // For non-strict dynamic registration flows, use a random OS-assigned port
  // (matches behaviour of Claude Code and other MCP clients)
  if (!strictPort) {
    const randomPort = await getRandomPort()
    const candidateServer = createServer(makeHandleRequest(pendingAuths))
    await new Promise<void>((resolve, reject) => {
      candidateServer.once("error", reject)
      candidateServer.listen(randomPort, "localhost", resolve)
    })
    server = candidateServer
    server.unref()
    setOAuthCallbackPort(randomPort)
    return
  }

  const preferredPort = configuredPort
  const maxAttempts = 1 // strictPort is always true here

  for (let offset = 0; offset < maxAttempts; offset++) {
    const candidatePort = preferredPort + offset
    const candidateServer = createServer(makeHandleRequest(pendingAuths))

    try {
      await new Promise<void>((resolve, reject) => {
        candidateServer.once("error", reject)
        candidateServer.listen(candidatePort, "localhost", resolve)
      })

      server = candidateServer
      server.unref()
      setOAuthCallbackPort(candidatePort)
      return
    } catch (error) {
      const nodeError = error as NodeJS.ErrnoException
      await new Promise<void>((resolve) => {
        candidateServer.close(() => resolve())
      })

      if (nodeError.code !== "EADDRINUSE") {
        throw error
      }

      lastError = error instanceof Error ? error : new Error(String(error))
    }
  }

  if (strictPort) {
    throw new Error(
      `OAuth callback port ${preferredPort} is already in use. Pre-registered OAuth clients require an exact redirect URI; set MCP_OAUTH_CALLBACK_PORT to your registered port or free port ${preferredPort}`,
      { cause: lastError }
    )
  }

  throw new Error(
    `OAuth callback port ${preferredPort} is already in use and no free port was found in range ${preferredPort}-${preferredPort + MAX_PORT_SCAN_ATTEMPTS - 1}`,
    { cause: lastError }
  )
}

/** Resolve the pendingAuths map for a given state (searches per-port servers first, then shared). */
function resolvePendingAuths(oauthState: string): Map<string, PendingAuth> {
  for (const { pendingAuths: auths } of portServers.values()) {
    if (auths.has(oauthState)) return auths
  }
  return pendingAuths
}

/**
 * Wait for a callback with the given OAuth state.
 * Registers into the per-port server if port is provided, otherwise the shared server.
 * Returns a promise that resolves with the authorization code.
 */
export function waitForCallback(oauthState: string, port?: number): Promise<string> {
  const auths = port !== undefined
    ? (portServers.get(port)?.pendingAuths ?? pendingAuths)
    : pendingAuths

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      if (auths.has(oauthState)) {
        auths.delete(oauthState)
        reject(new Error("OAuth callback timeout - authorization took too long"))
      }
    }, CALLBACK_TIMEOUT_MS)

    auths.set(oauthState, { resolve, reject, timeout })
  })
}

/**
 * Cancel a pending authorization by state.
 */
export function cancelPendingCallback(oauthState: string): void {
  const auths = resolvePendingAuths(oauthState)
  const pending = auths.get(oauthState)
  if (pending) {
    clearTimeout(pending.timeout)
    auths.delete(oauthState)
    pending.reject(new Error("Authorization cancelled"))
  }
}

/**
 * Stop a per-port callback server and reject its pending authorizations.
 */
export async function stopPortServer(port: number): Promise<void> {
  const state = portServers.get(port)
  if (!state) return

  portServers.delete(port)

  await new Promise<void>((resolve) => state.server.close(() => resolve()))

  const pendingList = Array.from(state.pendingAuths.entries())
  state.pendingAuths.clear()
  setTimeout(() => {
    for (const [, pending] of pendingList) {
      clearTimeout(pending.timeout)
      pending.reject(new Error("OAuth callback server stopped"))
    }
  }, 0)
}

/**
 * Stop the shared callback server and reject all pending authorizations.
 */
export async function stopCallbackServer(): Promise<void> {
  // Stop all per-port servers
  const ports = Array.from(portServers.keys())
  await Promise.all(ports.map(stopPortServer))

  if (server) {
    await new Promise<void>((resolve) => {
      server!.close(() => resolve())
    })
    server = undefined
  }

  setOAuthCallbackPort(getConfiguredOAuthCallbackPort())

  // Reject all shared pending auths
  const pendingList = Array.from(pendingAuths.entries())
  pendingAuths.clear()
  setTimeout(() => {
    for (const [, pending] of pendingList) {
      clearTimeout(pending.timeout)
      pending.reject(new Error("OAuth callback server stopped"))
    }
  }, 0)
}

/**
 * Check if the shared callback server is running.
 */
export function isCallbackServerRunning(): boolean {
  return server !== undefined || portServers.size > 0
}

/**
 * Get the number of pending authorizations.
 */
export function getPendingAuthCount(): number {
  let total = pendingAuths.size
  for (const { pendingAuths: auths } of portServers.values()) {
    total += auths.size
  }
  return total
}
