#!/usr/bin/env node
/**
 * Railway deployment entry: serve the harness Web UI behind HTTP Basic authentication.
 *
 * `dsh web` refuses `--host 0.0.0.0` on purpose — the Web carrier has no
 * authentication layer, so binding every interface would publish remote code
 * execution (`packages/bundle/web-app/src/startup.ts`). This entry keeps that
 * guard intact: the harness stays on loopback and only this process binds the
 * public port, rejecting every request that does not carry the shared
 * credential before any byte reaches the harness.
 *
 * Requests are forwarded with their original `Host`, so the harness reaches its
 * `/api` browser-trust fence as the public authority named by `DSH_PUBLIC_HOST`
 * rather than as loopback. That is deliberate: the fence pins the privileged
 * configuration and credential methods to loopback callers, and rewriting `Host`
 * to `127.0.0.1` would hand those methods to every authenticated browser.
 *
 * Required environment: `DSH_PUBLIC_HOST` (the served authority) and
 * `DSH_WEB_PASSWORD` (the shared secret). A missing value stops the process
 * before the port is bound, so a misconfigured deployment never serves
 * unauthenticated.
 */
import { spawn } from 'node:child_process'
import { createHash, timingSafeEqual } from 'node:crypto'
import http from 'node:http'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

/** Loopback port the harness binds; only this process connects to it. */
const HARNESS_PORT = 3080
/** Loopback address the harness binds and this process forwards to. */
const HARNESS_HOST = '127.0.0.1'
/** Unauthenticated liveness path, answered here and never forwarded. */
const HEALTH_PATH = '/healthz'
/** Seconds the browser may cache the credential prompt realm. */
const REALM = 'DeepSeek Harness'

/**
 * Read a required environment variable.
 *
 * @param name - Variable to read.
 * @returns The non-empty value.
 */
function required(name) {
  const value = process.env[name]
  if (value === undefined || value === '') {
    console.error(`railway-serve: ${name} is required; refusing to serve without it`)
    process.exit(1)
  }
  return value
}

const publicHost = required('DSH_PUBLIC_HOST')
const password = required('DSH_WEB_PASSWORD')
const user = process.env.DSH_WEB_USER ?? 'dsh'
const port = Number(process.env.PORT ?? 8080)
if (!Number.isInteger(port) || port <= 0 || port > 65535) {
  console.error(`railway-serve: PORT must be a valid port number, got ${process.env.PORT}`)
  process.exit(1)
}

/** Digest of the expected `user:password` pair; comparing digests keeps the check constant-time. */
const expected = createHash('sha256').update(`${user}:${password}`).digest()

/**
 * Test one request's `Authorization` header against the configured credential.
 *
 * @param header - Raw `Authorization` header value, if the client sent one.
 * @returns Whether the header carries the expected Basic credential.
 */
function authorized(header) {
  if (typeof header !== 'string') return false
  const [scheme, encoded] = header.split(' ')
  if (scheme?.toLowerCase() !== 'basic' || encoded === undefined) return false
  const presented = createHash('sha256')
    .update(Buffer.from(encoded, 'base64').toString('utf8'))
    .digest()
  return timingSafeEqual(expected, presented)
}

/**
 * Forwarded header set: the original headers with hop-by-hop entries removed.
 *
 * `Host` is preserved so the harness sees the public authority; `Authorization`
 * is stripped because the credential authenticates to this proxy alone.
 *
 * @param headers - Inbound request headers.
 * @returns Headers to send upstream.
 */
function forwardHeaders(headers) {
  const { authorization, ...rest } = headers
  return rest
}

const harnessEntry = fileURLToPath(new URL('../apps/cli/lib/bin.js', import.meta.url))
const mercuryPatch = fileURLToPath(new URL('./railway-mercury-mcp.cordis.yml', import.meta.url))

/**
 * Launcher overlays applied ahead of the profile.
 *
 * The Mercury CRM overlay is applied only when both its URL and token are
 * present: the row resolves `process.env` at load, so mounting it without
 * credentials would fail the boot rather than degrade to a harness without
 * Mercury tools. `--patch` is a launcher flag and must precede `--profile`;
 * the `dsh web` alias rejects it outright.
 */
const patchArgs = process.env.MERCURY_MCP_URL && process.env.MERCURY_MCP_TOKEN
  ? ['--patch', mercuryPatch]
  : []
if (patchArgs.length === 0) {
  console.log('railway-serve: Mercury MCP not configured (MERCURY_MCP_URL/MERCURY_MCP_TOKEN unset); serving without it')
}

const harness = spawn(
  process.execPath,
  [
    harnessEntry,
    ...patchArgs,
    '--profile', 'web',
    '--host', HARNESS_HOST,
    '--port', String(HARNESS_PORT),
    '--no-open',
    '--trusted-host', publicHost,
  ],
  { stdio: 'inherit' },
)

harness.on('exit', (code, signal) => {
  console.error(`railway-serve: harness exited (code=${code} signal=${signal}); stopping`)
  process.exit(code ?? 1)
})

/**
 * Report whether the configured Mercury MCP server is reachable and accepts the
 * token, once, at startup.
 *
 * The MCP client connects lazily and reports nothing on failure, so without this
 * a wrong URL or a token that failed to resolve looks identical to a healthy
 * deployment until someone asks the model for a Mercury tool. This only
 * observes: it never blocks serving and never changes the harness's own
 * connection.
 *
 * @returns Nothing; the outcome is written to the deploy log.
 */
async function probeMercury() {
  const url = process.env.MERCURY_MCP_URL
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        authorization: `Bearer ${process.env.MERCURY_MCP_TOKEN}`,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'railway-serve-probe', version: '1' },
        },
      }),
      signal: AbortSignal.timeout(15_000),
    })
    const body = await response.text()
    const verdict = response.ok && body.includes('"result"')
      ? 'ok'
      : response.status === 401 || response.status === 403
        ? 'REJECTED — check MERCURY_MCP_TOKEN'
        : 'UNEXPECTED RESPONSE'
    console.log(`railway-serve: mercury MCP probe ${url}: HTTP ${response.status} ${verdict}`)
  } catch (error) {
    console.error(`railway-serve: mercury MCP probe ${url}: UNREACHABLE (${error.message})`)
  }
}

if (patchArgs.length > 0) void probeMercury()

const server = http.createServer((req, res) => {
  if (req.url === HEALTH_PATH) {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('ok\n')
    return
  }
  if (!authorized(req.headers.authorization)) {
    res.writeHead(401, {
      'www-authenticate': `Basic realm="${REALM}", charset="UTF-8"`,
      'content-type': 'text/plain',
    })
    res.end('authentication required\n')
    return
  }
  const upstream = http.request(
    { host: HARNESS_HOST, port: HARNESS_PORT, method: req.method, path: req.url, headers: forwardHeaders(req.headers) },
    (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers)
      upstreamRes.pipe(res)
    },
  )
  upstream.on('error', (error) => {
    console.error(`railway-serve: upstream request failed: ${error.message}`)
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' })
    res.end('upstream unavailable\n')
  })
  req.pipe(upstream)
})

server.on('upgrade', (req, socket, head) => {
  if (!authorized(req.headers.authorization)) {
    socket.write(`HTTP/1.1 401 Unauthorized\r\nwww-authenticate: Basic realm="${REALM}", charset="UTF-8"\r\nconnection: close\r\n\r\n`)
    socket.destroy()
    return
  }
  const upstream = http.request({
    host: HARNESS_HOST,
    port: HARNESS_PORT,
    method: req.method,
    path: req.url,
    headers: forwardHeaders(req.headers),
  })
  upstream.on('upgrade', (upstreamRes, upstreamSocket, upstreamHead) => {
    const statusLine = `HTTP/1.1 ${upstreamRes.statusCode} ${upstreamRes.statusMessage}\r\n`
    const headerLines = Object.entries(upstreamRes.headers)
      .flatMap(([key, value]) => (Array.isArray(value) ? value.map((one) => `${key}: ${one}`) : [`${key}: ${value}`]))
      .join('\r\n')
    socket.write(`${statusLine}${headerLines}\r\n\r\n`)
    if (upstreamHead.length > 0) socket.unshift(upstreamHead)
    upstreamSocket.pipe(socket)
    socket.pipe(upstreamSocket)
    upstreamSocket.on('error', () => socket.destroy())
    socket.on('error', () => upstreamSocket.destroy())
  })
  upstream.on('error', (error) => {
    console.error(`railway-serve: upstream upgrade failed: ${error.message}`)
    socket.destroy()
  })
  if (head.length > 0) upstream.write(head)
  upstream.end()
})

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    harness.kill(signal)
    server.close(() => process.exit(0))
  })
}

server.listen(port, '0.0.0.0', () => {
  console.log(`railway-serve: authenticated proxy on 0.0.0.0:${port} -> ${HARNESS_HOST}:${HARNESS_PORT} (trusted host ${publicHost})`)
})
