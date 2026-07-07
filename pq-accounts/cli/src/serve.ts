import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import { handleWalletRequest, type WalletContext } from "./walletRpc.js";

/** Tiny inline icon shown by dapp connect modals next to the wallet name. */
const ICON =
  "data:image/svg+xml;base64," +
  Buffer.from(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">' +
      '<rect width="32" height="32" rx="7" fill="#4f2d7f"/>' +
      '<text x="16" y="21" font-family="monospace" font-size="12" fill="#fff" text-anchor="middle">PQ</text>' +
      "</svg>"
  ).toString("base64");

/** The console-paste injector: defines a discoverable wallet object that relays every
 * request to this daemon. `walletId` is the injected `window.starknet_<id>` key and the
 * object's `id`. StarknetKit-based dapps (Voyager) only render discovered wallets whose
 * id matches a registered connector, so this defaults to an id in that list (`braavos`);
 * the modal still shows this object's own name and icon, not the impersonated wallet's.
 * Dapps using get-starknet directly accept any id. */
export function injectorSnippet(port: number, token: string, walletId: string): string {
  return `(() => {
  const url = "http://127.0.0.1:${port}/wallet";
  const listeners = { accountsChanged: [], networkChanged: [] };
  window.starknet_${walletId} = {
    id: "${walletId}",
    name: "PQ Falcon Account",
    version: "0.1.0",
    icon: "${ICON}",
    request: async (call) => {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", "x-pq-token": "${token}" },
        body: JSON.stringify(call),
      });
      const body = await res.json();
      if (body.error) throw new Error(body.error);
      return body.result;
    },
    on: (e, h) => { (listeners[e] ??= []).push(h); },
    off: (e, h) => { listeners[e] = (listeners[e] ?? []).filter((x) => x !== h); },
  };
  console.log("PQ Falcon Account wallet injected as starknet_${walletId} — open the dapp's connect dialog.");
})();`;
}

function setCors(req: IncomingMessage, res: ServerResponse): void {
  res.setHeader("access-control-allow-origin", req.headers.origin ?? "*");
  res.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
  res.setHeader("access-control-allow-headers", "content-type, x-pq-token");
  // Chrome Private Network Access: public pages fetching 127.0.0.1 preflight with this.
  if (req.headers["access-control-request-private-network"] === "true") {
    res.setHeader("access-control-allow-private-network", "true");
  }
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

/** Runs the local wallet daemon: POST /wallet handles wallet JSON-RPC messages (token
 * gated), GET /inject.js returns the console-paste injector. Binds to 127.0.0.1 only. */
export function serveWallet(params: {
  ctx: WalletContext;
  port: number;
  walletId: string;
  token?: string;
  log: (line: string) => void;
}): void {
  const token = params.token ?? randomBytes(8).toString("hex");
  const server = createServer(async (req, res) => {
    setCors(req, res);
    if (req.method === "OPTIONS") {
      res.writeHead(204).end();
      return;
    }
    if (req.method === "GET" && req.url?.startsWith("/inject.js")) {
      res.writeHead(200, { "content-type": "application/javascript" });
      res.end(injectorSnippet(params.port, token, params.walletId));
      return;
    }
    if (req.method === "POST" && req.url === "/wallet") {
      if (req.headers["x-pq-token"] !== token) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "missing or invalid x-pq-token" }));
        return;
      }
      let request: { type?: string; params?: unknown };
      try {
        request = JSON.parse(await readBody(req));
      } catch {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "invalid JSON body" }));
        return;
      }
      const origin = req.headers.origin ?? "local";
      try {
        const result = await handleWalletRequest(params.ctx, {
          type: String(request.type),
          params: request.params
        });
        params.log(`${origin} -> ${request.type} ok`);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ result }));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        params.log(`${origin} -> ${request.type} error: ${message}`);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: message }));
      }
      return;
    }
    res.writeHead(404).end();
  });

  server.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      params.log(
        `port ${params.port} is already in use — another daemon may be running. ` +
          `Stop it, or pass --port <n> to use a different port.`
      );
      process.exit(1);
    }
    throw err;
  });

  server.listen(params.port, "127.0.0.1", () => {
    params.log(`wallet daemon for ${params.ctx.scheme.key} account ${params.ctx.accountAddress}`);
    params.log(`rpc: ${params.ctx.rpcUrl}`);
    params.log(`listening on http://127.0.0.1:${params.port} (requests are token-gated)`);
    params.log("");
    params.log(`injected as window.starknet_${params.walletId} (StarknetKit connector slot)`);
    params.log("");
    params.log("Paste this into the dapp tab's DevTools console, then connect:");
    params.log("");
    params.log(injectorSnippet(params.port, token, params.walletId));
  });
}
