import { routeAgentRequest } from "agents";
import { PRINCIPAL_HEADER, Scribe } from "@forestrie/think-scribe";
import { handleAuth, verifySession } from "./auth.ts";

// The DO class the wrangler binding + migration refer to.
export { Scribe };

/**
 * Option B per-user routing (plan §4): the instance name is `user-<sub>`
 * where `sub` is the wcc-1-verified principal. partyserver computes the DO
 * id from the URL segment BEFORE onBeforeConnect/onBeforeRequest run, so
 * the gate cannot rewrite the name — instead the client addresses
 * `/agents/scribe/user-<sub>` itself and the gate ENFORCES that the name
 * matches the verified session (403 otherwise). Nobody can reach an
 * instance they don't own; the DO additionally binds the principal on
 * first touch. Never put "/" in a name (agents#379 silently truncates).
 */
function gate(env: Env) {
  return async (req: Request, lobby: { name: string }) => {
    const sub = await verifySession(req, env);
    if (!sub) return new Response("Unauthorized", { status: 401 });
    if (lobby.name !== `user-${sub}`)
      return new Response("Forbidden: instance is not yours", { status: 403 });
    // Forward the verified principal; drop the credentials so they don't
    // outlive the edge (the ?token= variant is also stripped from the URL).
    const url = new URL(req.url);
    url.searchParams.delete("token");
    const fwd = new Request(url, req);
    fwd.headers.set(PRINCIPAL_HEADER, sub);
    fwd.headers.delete("authorization");
    return fwd;
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const authResponse = await handleAuth(request, env);
    if (authResponse) return authResponse;

    const g = gate(env);
    return (
      (await routeAgentRequest(request, env, {
        onBeforeConnect: g,
        onBeforeRequest: g,
      })) ?? new Response("Not found", { status: 404 })
    );
  },
} satisfies ExportedHandler<Env>;
