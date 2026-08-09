import { routeAgentRequest } from "agents";
import { Scribe } from "@forestrie/think-scribe";

// The DO class the wrangler binding + migration refer to.
export { Scribe };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // M0: open routing to named Scribe instances via the agents chat
    // protocol. M1 replaces this with wcc-1 edge auth and Option B per-user
    // instance naming — `user-<sub>` derived from the verified principal in
    // onBeforeConnect/onBeforeRequest (plan §4). Never put "/" in a derived
    // instance name (agents#379: text after "/" is silently dropped).
    return (
      (await routeAgentRequest(request, env)) ??
      new Response("Not found", { status: 404 })
    );
  },
} satisfies ExportedHandler<Env>;
