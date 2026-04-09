import { Elysia } from "elysia";
import { registry } from "../../utilities/registry.ts";
import { logger } from "../../utilities/logging.ts";
import { check_api_key } from "../../utilities/security.ts";
import { LogLevel } from "@sapphire/framework";
import { is_ip_from_roblox } from "../../utilities/preconditions.ts"
import { get_client_ip } from "../../utilities/helpers.ts";

const request_queue = registry.request_queue

export function register_route(app: Elysia) {
  app.get("/api/v3/poll", async (context) => {
    if (!context.headers.Authorization || !await check_api_key(context.headers.Authorization)) {
      logger.write(LogLevel.Info, `Invalid API key: ${context.headers.Authorization}`);
      return context.status(401);
    }

    const ip = await get_client_ip(context.request, context.server);

    if (!await is_ip_from_roblox(ip)) {
      logger.write(LogLevel.Info, `IP is not from Roblox: ${ip}`);
      return context.status(401, "IP is not from Roblox");
    }

    const TIMEOUT = 90 / 1000; // 90 seconds

    return new Promise((resolve) => {
      const start = Date.now();

      const try_send = () => {
        if (!request_queue.isEmpty()) {
          const event = request_queue.shift();
          resolve({ event });
        } else if (Date.now() - start > TIMEOUT) {
          resolve({ event: null })
        } else {
          setTimeout(try_send, 10)
        }
      }

      try_send();
    })
  })
}
