import { Elysia } from "elysia";
import { registry } from "../../utilities/registry.ts";
import { logger } from "../../utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";
import { is_ip_from_roblox } from "../../utilities/preconditions.ts"
import { readFile } from "fs/promises";

export function register_route(app: Elysia) {
  app.get("/api/v3/loader", async (context) => {
    const ip =
      context.server?.requestIP?.(context.request)?.address ??
      'unknown';

    if (!await is_ip_from_roblox(ip)) {
      logger.write(LogLevel.Info, `IP is not from Roblox: ${ip}`);
      return context.status(401, "IP is not from Roblox");
    }

    const loader_key = context.request.headers?.get("X-Loader-Key");

    if (!loader_key) {
      logger.write(LogLevel.Info, `No loader key provided`);
      return context.status(401, "No key provided");
    }

    for (const loader_key_from_reg of registry.generated_keys) {
      if (loader_key_from_reg.loader_key === loader_key) {
        if ((new Date().getTime() - loader_key_from_reg.unix_timestamp) >= 25000) {
          return context.status(401, "Loader key is expired");
        }
      }
    }

    context.set.headers["content-type"] = "text/plain";

    const obfuscated_loader = await readFile("../../luau_frontend/loader_obfed.luau", "utf-8");
    return obfuscated_loader
  })
}
