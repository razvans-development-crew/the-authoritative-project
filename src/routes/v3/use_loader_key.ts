import { Elysia } from "elysia";
import { registry } from "../../registry.ts";
import { logger } from "../../logging.ts";
import { check_api_key } from "../../security.ts";
import { LogLevel } from "@sapphire/framework";
import { is_ip_from_roblox } from "../../preconditions.ts"

export function register_route(app: Elysia) {
  app.get("/api/v3/use-loader-key", async (context) => {
    if (!context.headers.Authorization || !await check_api_key(context.headers.Authorization)) {
      logger.write(LogLevel.Info, `Invalid API key: ${context.headers.Authorization}`);
      return context.status(401);
    }

    const ip =
      context.request.headers.get("x-forwarded-for") ??
      context.server?.requestIP?.(context.request)?.address ??
      'unknown';

    if (!await is_ip_from_roblox(ip)) {
      logger.write(LogLevel.Info, `IP is not from Roblox: ${ip}`);
      return context.status(401);
    }

    const loader_key = (await context.request.body?.json()).loader_key;

    if (!loader_key) {
      logger.write(LogLevel.Info, `No loader key provided`);
      return context.status(400);
    }

    for (const loader_key_from_reg of registry.generated_keys) {
      if (loader_key_from_reg.loader_key === loader_key) {
        logger.write(LogLevel.Info, `Loader key found in the registry: ${loader_key}`);
        logger.write(LogLevel.Info, "Checking if it is expired...")

        if ((new Date().getTime() - loader_key_from_reg.unix_timestamp) >= 25000) {
          logger.write(LogLevel.Info, `Loader key is expired`);
          return context.status(401);
        }

        logger.write(LogLevel.Info, `Loader key is valid`);
        // remove the key from the registry, it is now used
        registry.generated_keys = registry.generated_keys.filter(key => key.loader_key !== loader_key);

        return context.status(200);
      }
    }

    return context.status(404);
  })
}
