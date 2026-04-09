import { Elysia } from "elysia";
import { load_routes } from "../loaders/route_loader.ts";
import { logger } from "@bogeychan/elysia-logger";
import { join } from "path";
import { logger as utils_logger } from "../utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";
import { get_client_ip } from "../utilities/helpers.ts";

const env_variables = require("../utilities/env_variables.ts");
const app = new Elysia({
  aot: true,
  precompile: true,
  nativeStaticResponse: true,
});

await load_routes(app, join(import.meta.dir, "../routes"));

export async function run_backend_server(): Promise<void> {
  app.use(logger({
    level: "debug",
    formatters: {
      bindings: () => ({ pid: null })
    },
    transport: {
      target: "pino-pretty",
      options: {
        colorize: true
      }
    },
    autoLogging: true
  }));

  app.onAfterResponse(async (context) => {
    utils_logger.write(LogLevel.Info, `${await get_client_ip(context.request, context.server)} | (${context.request.method}) ${context.request.url} - ${context.set.status}`);
  });

  app.listen(await env_variables.get_env_variable("PORT"));
}
