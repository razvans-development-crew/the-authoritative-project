import { Elysia } from "elysia";
import { load_routes } from "../loaders/route_loader.ts";
import { logger } from "@bogeychan/elysia-logger";
import { join } from "path";
import { logger as utils_logger } from "../utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";
import { get_client_ip } from "../utilities/helpers.ts";

export const AHEAD_OF_TIME = true;
export const PRECOMPILE = true;

const env_variables = require("../utilities/env_variables.ts");
const app = new Elysia({
  aot: AHEAD_OF_TIME,
  precompile: PRECOMPILE,
  nativeStaticResponse: true,
});

await load_routes(app, join(import.meta.dir, "../routes"));

export async function run_backend_server(): Promise<void> {
  utils_logger.write(LogLevel.Info, "Starting backend server...");

  // app.use(logger({
  //   level: "debug",
  //   formatters: {
  //     bindings: () => ({ pid: null })
  //   },
  //   transport: {
  //     target: "pino-pretty",
  //     options: {
  //       colorize: true
  //     }
  //   },
  //   autoLogging: true
  // }));

  app.onAfterResponse(async (context) => {
    utils_logger.write(LogLevel.Info, `(Outgoing Response) ${await get_client_ip(context.request, context.server)} | (${context.request.method}) ${context.request.url} - ${context.set.status}`);
  });

  app.onRequest(async (context) => {
    utils_logger.write(LogLevel.Info, `(Incoming) ${await get_client_ip(context.request, context.server)} | (${context.request.method}) ${context.request.url} - ${context.set.status}`);
  });

  app.listen(await env_variables.get_env_variable("PORT"), async () => {
    utils_logger.info(`Server started on port ${await env_variables.get_env_variable("PORT")} | https://127.0.0.1:${await env_variables.get_env_variable("PORT")}`);
  });
}
