import { Elysia } from "elysia";
import { load_routes } from "../loaders/route_loader.ts";
// import { logger } from "@bogeychan/elysia-logger";
import { join } from "path";
import { logger as utils_logger } from "../utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";
// import { get_client_ip } from "../utilities/helpers.ts";
import { staticPlugin } from "@elysiajs/static"
import logixlysia from "logixlysia"

export const AHEAD_OF_TIME = true;
export const PRECOMPILE = true;

const env_variables = require("../utilities/env_variables.ts");
const app = new Elysia({
  aot: AHEAD_OF_TIME,
  precompile: PRECOMPILE,
  nativeStaticResponse: true,
});

export async function run_service(): Promise<void> {
  utils_logger.write(LogLevel.Info, "Starting backend server...");

  await load_routes(app, join(import.meta.dir, "../routes"));

  app.use(staticPlugin({
    assets: "static",
    prefix: "/static",
  }))

  app.use(
    logixlysia({
      config: {
        service: "tap-server",
        showStartupMessage: true,
        startupMessageFormat: 'banner',
        showContextTree: true,
        contextDepth: 2,
        slowThreshold: 500,
        verySlowThreshold: 1000,
        timestamp: {
          translateTime: "yyyy-mm-dd HH:MM:ss.SSS"
        },
        ip: true
      }
    })
  )

  // app.onAfterResponse(async (context) => {
  //   utils_logger.write(LogLevel.Info, `${await get_client_ip(context.request, context.server)} | (${context.request.method}) ${context.request.url} - ${context.set.status}`);
  // });

  // app.onRequest(async (context) => {
  //   utils_logger.write(LogLevel.Info, `(Incoming) ${await get_client_ip(context.request, context.server)} | (${context.request.method}) ${context.request.url} - ${context.set.status}`);
  // });

  app.listen(Number(await env_variables.get_env_variable("PORT")) ?? 8000, async () => {
    utils_logger.info(`Server started on port ${await env_variables.get_env_variable("PORT")} | https://127.0.0.1:${await env_variables.get_env_variable("PORT")}`);
  });
}

export default run_service;
