import { Elysia } from "elysia";
import { load_routes } from "./route_loader.ts";
import { logger } from "./logging.ts";
import { join } from "path";
import { LogLevel } from "@sapphire/framework";

const env_variables = require("./env_variables.ts");
const app = new Elysia();

load_routes(app, join(import.meta.dir, "routes"));

export async function run_backend_server(): Promise<void> {
  app.onRequest(async ({request, set}) => {
    logger.write(LogLevel.Info, `(INCOMING - ${request.method}) ${set.headers.x_forwarded_for ?? "Unknown IP"} | ${request.url}`);
  });

  app.onAfterResponse(async (context) => {
    logger.write(LogLevel.Info, `(${context.status} - ${context.request.method}) ${context.set.headers.x_forwarded_for ?? "Unknown IP"} | ${context.request.url}`);
  })

  app.listen(await env_variables.get_env_variable("PORT"));
}