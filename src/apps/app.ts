import { Elysia } from "elysia";
import { load_routes } from "../loaders/route_loader.ts";
import { logger } from "@bogeychan/elysia-logger";
import { join } from "path";

const env_variables = require("../utilities/env_variables.ts");
const app = new Elysia({
  aot: true,
  precompile: true,
  nativeStaticResponse: true,
});

await load_routes(app, join(import.meta.dir, "routes"));

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
  app.listen(await env_variables.get_env_variable("PORT"));
}
