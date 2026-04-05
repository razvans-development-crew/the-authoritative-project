import { Elysia } from "elysia";
import { load_routes } from "./route_loader.ts";
import { logger } from "@bogeychan/elysia-logger";
import { join } from "path";

const env_variables = require("./env_variables.ts");
const app = new Elysia();

load_routes(app, join(import.meta.dir, "routes"));

export async function run_backend_server(): Promise<void> {
  app.use(logger({level: "debug"}))
  app.listen(await env_variables.get_env_variable("PORT"));
}