import { Elysia } from "elysia";
import { load_routes } from "./route_loader.ts";

const env_variables = require("./env_variables.ts");
const app = new Elysia();

load_routes(app, "./routes");

export async function run_backend_server(): Promise<void> {
  app.listen(await env_variables.get_env_variable("PORT"));
}