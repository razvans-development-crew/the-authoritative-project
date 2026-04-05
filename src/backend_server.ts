import { Elysia } from "elysia";
import { get } from "node:http";
const database = require("./database.ts");
const env_variables = require("./env_variables.ts");

const app = new Elysia();

app.get("/", () => {
  return "hi"
});

// the V3 api
app.get("/api/v3/whitelists", () => {
  return database.get_whitelists();
})

app.get("/api/v3/bans", () => {
  return database.get_global_user_bans();
})

app.get("/api/v3/group-bans", () => {
  return database.get_global_group_bans();
})

// the v2 API
app.get("/api/v2/whitelists", () => {
  return database.get_legacy_whitelists();
})

app.get("/api/v2/bans", () => {
  return database.get_legacy_global_user_bans();
})

app.get("/api/v2/group-bans", () => {
  return database.get_legacy_global_group_bans();
})

export async function run_backend_server(): Promise<void> {
  app.listen(await env_variables.get_env_variable("PORT"));
}