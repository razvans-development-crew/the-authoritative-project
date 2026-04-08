import { Elysia } from "elysia";
const database = require("../../utilities/database.ts");

export function register_route(app: Elysia) {
  app.get("/api/v2/whitelists", database.get_legacy_whitelists());
}
