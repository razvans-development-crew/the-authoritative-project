import { Elysia } from "elysia";
const database = require("../../utilities/database.ts");

export function register_route(app: Elysia) {
  app.get("/api/v2/bans", database.get_legacy_global_user_bans());
}
