import { Elysia } from "elysia";
const database = require("../../database.ts");

export function register_route(app: Elysia) {
  app.get("/api/v2/group-bans", database.get_legacy_global_group_bans());
}