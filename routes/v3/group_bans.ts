import { Elysia } from "elysia";
const database = require("../../utilities/database.ts");

export function register_route(app: Elysia) {
  app.get("/api/v3/group-bans", database.get_global_group_bans());
}
