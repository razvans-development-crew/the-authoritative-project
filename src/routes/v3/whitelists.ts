import { Elysia } from "elysia";
const database = require("../../database.ts");

export function register_route(app: Elysia) {
  app.get("/api/v3/whitelists", database.get_whitelists());
}