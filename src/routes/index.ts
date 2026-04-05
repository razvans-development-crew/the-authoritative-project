import { Elysia } from "elysia";

export function register_route(app: Elysia) {
  app.get("/", "hi")
}