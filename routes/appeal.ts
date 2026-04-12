import { Elysia } from "elysia";

export function register_route(app: Elysia) {
  app.post("/appeal", async ({redirect}) => {
    return redirect("https://discord.gg/jQ3vCYCJZD")
  })
}
