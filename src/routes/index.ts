import { Elysia } from "elysia";
import { readFile } from "fs/promises";
import { uptime } from "../index.ts";
import { client } from "../services/bot.ts";
import { AHEAD_OF_TIME, PRECOMPILE } from "../services/app.ts";
import path from "path";

export function register_route(app: Elysia) {
  app.get("/", async (context) => {
    context.set.headers["content-type"] = "text/plain";

    const uptime_until_now = new Date().getTime() - Math.floor(uptime / 1000);
    const bot_websocket_latency = client.ws.ping.toString() + "ms";

    let plaintext_page_index = await readFile(path.join(import.meta.dir, "../../plaintext_pages/", "home.txt"), "utf-8");

    if (plaintext_page_index.includes("{UPTIME}")) {
      plaintext_page_index = plaintext_page_index.replace("{UPTIME}", uptime_until_now.toString());
    }

    if (plaintext_page_index.includes("AOT")) {
      plaintext_page_index = plaintext_page_index.replace("AOT", AHEAD_OF_TIME ? "true" : "false");
    }

    if (plaintext_page_index.includes("PRECOMPILE")) {
      plaintext_page_index = plaintext_page_index.replace("PRECOMPILE", PRECOMPILE ? "true" : "false");
    }

    if (plaintext_page_index.includes("WS_LATENCY")) {
      plaintext_page_index = plaintext_page_index.replace("WS_LATENCY", bot_websocket_latency);
    }

    return plaintext_page_index;
  })
}
