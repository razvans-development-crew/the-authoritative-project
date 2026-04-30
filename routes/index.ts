import { Elysia } from "elysia";
import { readFile } from "fs/promises";
import { uptime } from "../index.ts";
import { client } from "../services/bot.ts";
import { AHEAD_OF_TIME, PRECOMPILE } from "../services/app.ts";
import path from "path";
import { is_bot_ratelimited } from "../utilities/helpers.ts";

export function register_route(app: Elysia) {
  app.get("/", async (context) => {
    context.set.headers["content-type"] = "text/plain";

    const uptime_until_now = Math.floor((new Date().getTime() - uptime) / 1000);
    const bot_websocket_latency = client.ws.ping.toString() + "ms";

    let plaintext_page_index = await readFile(path.join(import.meta.dir, "../plaintext_pages/", "home.txt"), "utf-8");

    if (plaintext_page_index.includes("{UPTIME}")) {
      plaintext_page_index = plaintext_page_index.replace("{UPTIME}", uptime_until_now.toString());
    }

    if (plaintext_page_index.includes("{AOT}")) {
      plaintext_page_index = plaintext_page_index.replace("{AOT}", AHEAD_OF_TIME ? "true" : "false");
    }

    if (plaintext_page_index.includes("{PRECOMPILE}")) {
      plaintext_page_index = plaintext_page_index.replace("{PRECOMPILE}", PRECOMPILE ? "true" : "false");
    }

    if (plaintext_page_index.includes("{WS_LATENCY}")) {
      plaintext_page_index = plaintext_page_index.replace("{WS_LATENCY}", bot_websocket_latency);
    }

    // keeping this branch would cause a ratelimit, therefore it has been commented out
    // if (plaintext_page_index.includes("{RATELIMITED}")) {
    //   const ratelimit_data = await is_bot_ratelimited();
    //   plaintext_page_index = plaintext_page_index.replace("{RATELIMITED}", ratelimit_data.is_ratelimited ? "true" : "false");
    //   plaintext_page_index += "\n   -> retry after: " + ratelimit_data.retry_after;
    //   plaintext_page_index += "\n   -> reset after: " + ratelimit_data.reset_after;
    //   plaintext_page_index += "\n   -> rate limit remaining: " + ratelimit_data.rate_limit_remaining;
    //   plaintext_page_index += "\n   -> rate limit scope: " + ratelimit_data.rate_limit_scope;
    // }

    return plaintext_page_index;
  })
}
