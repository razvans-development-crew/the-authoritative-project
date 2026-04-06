import { Elysia } from "elysia";
import { registry } from "../../registry.ts";
import { logger } from "../../logging.ts";
import Denque from "denque";
import { get_all_valid_api_keys } from "../../security.ts";

const request_queue = registry.request_queue

export function register_route(app: Elysia) {
  app.get("/api/v3/poll", async (context) => {
    return

    const TIMEOUT = 90 / 1000; // 90 seconds

    return new Promise((resolve) => {
      const start = Date.now();

      const try_send = () => {
        if (!request_queue.isEmpty()) {
          const event = request_queue.shift();
          resolve({ event });
        } else if (Date.now() - start > TIMEOUT) {
          resolve({ event: null })
        } else {
          setTimeout(try_send, 10)
        }
      }

      try_send();
    })
  })
}
