import { logger } from "./logging.ts";
import { LogLevel } from "@sapphire/framework";
import { registry } from "./registry.ts";
import { type Event } from "../types/Event.ts";

export async function send_event(event: Event) {
  logger.write(LogLevel.Info, `Sending event ${event.event_name} to session ${event.session_id}`);
  registry.request_queue.push(event);
}
