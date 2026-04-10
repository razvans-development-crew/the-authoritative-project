import { run_backend_server } from "./apps/app.ts";
import { logger } from "./utilities/logging.ts";
import { run_bot } from "./apps/bot.ts";
import { LogLevel } from "@sapphire/framework";

export const uptime = new Date().getTime();

const database = require("./utilities/database.ts");

async function main() {
  database.connect();

  const backend = run_backend_server().catch((err) => {
    database.disconnect();
    logger.write(LogLevel.Warn, `Backend server has crashed:`, err);
  });

  await run_bot().catch((err) => {
    database.disconnect();
    logger.write(LogLevel.Warn, `Bot has crashed:`, err);
  });

  logger.write(LogLevel.Info, "All services have started.")
  await Promise.all([backend]);
}

await main();
