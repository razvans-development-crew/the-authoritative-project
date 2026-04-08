import { run_backend_server } from "./apps/app.ts";
import { logger } from "./utilities/logging.ts";
import { run_bot } from "./apps/bot.ts";
import { LogLevel } from "@sapphire/framework";

const database = require("../utilities/database.ts");

async function main() {
  await run_backend_server().catch((err) => {
    database.disconnect();
    logger.write(LogLevel.Warn, `Exception while running backend server ${err}`);
  }).then(() => {
    database.connect();
    logger.write(LogLevel.Info, "Backend server has started");
  }).finally(() => {
    logger.write(LogLevel.Warn, "Backend server has stopped")
  });

  await run_bot().catch((err) => {
    database.disconnect();
    logger.write(LogLevel.Warn, `Exception while running bot ${err}`);
  }).finally(() => {
    logger.write(LogLevel.Warn, "Bot has stopped")
  });
}

await main();
