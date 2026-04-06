import { run_backend_server } from "./app.ts";
import { logger } from "./logging.ts";
import { run_bot } from "./bot.ts";
import { LogLevel } from "@sapphire/framework";

const database = require("./database.ts");

async function main() {
  await run_backend_server().catch((err) => {
    database.disconnect();
    logger.write(LogLevel.Error, `Error running backend server ${err}`);
  }).then(() => {
    database.connect();
    logger.write(LogLevel.Info, "Backend server has started");
  }).finally(() => {
    logger.write(LogLevel.Info, "Backend server has stopped");
  });

  await run_bot().catch((err) => {
    database.disconnect();
    logger.write(LogLevel.Error, `Error running bot ${err}`);
  }).finally(() => {
    logger.write(LogLevel.Info, "Bot has stopped")
  });
}

await main();
