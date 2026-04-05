import { run_backend_server } from "./app.ts";
import { logger } from "./logging.ts";
import { run_bot } from "./bot.ts";
const database = require("./database.ts");

async function main() {
  await run_backend_server().catch((err) => {
    database.disconnect();
    logger.error(err, "Error running backend server");
  }).then(() => {
    database.connect();
    logger.info("Backend server has started");
  });

  await run_bot().catch((err) => {
    logger.error(err, "Error running bot");
  });
}

await main();