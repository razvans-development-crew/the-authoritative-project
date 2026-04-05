import { run_backend_server } from "./app.ts";
import { logger } from "./logging.ts";
import { run_bot } from "./bot.ts";
const database = require("./database.ts");

async function main() {
  await run_backend_server().catch((err) => {
    database.disconnect();
    logger.write({level: "error", timestamp: new Date().toISOString(), message: "Error running backend server", error: err});
  }).then(() => {
    database.connect();
    logger.write({level: "info", timestamp: new Date().toISOString(), message: "Backend server has started"});
  });

  await run_bot().catch((err) => {
    database.disconnect();
    logger.write({level: "error", timestamp: new Date().toISOString(), message: "Error running bot", error: err});
  });
}

await main();