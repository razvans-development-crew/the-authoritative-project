import { logger } from "./utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";
import { readdir } from "fs/promises";
import { generate_random_string } from "./utilities/helpers.ts";
import path from "path";
import { client } from "./services/bot.ts";
import { run_service } from "./services/bot.ts";
import { get_env_variable } from "./utilities/env_variables.ts";

export const uptime = new Date().getTime();

const database = require("./utilities/database.ts");

(async () => {
  database.connect();

  // const service_files = await readdir(path.join(import.meta.dir, "./services"));
  // const running_services = [];

  // for (const service of service_files) {
  //   const JOB_ID = await generate_random_string(12);

  //   try {
  //     const service_path = path.join(import.meta.dir, "./services", service);
  //     const service_module = await import(service_path);

  //     running_services.push(
  //       service_module.default()
  //         .then(() => {
  //           logger.write(LogLevel.Info, `${service} has started successfully.`);
  //         })
  //         .catch((err: Error) => {
  //           logger.write(LogLevel.Warn, `${service} has crashed:`, err);
  //         })
  //     );
  //   } catch (err) {
  //     logger.write(LogLevel.Warn, `Failed to load ${service}: `, err);
  //   } finally {
  //     logger.write(LogLevel.Info, `Finished start job ${JOB_ID} for ${service}`);
  //   }
  // }

  // await Promise.all(running_services);

  try {
    logger.write(LogLevel.Info, "Starting backend server...");
    await run_service();
  } catch {
    logger.write(LogLevel.Error, "Failed to start the backend server");
    database.disconnect();
  }

  try {
    logger.write(LogLevel.Info, "Starting bot...");
    client.login(await get_env_variable("TOKEN"));
  } catch {
    logger.write(LogLevel.Error, "Failed to start the bot");
    database.disconnect();
  }
})();
