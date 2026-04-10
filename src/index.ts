import { logger } from "./utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";
import { readdir } from "fs/promises";
import { pathToFileURL } from "url";
import { generate_random_string } from "./utilities/helpers.ts";
import path from "path";

export const uptime = new Date().getTime();

const database = require("./utilities/database.ts");

(async () => {
  const services_path = await readdir(path.join(import.meta.dir, "./services"));
  const running_services = [];

  for (const service of services_path) {
    const JOB_ID = generate_random_string(12);

    try {
      const service_path = path.join("./services", service);
      const service_url = pathToFileURL(service_path).href;
      const service_module = await import(service_url);

      running_services.push(
        await service_module.default()
          .catch((err: Error) => {
            logger.write(LogLevel.Warn, `${service} has crashed:`, err);
          })
          .then(() => {
            logger.write(LogLevel.Info, `${service} has started successfully.`);
          })
      );
    } catch (err) {
      logger.write(LogLevel.Warn, `Failed to load ${service}: `, err);
    } finally {
      logger.write(LogLevel.Info, `Finished start job ${JOB_ID} for ${service}`);
    }
  }

  await Promise.all(running_services)
})()
