import https from "https";
import { logger } from "../utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";

export async function run_service(): Promise<void> {
  logger.write(LogLevel.Info, "Checking if Discord's gateway is reachable...");

  https.get("https://gateway.discord.gg", (res) => {
    logger.write(LogLevel.Info, "Discord's gateway is reachable.");
  }).on("error", (err) => {
    logger.write(LogLevel.Error, "Discord's gateway is not reachable.");
    logger.write(LogLevel.Error, err);
  });
}

export default run_service;
