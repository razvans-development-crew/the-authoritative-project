import https from "https";
import { logger } from "../utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";

export async function run_service(): Promise<void> {
  logger.write(LogLevel.Info, "Checking if Discord's gateway at gateway.discord.gg is reachable...");

  https.get("https://gateway.discord.gg", (res) => {
    logger.write(LogLevel.Info, "Discord's gateway at gateway.discord.gg is reachable, status code: " + res.statusCode);
  }).on("error", (err) => {
    logger.write(LogLevel.Error, "Discord's gateway at gateway.discord.gg is not reachable.");
    logger.write(LogLevel.Error, err);
  });

  https.get("https://discord.com/api/v10/gateway", (res) => {
    logger.write(LogLevel.Info, "Discord's gateway at discord.com/api/v10/gateway is reachable, status code: " + res.statusCode);
  }).on("error", (err) => {
    logger.write(LogLevel.Error, "Discord's gateway at discord.com/api/v10/gateway is not reachable.");
    logger.write(LogLevel.Error, err);
  });
}

export default run_service;
