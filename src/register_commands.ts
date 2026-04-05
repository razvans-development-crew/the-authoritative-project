import { REST, Routes } from "discord.js";
import type { Command } from "./types/Command";
import { logger } from "./logging";

export async function register_commands(
  commands: Map<string, Command>,
  token: string,
  clientId: string,
  guildId?: string
) {
  const rest = new REST({ version: "10" }).setToken(token);

  const body = [...commands.values()].map(cmd => cmd.data.toJSON());

  if (guildId) {
    await rest.put(
      Routes.applicationGuildCommands(clientId, guildId),
      { body }
    );
    logger.info("Registered guild commands.");
  } else {
    await rest.put(
      Routes.applicationCommands(clientId),
      { body }
    );
    logger.info("Registered global commands.");
  }
}