import { REST, Routes } from "discord.js";
import type { Command } from "./types/Command";
import { logger } from "./logging";
import { LogLevel } from "@sapphire/framework";
import { SlashCommandBuilder } from "discord.js";

export async function register_commands(
  commands: Map<string, Command>,
  token: string,
  clientId: string,
  guildId?: string
) {
  const rest = new REST({ version: "10" }).setToken(token);

  const grouped: Map<string, Command[]> = new Map();
  const topLevel: Command[] = [];

  for (const cmd of commands.values()) {
    if (cmd.group) {
      if (!grouped.has(cmd.group)) grouped.set(cmd.group, []);
      grouped.get(cmd.group)!.push(cmd);
    } else {
      topLevel.push(cmd);
    }
  }

  const body = [];

  for (const cmd of topLevel) {
    body.push(cmd.data.toJSON());
  }

  for (const [groupName, groupCommands] of grouped.entries()) {
    const parentCommand = new SlashCommandBuilder()
      .setName(groupName)
      .setDescription(`commands for ${groupName}`);

    for (const cmd of groupCommands) {
      parentCommand.addSubcommand(sub =>
        sub.setName(cmd.data.name).setDescription(cmd.data.description || "No description")
      );
    }

    body.push(parentCommand.toJSON());
  }

  if (guildId) {
    await rest.put(Routes.applicationGuildCommands(clientId, guildId), { body });
    logger.write(LogLevel.Info, "Registered guild commands.");
  } else {
    await rest.put(Routes.applicationCommands(clientId), { body });
    logger.write(LogLevel.Info, "Registered global commands.");
  }
}
