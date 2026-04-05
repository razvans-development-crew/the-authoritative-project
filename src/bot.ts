import { logger } from "./logging.ts";
import { get_env_variable } from "./env_variables.ts";
import type { BaseInteraction, CommandInteraction, Interaction, InteractionResponse } from "discord.js";
import { load_commands } from "./command_loader.ts";
import { register_commands } from "./register_commands.ts";

const fs = require('node:fs');
const path = require('node:path');
const commands_path = path.join(import.meta.dir, "commands");
const commands = await load_commands(commands_path);
const database = require("./database.ts");
const TOKEN = await get_env_variable("TOKEN")!;
const CLIENT_ID = await get_env_variable("CLIENT_ID")!;

const { 
  Client, Collection, Events, 
  GatewayIntentBits, MessageFlags, 
  Partials, Routes, REST 
} = require('discord.js');

export const client = new Client({
  intents: [
    GatewayIntentBits.AutoModerationConfiguration,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildIntegrations,
    GatewayIntentBits.GuildInvites,
    GatewayIntentBits.GuildVoiceStates,
    GatewayIntentBits.GuildWebhooks,
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.DirectMessageReactions,
    GatewayIntentBits.DirectMessageTyping,
    GatewayIntentBits.MessageContent,
  ],
});

{
  (client as any).commands = commands;
  await register_commands(commands, TOKEN, CLIENT_ID);
}

client.once(Events.ClientReady, async (readyClient: typeof Client) => {
  logger.info(`Logged in as ${readyClient.user?.tag}`);
})

client.on(Events.InteractionCreate, async (interaction: BaseInteraction) => {
	if (!interaction.isChatInputCommand()) return;

    const command = commands.get(interaction.commandName);
    if (!command) return;

    try {
      await command.execute(interaction);
    } catch (err) {
      logger.error(err);
      await interaction.reply({
        content: "> An error has occurred while executing the command.",
        ephemeral: true
      });
    }
});

export async function run_bot(): Promise<void> {
  client.login(await get_env_variable("TOKEN"));
}