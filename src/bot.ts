import { logger } from "./logging.ts";
import { get_env_variable } from "./env_variables.ts";
import { UserFlagsBitField, type BaseInteraction, type CommandInteraction, type Interaction, type InteractionResponse } from "discord.js";
import { load_commands } from "./command_loader.ts";
import { register_commands } from "./register_commands.ts";
import { LogLevel } from "@sapphire/framework";

const fs = require('node:fs');
const path = require('node:path');
const commands_path = path.join(import.meta.dir, "commands");
const commands = await load_commands(commands_path);
const database = require("./database.ts");
const TOKEN = await get_env_variable("TOKEN")!;
const CLIENT_ID = await get_env_variable("CLIENT_ID")!;
const {
  DefaultWebSocketManagerOptions: { identifyProperties }
} = require("@discordjs/ws");

const {
  Client, Collection, Events,
  GatewayIntentBits, MessageFlags,
  Partials, Routes, REST, ActivityType
} = require('discord.js');

identifyProperties.browser = "Discord iOS"; // discord embedded
identifyProperties.device = "linux"; // xbox series x/s
identifyProperties.os = "linux"; // linux

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
  partials: [
    Partials.Channel,
		Partials.GuildMember,
		Partials.GuildScheduledEvent,
		Partials.Message,
		Partials.Reaction,
		Partials.ThreadMember,
		Partials.User
  ],
  logger: {
    instance: logger
  },
  ws: {
    properties: {
      $browser: "Discord iOS"
    }
  },
  presence: {
    status: "dnd",
    activities: [
      {
        name: "https://112x4.scriptlang.com/",
        state: "https://112x4.scriptlang.com/",
        type: ActivityType.Watching
      }
    ]
  }
});

{
  (client as any).commands = commands;
  await register_commands(commands, TOKEN, CLIENT_ID);
}

client.once(Events.ClientReady, async (readyClient: typeof Client) => {
  logger.write(LogLevel.Info, `Logged in as ${readyClient.user?.tag}`);
})

client.on(Events.InteractionCreate, async (interaction: BaseInteraction) => {
	if (!interaction.isChatInputCommand()) return;

  let command_name = interaction.commandName;

  try {
    const sub = interaction.options.getSubcommand(false);
    if (sub) command_name = sub;
  } catch {
    // ignore, indicates there is no subcommand
  }

  const command = commands.get(interaction.commandName);
  if (!command) return;

  try {
    await command.execute(interaction);
    logger.write(
      LogLevel.Info,
      `(${interaction.commandName}${command.group ? ` ${command_name}` : ""}) ${interaction.user.globalName} (<@${interaction.user.id}>)`
    );
  } catch (err) {
    logger.write(LogLevel.Error, `Error executing command ${interaction.commandName}: ${err}`);
    await interaction.reply({
      content: "> An error has occurred while executing the command.",
      ephemeral: true
    });
  }
});

export async function run_bot(): Promise<void> {
  client.login(await get_env_variable("TOKEN"));
}
