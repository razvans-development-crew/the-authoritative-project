import { logger } from "../utilities/logging.ts";
import { get_env_variable } from "../utilities/env_variables.ts";
import { UserFlagsBitField, type BaseInteraction, type CommandInteraction, type Interaction, type InteractionResponse } from "discord.js";
import { load_commands } from "../loaders/command_loader.ts";
import { register_commands } from "../loaders/register_commands.ts";
import { LogLevel } from "@sapphire/framework";
import { watch_for_expired_bans } from "../watchdogs/watch_for_expired_bans.ts";

const fs = require('node:fs');
const path = require('node:path');
const commands_path = path.join(import.meta.dir, "../commands");
const commands = await load_commands(commands_path);
const database = require("../utilities/database.ts");
const TOKEN = await get_env_variable("TOKEN")!;
const CLIENT_ID = await get_env_variable("CLIENT_ID")!;
const {
  DefaultWebSocketManagerOptions: { identifyProperties }
} = require("@discordjs/ws");

let ALREADY_RAN_EXPIRED_BANS_WATCHDOG = false;

import {
  Client, Collection, Events,
  GatewayIntentBits, MessageFlags,
  Partials, Routes, REST, ActivityType
} from 'discord.js';

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

client.once(Events.ClientReady, async (readyClient) => {
  logger.write(LogLevel.Info, `Logged in as ${readyClient.user?.tag}`);

  if (!ALREADY_RAN_EXPIRED_BANS_WATCHDOG) {
    ALREADY_RAN_EXPIRED_BANS_WATCHDOG = true;
    watch_for_expired_bans();
  }
})

client.on(Events.Error, async (error) => {
  logger.write(LogLevel.Error, `Discord client error:`, error);
})

client.on(Events.Debug, async (debug_msg) => {
  logger.write(LogLevel.Debug, `Debug:`, debug_msg);
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

  const command = commands.get(command_name);
  if (!command) return;

  try {
    await command.execute(interaction);
    logger.write(
      LogLevel.Info,
      `(${command_name}${command.group ? ` ${command_name}` : ""}) ${interaction.user.globalName} (<@${interaction.user.id}>)`
    );
  } catch (err) {
    logger.write(LogLevel.Error, `Exception while executing command ${command_name}: ${err}`, err);

    if (interaction.deferred) {
      await interaction.editReply({
        content: "> An error has occurred while executing the command."
      });
    } else {
      await interaction.reply({
        content: "> An error has occurred while executing the command.",
        flags: MessageFlags.Ephemeral
      });
    }
  }
});

export async function run_bot(): Promise<void> {
  logger.write(LogLevel.Info, "Starting bot...");

  try {
    await client.login(TOKEN);
    logger.write(LogLevel.Info, "Successfully logged in");
  } catch (err) {
    logger.write(LogLevel.Error, "Failed to log in", err);
    return;
  }
}
