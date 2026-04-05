import { logger } from "./logging.ts";
import { get_env_variable } from "./env_variables.ts";
import type { BaseInteraction, CommandInteraction, Interaction, InteractionResponse } from "discord.js";

const fs = require('node:fs');
const path = require('node:path');

const { 
  Client, Collection, Events, 
  GatewayIntentBits, MessageFlags, 
  Partials, Routes, REST 
} = require('discord.js');

const { token } = require('./config.json');

const database = require("./database.ts");
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

client.once(Events.ClientReady, (readyClient: typeof Client) => {
  logger.info(`Logged in as ${readyClient.user?.tag}!`);
})

client.commands = new Collection();

const foldersPath = path.join(__dirname, 'commands');
const commandFolders = fs.readdirSync(foldersPath);

for (const folder of commandFolders) {
	const commandsPath = path.join(foldersPath, folder);
	const commandFiles = fs.readdirSync(commandsPath).filter((file: string) => file.endsWith('.js'));
	for (const file of commandFiles) {
		const filePath = path.join(commandsPath, file);
		const command = require(filePath);
		// Set a new item in the Collection with the key as the command name and the value as the exported module
		if ('data' in command && 'execute' in command) {
			client.commands.set(command.data.name, command);
		} else {
			console.log(`[WARNING] The command at ${filePath} is missing a required "data" or "execute" property.`);
		}
	}
}

client.on(Events.InteractionCreate, async (interaction: BaseInteraction) => {
	if (!interaction.isChatInputCommand()) return;
	const command = (interaction.client as any).commands.get(interaction.commandName);

	if (!command) {
		console.error(`No command matching ${interaction.commandName} was found.`);
		return;
	}

	try {
		await command.execute(interaction);
	} catch (error) {
		console.error(error);
		if (interaction.replied || interaction.deferred) {
			await interaction.followUp({
				content: '> There was an error while executing this command',
				flags: MessageFlags.Ephemeral,
			});
		} else {
			await interaction.reply({
				content: '> There was an error while executing this command',
				flags: MessageFlags.Ephemeral,
			});
		}
	}
});

export async function run_bot(): Promise<void> {
  client.login(await get_env_variable("TOKEN"));
}