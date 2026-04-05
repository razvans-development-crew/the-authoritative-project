import { Client, GatewayIntentBits, REST, Routes, Events } from "discord.js";
import { logger } from "./logging.ts";
import { get_env_variable } from "./env_variables.ts";

const database = require("./database.ts");
const client = new Client({
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

client.once(Events.ClientReady, (readyClient) => {
  logger.info(`Logged in as ${readyClient.user?.tag}!`);
})

export async function run_bot(): Promise<void> {
  client.login(await get_env_variable("TOKEN"));
}