import { Client, Events, GatewayIntentBits } from 'discord.js';
import { get_env_variable } from "../utilities/env_variables.ts";

const client = new Client({ intents: [GatewayIntentBits.Guilds] });
const token = await get_env_variable("TOKEN");

client.once(Events.ClientReady, (readyClient: typeof client) => {
	console.log(`Logged in as ${readyClient.user?.tag}`);
});

export async function run_service(): Promise<void> {
  client.login(token);
}

export default run_service;
