import { SlashCommandBuilder, CommandInteraction} from "discord.js";
import { type Command } from "../types/Command.ts";

const command: Command = {
  data: new SlashCommandBuilder().setName('ping').setDescription('Pong! Returns the latency of the bot.'),
  async execute(interaction: CommandInteraction) {
    const sent = await interaction.reply({ content: '> Pinging...', withResponse: true });
    const websocket_latency = sent.client.ws.ping
    const api_latency = sent.resource?.message?.createdTimestamp as any - interaction.createdTimestamp;

    await interaction.editReply({
      content: `> Pong! \n> -# Websocket latency: \`${websocket_latency}ms\`\n> -# API latency: \`${api_latency}ms\``
    });
  },
}

export default command;
