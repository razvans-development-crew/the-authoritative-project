import { SlashCommandBuilder, CommandInteraction, Client} from "discord.js";
import { client } from "../../bot.ts";

module.exports = {
  data: new SlashCommandBuilder()
    .setName('ping')
    .setDescription('Pong! Returns the latency of the bot.'),
  async execute(interaction: CommandInteraction) {
    const sent = await interaction.reply({ content: '> Pinging...', fetchReply: true });

    const latency = sent.createdTimestamp - interaction.createdTimestamp;
    const ws_ping = Math.round(client.ws.ping);

    const uptime_ms = client.uptime;
    const uptime = `${Math.floor(uptime_ms / 3600000)}h ${Math.floor((uptime_ms % 3600000) / 60000)}m ${Math.floor((uptime_ms % 60000) / 1000)}s`;

    await interaction.editReply({
      content: `> Pong! Latency: ${latency}ms, WS ping: ${ws_ping}ms, Uptime: ${uptime}`
    });
  },
}