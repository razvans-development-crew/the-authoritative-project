import { SlashCommandBuilder, CommandInteraction, Client} from "discord.js";
import { type Command } from "../types/Command.ts";

const command: Command = {
  data: new SlashCommandBuilder().setName('ping').setDescription('Pong! Returns the latency of the bot.'),
  async execute(interaction: CommandInteraction) {
    const sent = await interaction.reply({ content: '> Pinging...', withResponse: true });
    const latency = sent.client.ws.ping // horrible solution: sent.interaction.createdTimestamp - interaction.createdTimestamp;

    await interaction.editReply({
      content: `> Pong! Latency: \`${latency}ms\``
    });
  },
}

export default command;