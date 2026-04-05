import { SlashCommandBuilder, CommandInteraction, Client} from "discord.js";

module.exports = {
  data: new SlashCommandBuilder()
    .setName('ping')
    .setDescription('Pong! Returns the latency of the bot.'),
  async execute(interaction: CommandInteraction) {
    await interaction.reply('pong!');
  },
}