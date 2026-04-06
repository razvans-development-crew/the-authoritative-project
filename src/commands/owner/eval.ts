import { SlashCommandBuilder, CommandInteraction, ChatInputCommandInteraction} from "discord.js";
import { type Command } from "../../types/Command.ts";

const preconditions = require("../../preconditions.ts");

const command: Command = {
  data: new SlashCommandBuilder()
    .setName('eval')
    .setDescription('Evaluates a javascript expression.')
    .addStringOption(option =>
      option
        .setName('expression')
        .setDescription('The expression to evaluate')
        .setRequired(true)
    ),
  async execute(interaction: ChatInputCommandInteraction) {
    if (!await preconditions.is_dc_user_id_owner(interaction.user.id)) {
      await interaction.reply({ content: '> You are not the owner of this bot.' });
      return;
    }

    const expression = interaction.options.getString('expression');
    const result = eval(String(expression));

    await interaction.reply({ content: '```' + result + '```' });
  },
}

export default command;
