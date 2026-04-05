import { SlashCommandBuilder, CommandInteraction} from "discord.js";
import { type Command } from "../../types/Command.ts";

const preconditions = require("../../preconditions.ts");

const command: Command = {
  data: new SlashCommandBuilder().setName('test').setDescription('Literally does nothing but send a message.'),
  async execute(interaction: CommandInteraction) {
    if (!await preconditions.is_owner(interaction.user.id)) {
      await interaction.reply({ content: '> You are not the owner of this bot.' });
      return;
    }

    await interaction.reply({ content: '> hi' });
  },
}

export default command;