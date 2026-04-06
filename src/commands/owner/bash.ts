import { SlashCommandBuilder, CommandInteraction, ChatInputCommandInteraction} from "discord.js";
import { type Command } from "../../types/Command.ts";
import { exec } from "node:child_process";

const preconditions = require("../../preconditions.ts");

const command: Command = {
  data: new SlashCommandBuilder()
    .setName('bash')
    .setDescription('Runs a bash command.')
    .addStringOption(option =>
      option
        .setName('command')
        .setDescription('The command to run')
        .setRequired(true)
    ),
  async execute(interaction: ChatInputCommandInteraction) {
    if (!await preconditions.is_dc_user_id_owner(interaction.user.id)) {
      await interaction.reply({ content: '> You are not the owner of this bot.' });
      return;
    }

    const command = interaction.options.getString('command');
    exec(String(command), async (err, stdout, stderr) => {
      if (err) {
        await interaction.reply("```" + err + "```");
        return;
      }
      
      await interaction.reply("```" + stdout + "```");
    });
  },
}

export default command;
