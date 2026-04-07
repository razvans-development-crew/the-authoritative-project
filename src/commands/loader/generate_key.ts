import { type Command } from "../../types/Command";
import { SlashCommandBuilder, ChatInputCommandInteraction } from "discord.js";
import { registry } from "../../registry.ts";
import { logger } from "../../logging.ts";
import { LogLevel } from "@sapphire/framework";

const preconditions = require("../../preconditions.ts");

export const command: Command = {
  data: new SlashCommandBuilder()
    .setName("generate-key")
    .setDescription("Generates an authentication key for the loader.")
    .addStringOption(o => o
      .setName("key")
      .setDescription("The authentication key.")
      .setRequired(true)
    ),
  async execute(interaction: ChatInputCommandInteraction) {
    if (!interaction.deferred) {
      await interaction.deferReply({flags: "Ephemeral"});
    }

    if (await preconditions.is_dc_user_id_owner(interaction.user.id) === false) {
      await interaction.followUp({ content: '> Missing privilege level: `6`.\n> -# Note: this command is temporarily only available to the owner for testing.' });
      return;
    }
  }
}

export default command;
