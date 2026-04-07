import { type Command } from "../../types/Command";
import { SlashCommandBuilder, ChatInputCommandInteraction } from "discord.js";
import { registry } from "../../registry.ts";
import { logger } from "../../logging.ts";
import { LogLevel } from "@sapphire/framework";
import { check_api_key, check_signature } from "../../security.ts";

const preconditions = require("../../preconditions.ts");

export const command: Command = {
  data: new SlashCommandBuilder()
    .setName("check-authentication-key")
    .setDescription("Check if the authentication key is valid.")
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
      await interaction.followUp({ content: '> Missing privilege level: `6`.' });
      return;
    }

    const key = interaction.options.getString("key");

    if (!key) {
      await interaction.followUp({ content: '> No authentication key provided.' });
      return;
    }

    if (!await check_api_key(key)) {
      await interaction.followUp({ content: '> Invalid authentication key.' });
      return;
    }
  }
}

export default command;
