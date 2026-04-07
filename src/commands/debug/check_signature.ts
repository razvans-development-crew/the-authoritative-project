import { type Command } from "../../types/Command";
import { SlashCommandBuilder, ChatInputCommandInteraction } from "discord.js";
import { registry } from "../../registry.ts";
import { logger } from "../../logging.ts";
import { LogLevel } from "@sapphire/framework";
import { check_api_key, check_signature } from "../../security.ts";

const preconditions = require("../../preconditions.ts");

export const command: Command = {
  data: new SlashCommandBuilder()
    .setName("check-signature")
    .setDescription("Check if the signature is valid.")
    .addStringOption(o => o
      .setName("signature")
      .setDescription("The signature.")
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

    const signature = interaction.options.getString("signature");

    if (!signature) {
      await interaction.followUp({ content: '> No signature provided.' });
      return;
    }

    if (!await check_signature(signature)) {
      await interaction.followUp({ content: '> Invalid signature.' });
      return;
    }

    await interaction.followUp({ content: '> Signature is valid.' });
  }
}

export default command;
