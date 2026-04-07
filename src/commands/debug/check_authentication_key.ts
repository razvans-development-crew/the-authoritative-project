import { type Command } from "../../types/Command";
import { SlashCommandBuilder, ChatInputCommandInteraction } from "discord.js";
import { registry } from "../../registry.ts";
import { logger } from "../../logging.ts";
import { LogLevel } from "@sapphire/framework";
import { check_api_key } from "../../security.ts";

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

    try {
      const result = await check_api_key(interaction.options.getString("key") ?? "No key provided");

      if (result === true) {
        await interaction.followUp({ content: '> Test successful (API key verification): API key is valid' });
        logger.write(LogLevel.Info, `Test successful (API key verification): API key is valid`);
        return;
      }
    } catch (err) {
      await interaction.followUp({ content: '> An error has occurred while checking the API key.' });
      logger.write(LogLevel.Error, `Exception while checking API key: ${err}`);

      return;
    }
  }
}

export default command;
