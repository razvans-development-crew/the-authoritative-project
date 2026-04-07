import { type Command } from "../../types/Command";
import { SlashCommandBuilder, ChatInputCommandInteraction } from "discord.js";
import { registry } from "../../registry.ts";
import { logger } from "../../logging.ts";
import { LogLevel } from "@sapphire/framework";
import { get_all_valid_api_keys, check_api_key, check_signature } from "../../security.ts";

const preconditions = require("../../preconditions.ts");

export const command: Command = {
  data: new SlashCommandBuilder()
    .setName("test-api-key-generation")
    .setDescription("Tests the API key generation."),
  async execute(interaction: ChatInputCommandInteraction) {
    if (!interaction.deferred) {
      await interaction.deferReply({flags: "Ephemeral"});
    }

    if (await preconditions.is_dc_user_id_owner(interaction.user.id) === false) {
      await interaction.followUp({ content: '> Missing privilege level: `6`.' });
      return;
    }

    logger.write(LogLevel.Info, "[TEST] API keys are being generated...");
    const api_key = (await get_all_valid_api_keys())[7998];
    logger.write(LogLevel.Info, `[TEST] Generated API key: ${api_key}`);

    logger.write(LogLevel.Info, "[TEST] An API key is being checked...");
    if (!api_key) {
      await interaction.followUp({ content: '> Test failed: No API key generated.' });
      logger.write(LogLevel.Info, "[TEST] No API key generated.");
      return;
    }

    const is_api_key_valid = await check_api_key(api_key);

    if (is_api_key_valid) {
      await interaction.followUp({ content: '> Test successful: API key is valid.' });
      logger.write(LogLevel.Info, "[TEST] API key is valid.");
    } else {
      await interaction.followUp({ content: '> Test failed: API key is invalid.' });
      logger.write(LogLevel.Info, "[TEST] API key is invalid.");
    }
  }
}

export default command;
