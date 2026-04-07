import { type Command } from "../../types/Command";
import { SlashCommandBuilder, ChatInputCommandInteraction } from "discord.js";
import { registry } from "../../registry.ts";
import { logger } from "../../logging.ts";
import { LogLevel } from "@sapphire/framework";
import { check_api_key } from "../../security.ts";
import { encrypt, sign } from "../../crypto_helpers.ts";
import crypto from "crypto";
import { get_env_variable } from "../../env_variables.ts";

const preconditions = require("../../preconditions.ts");

const AES_ENCRYPTION_KEY = await get_env_variable("AES_ENCRYPTION_KEY");
const SECRET_KEY = await get_env_variable("SECRET_KEY");
const SIGNATURE_KEY = await get_env_variable("SIGNATURE_KEY");

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

    const key = Date.now() + ":" + SECRET_KEY;
    const signature = await sign(key, SIGNATURE_KEY);
    const signed_key = key + ":" + signature;
    const encrypted_key = await encrypt(signed_key, AES_ENCRYPTION_KEY);

    logger.write(LogLevel.Info, `Generated API key: ${encrypted_key}`);

    const result = await check_api_key(encrypted_key);

    if (result === true) {
      await interaction.followUp({ content: '> Test successful (API key verification): API key is valid' });
      logger.write(LogLevel.Info, `Test successful (API key verification): API key is valid`);
      return;
    }

    await interaction.followUp({ content: '> Test failed (API key verification): API key is invalid' });
    logger.write(LogLevel.Info, `Test failed (API key verification): API key is invalid`);
  }
}

export default command;
