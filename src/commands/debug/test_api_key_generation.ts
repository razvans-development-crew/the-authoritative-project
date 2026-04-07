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
    .setDescription("Tests the API key generation.")
    .addBooleanOption(
      o => o
        .setName("check-as-expired")
        .setDescription("Waits 3.5 seconds before checking the API key.")
        .setRequired(false)
    )
    .addBooleanOption(
      o => o
        .setName("invalid-signature")
        .setDescription("Checks the API key with an invalid signature.")
        .setRequired(false)
    ),
  async execute(interaction: ChatInputCommandInteraction) {
    if (!interaction.deferred) {
      await interaction.deferReply({flags: "Ephemeral"});
    }

    if (await preconditions.is_dc_user_id_owner(interaction.user.id) === false) {
      await interaction.followUp({ content: '> Missing privilege level: `6`.' });
      return;
    }

    const check_as_expired = interaction.options.getBoolean("check-as-expired") ?? false;
    const invalid_signature = interaction.options.getBoolean("invalid-signature") ?? false;

    const key = new Date().toISOString().slice(0, 19) + "|" + SECRET_KEY;

    if (check_as_expired === true) { await new Promise(r => setTimeout(r, 3500)); }

    let signature;

    if (invalid_signature === true) {
      signature = await sign(key, "invalid");
    } else {
      signature = await sign(key, SIGNATURE_KEY);
    }

    const signed_key = key + "|" + signature;
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
