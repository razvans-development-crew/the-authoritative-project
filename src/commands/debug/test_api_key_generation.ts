import { type Command } from "../../types/Command";
import { SlashCommandBuilder, ChatInputCommandInteraction } from "discord.js";
import { registry } from "../../registry.ts";
import { logger } from "../../logging.ts";
import { LogLevel } from "@sapphire/framework";
import { get_all_valid_api_keys, check_api_key, check_signature } from "../../security.ts";
import crypto from "crypto";
import { get_env_variable } from "../../env_variables.ts";

const preconditions = require("../../preconditions.ts");

const AES_ENCRYPTION_KEY = await get_env_variable("AES_ENCRYPTION_KEY");               // 256-bit (32-byte) key
const AES_INITIALIZATION_VECTOR = await get_env_variable("AES_INITIALIZATION_VECTOR"); // 16-byte initialization vector
const SIGNATURE_KEY = await get_env_variable("SIGNATURE_KEY");                         // 512-bit (64-byte) key

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

    // sign the API key
    let signed_encrypted_api_key;

    {
      const decipher = crypto.createDecipheriv("aes-256-ctr", AES_ENCRYPTION_KEY, AES_INITIALIZATION_VECTOR);
      let decrypted_api_key_to_check = decipher.update(Buffer.from(api_key, "base64").toString("utf8"), "hex", "utf8");
      decrypted_api_key_to_check += decipher.final("utf8");

      let decrypted_key_without_signature = decrypted_api_key_to_check.split(":")[0] + ":" + decrypted_api_key_to_check.split(":")[1];

      const signature = crypto.createHash("sha256").update(decrypted_key_without_signature + ":" + SIGNATURE_KEY).digest("hex");

      signed_encrypted_api_key = Buffer.from(decrypted_api_key_to_check + ":" + signature).toString("base64");
    }

    const is_api_key_valid = await check_api_key(signed_encrypted_api_key);

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
