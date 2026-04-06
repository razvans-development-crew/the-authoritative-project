import crypto from "crypto";
import { logger } from "./logging.ts";
import { LogLevel } from "@sapphire/framework";
import { get_env_variable } from "./env_variables.ts";

const AES_ENCRYPTION_KEY = await get_env_variable("AES_ENCRYPTION_KEY");               // 256-bit (32-byte) key
const AES_INITIALIZATION_VECTOR = await get_env_variable("AES_INITIALIZATION_VECTOR"); // 16-byte initialization vector
const SECRET_KEY = await get_env_variable("SECRET_KEY");                               // 256-bit (32-byte) key

export async function get_all_valid_api_keys(): Promise<string[]> {
  logger.write(LogLevel.Info, "API keys are being generated...");

  const api_keys: string[] = [];

  // "DATE_TIME_STRING:SECRET_KEY"
  for (let i = 0; i < 8; i++) {
    const date_time_string = new Date().toISOString().replace(/[-:.]/g, "");
    const cipher = crypto.createCipheriv("aes-256-cbc", AES_ENCRYPTION_KEY, AES_INITIALIZATION_VECTOR);

    let encrypted = cipher.update(date_time_string + ":" + SECRET_KEY, "utf8", "hex");
    encrypted += cipher.final("hex");

    api_keys.push(Buffer.from(encrypted, "base64").toString("utf8"))

    logger.write(LogLevel.Info, `Generated API key ${i + 1} (encrypted): ${api_keys[i]}`);
  }

  return api_keys;
}
