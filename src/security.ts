import crypto from "crypto";
import { logger } from "./logging.ts";
import { LogLevel } from "@sapphire/framework";
import { get_env_variable } from "./env_variables.ts";

const AES_ENCRYPTION_KEY = await get_env_variable("AES_ENCRYPTION_KEY");               // 256-bit (32-byte) key
const AES_INITIALIZATION_VECTOR = await get_env_variable("AES_INITIALIZATION_VECTOR"); // 16-byte initialization vector
const SECRET_KEY = await get_env_variable("SECRET_KEY");                               // 512-bit (64-byte) key
const SIGNATURE_KEY = await get_env_variable("SIGNATURE_KEY");                         // 512-bit (64-byte) key

export async function get_all_valid_api_keys(): Promise<Array<string>> {
  logger.write(LogLevel.Info, "API keys are being generated...");

  const api_keys: Array<string> = [];

  // "DATE_TIME_STRING:SECRET_KEY"
  for (let i = 0; i < 8000; i++) {
    const date_time_string = new Date().toISOString().slice(0, 19);
    const cipher = crypto.createCipheriv("aes-256-ctr", AES_ENCRYPTION_KEY, AES_INITIALIZATION_VECTOR);

    let encrypted = cipher.update(date_time_string + ":" + SECRET_KEY, "utf8", "hex");
    encrypted += cipher.final("hex");

    api_keys.push(String(Buffer.from(encrypted).toString("base64")))
  }

  return api_keys; // array of encrypted API keys
}

export async function check_api_key(encrypted_api_key: string): Promise<boolean> {
  logger.write(LogLevel.Info, "An API key is being checked...");

  // check first if the encrypted api key is valid
  // then check if their decrypted versions are valid
  // then check if they are properly signatured

  // we first check if the api key is first encoded with base64

  try {
    Buffer.from(encrypted_api_key, "base64").toString("utf8");
  } catch {
    logger.write(LogLevel.Info, "The specified API key is not base64 encoded");
    return false;
  }

  const api_keys = await get_all_valid_api_keys();

  for (const api_key of api_keys) {
    if (api_key === encrypted_api_key) {
      const decipher = crypto.createDecipheriv("aes-256-ctr", AES_ENCRYPTION_KEY, AES_INITIALIZATION_VECTOR);
      let decrypted_api_key_to_check = decipher.update(Buffer.from(encrypted_api_key, "base64").toString("utf8"), "hex", "utf8");
      decrypted_api_key_to_check += decipher.final("utf8");

      // trying to add data to the previous decipher will cause an unsupported state error, therefore we create a new one
      const new_decipher = crypto.createDecipheriv("aes-256-ctr", AES_ENCRYPTION_KEY, AES_INITIALIZATION_VECTOR);
      let decrypted_api_key_to_check_against = new_decipher.update(Buffer.from(encrypted_api_key, "base64").toString("utf8"), "hex", "utf8");
      decrypted_api_key_to_check_against += new_decipher.final("utf8");

      let decrypted_key_without_signature = decrypted_api_key_to_check.split(":")[0] + ":" + decrypted_api_key_to_check.split(":")[1];

      if (decrypted_key_without_signature === decrypted_api_key_to_check_against) {
        // key coming from the client should be the exact following: "DATE_TIME_STRING:SECRET_KEY:SIGNATURE_HASH"
        const signature = decrypted_api_key_to_check.split(":")[2];

        if (signature) {
          // hash the decrypted key against the signature, then check if the hash matches the signature
          const hash = crypto.createHash("sha256").update(decrypted_key_without_signature + ":" + SIGNATURE_KEY).digest("hex");
          if (hash === signature) {
            logger.write(LogLevel.Info, "A valid API key was provided. API key: " + encrypted_api_key);
            return true;
          }
        } else {
          logger.write(LogLevel.Info, "The specified API key is not properly signatured");
          return false;
        }
      }
    }
  }

  logger.write(LogLevel.Info, "An invalid API key was provided. API key: " + encrypted_api_key);
  return false;
}

export async function check_signature(signatured_key: string): Promise<boolean> {
  logger.write(LogLevel.Info, "A signature is being checked...");

  // "DATE_TIME_STRING:RANDOM_STRING:SIGNATURE_HASH"
  // it is also encrypted using the encryption key

  // the signature hash is the SHA256 hash of the
  // decrypted key with the signature key appended to it

  const decipher = crypto.createDecipheriv("aes-256-ctr", AES_ENCRYPTION_KEY, AES_INITIALIZATION_VECTOR);
  let decrypted_signature_to_check = decipher.update(Buffer.from(signatured_key, "base64").toString("utf8"), "hex", "utf8");
  decrypted_signature_to_check += decipher.final("utf8");

  if (decrypted_signature_to_check.split(":")[2]) {
    const signature = decrypted_signature_to_check.split(":")[2];
    const hash = crypto.createHash("sha256").update(decrypted_signature_to_check + ":" + SIGNATURE_KEY).digest("hex");

    if (hash === signature) {
      logger.write(LogLevel.Info, "A valid signature was provided. Signature: " + signatured_key);
      return true;
    }

    logger.write(LogLevel.Info, "The specified signature didn't have a valid signature: " + signatured_key);
  }

  logger.write(LogLevel.Info, "The specified signature wasn't valid: " + signatured_key);
  return false;
}

