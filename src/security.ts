import crypto from "crypto";
import { logger } from "./logging.ts";
import { LogLevel } from "@sapphire/framework";
import { get_env_variable } from "./env_variables.ts";
import {
  decrypt,
  sign
} from "./crypto_helpers.ts";

const AES_ENCRYPTION_KEY = await get_env_variable("AES_ENCRYPTION_KEY");               // 256-bit (32-byte) key
// const AES_INITIALIZATION_VECTOR = await get_env_variable("AES_INITIALIZATION_VECTOR"); // 16-byte initialization vector (static IVs are not secure)
const SECRET_KEY = await get_env_variable("SECRET_KEY");                               // 512-bit (64-byte) key
const SIGNATURE_KEY = await get_env_variable("SIGNATURE_KEY");                         // 512-bit (64-byte) key

async function utc_string_to_unix_ms(utc_string: string): Promise<number> {
  const dt = new Date(utc_string + "Z");
  return dt.getTime();
}

export async function check_api_key(encrypted_api_key: string): Promise<boolean> {
  logger.write(LogLevel.Info, "Checking API key: " + encrypted_api_key);

  // decrypt the encrypted api key
  // then check if the decrypted api key is valid
  //
  // then extract the timestamp and generated if it is
  // within the last 10 seconds
  //
  // then extract the secret key from the api key and
  // check if it is valid
  //
  // then check if the api key is properly signatured
  //
  // the key should look something like this:
  // timestamp:secret_key:signature


  const decrypted_api_key_to_check = await decrypt(
    encrypted_api_key, AES_ENCRYPTION_KEY
  );

  const decrypted_data_to_check = {
    // formatted UTC string (%Y-%m-%dT%H:%M:%S)
    // converted to unix timestamp in milliseconds
    timestamp: decrypted_api_key_to_check.split(":")[0],

    secret_key: decrypted_api_key_to_check.split(":")[1],
    signature: decrypted_api_key_to_check.split(":")[2]
  }

  if (
    !decrypted_data_to_check.timestamp
    || !decrypted_data_to_check.secret_key
    || !decrypted_data_to_check.signature
  ) {
    logger.write(
      LogLevel.Info,
      `Invalid API key (missing data): ${encrypted_api_key}`,
      {
        missing_fields: {
          comment: "false = not missing, true = missing",
          timestamp: !decrypted_data_to_check.timestamp,
          secret_key: !decrypted_data_to_check.secret_key,
          signature: !decrypted_data_to_check.signature
        }
      }
    );
    return false;
  }

  if (
    (await utc_string_to_unix_ms(
      decrypted_data_to_check.timestamp
    ) - new Date().getTime()) >= 7500
  ) {
    logger.write(
      LogLevel.Info, `
      Invalid API key (lasted for more than 7.5 seconds): ${encrypted_api_key}`,
      {
        lasted_for: await utc_string_to_unix_ms(
          decrypted_data_to_check.timestamp
        ) - new Date().getTime()
      }
    );
    return false;
  }

  const expected_signature = await sign(
    decrypted_data_to_check.timestamp
    + ":"
    + decrypted_data_to_check.secret_key,
    SIGNATURE_KEY
  );

  if (expected_signature !== decrypted_data_to_check.signature) {
    logger.write(
      LogLevel.Info,
      `Invalid API key (signature mismatch): ${encrypted_api_key}`,
    {
      expected_signature: expected_signature,
      actual_signature: decrypted_data_to_check.signature
    });
    return false;
  }

  return true;
}
