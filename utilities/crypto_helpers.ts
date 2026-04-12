import crypto from "crypto";

export const AES_MODE = "aes-256-gcm";
export const KEY_LENGTH = 32; // recommended length for AES-GCM
export const IV_LENGTH = 12; // recommended length for AES-GCM
export const TAG_LENGTH = 16;

export async function encrypt(plaintext: string, key: string): Promise<string> {
  if (key.length !== KEY_LENGTH) throw new Error("Key must be 32 bytes long");

  const initialization_vector = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(AES_MODE, key, initialization_vector);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final()
  ])

  const tag = cipher.getAuthTag();

  return Buffer.concat([initialization_vector, tag, encrypted]).toString("base64");
}

export async function decrypt(payload: string, key: string): Promise<string> {
  if (key.length !== KEY_LENGTH) throw new Error("Key must be 32 bytes long");

  const data = Buffer.from(payload, "base64");

  const iv = data.subarray(0, IV_LENGTH);
  const tag = data.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const encrypted = data.subarray(IV_LENGTH + TAG_LENGTH);

  const decipher = crypto.createDecipheriv(AES_MODE, key, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ])

  return decrypted.toString("utf8")
}

export async function decrypt_luau_string(payload: string, key: string): Promise<string> {
  /*
    IV length on luau side: 12 bytes
    Tag length on luau side: 16 bytes

    local function generate_api_key()
      ...

      return buffer.tostring(
        base64.encode(
          buffer.fromstring(
            table.concat(
              {buffer.tostring(iv), buffer.tostring(tag), buffer.tostring(ciphertext)}
            )
          )
        )
      )
    end
  */

  if (key.length !== KEY_LENGTH) throw new Error("Key must be 32 bytes long");

  const data = Buffer.from(payload, "base64");

  const iv = data.subarray(0, IV_LENGTH);
  const tag = data.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const ciphertext = data.subarray(IV_LENGTH + TAG_LENGTH);

  const decipher = crypto.createDecipheriv(AES_MODE, key, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ])

  return decrypted.toString("utf8")
}

export async function sign(data: string, key: string): Promise<string> {
  return crypto.createHmac("sha256", key).update(data).digest("hex")
}
