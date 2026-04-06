const env_variables = require("./env_variables.ts");
const database = require("./database.ts");
import { logger } from "./logging.ts";
import { LogLevel } from "@sapphire/framework";

export async function is_dc_user_id_owner(to_check: string): Promise<boolean> {
  logger.write(LogLevel.Info, `${env_variables.get_env_variable("OWNER") == to_check}`);
  logger.write(LogLevel.Info , `${env_variables.get_env_variable("OWNER") === to_check}`);

  return (await env_variables.get_env_variable("OWNER") == to_check)
}

export async function is_dc_user_id_admin(to_check: string): Promise<boolean> {
  let whitelist = await database.prisma.tAPWhitelist.findFirst({
    where: {
      discord_user_id: to_check
    }
  });

  return whitelist.privilege_level === 5
}

export async function is_rx_user_id_admin(to_check: string): Promise<boolean> {
  let whitelist = await database.prisma.tAPWhitelist.findFirst({
    where: {
      rx_user_id: Number(to_check)
    }
  });

  return whitelist.privilege_level === 5
}
