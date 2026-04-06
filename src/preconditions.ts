const env_variables = require("./env_variables.ts");
const database = require("./database.ts");

export async function is_dc_user_id_owner(to_check: string): Promise<boolean> {
  return (await env_variables.get_env_variable("OWNER") == to_check)
}

export async function is_dc_user_id_admin(to_check: string): Promise<boolean> {
  let whitelist = await database.prisma.tAPWhitelist.findFirst({
    where: {
      discord_user_id: to_check
    }
  });

  return whitelist.privilege_level === 5 || await env_variables.get_env_variable("OWNER") == to_check
}

export async function is_rx_user_id_admin(to_check: string): Promise<boolean> {
  let whitelist = await database.prisma.tAPWhitelist.findFirst({
    where: {
      rx_user_id: Number(to_check)
    }
  });

  return whitelist.privilege_level === 5
}

export async function is_dc_user_id_capable_to_ban_users(to_check: string): Promise<boolean> {
  let whitelist = await database.prisma.tAPWhitelist.findFirst({
    where: {
      dc_user_id: to_check
    }
  });

  return whitelist.privilege_level >= 3 || await env_variables.get_env_variable("OWNER") == to_check
}

export async function is_dc_user_id_capable_to_ban_groups(to_check: string): Promise<boolean> {
  let whitelist = await database.prisma.tAPWhitelist.findFirst({
    where: {
      dc_user_id: to_check
    }
  });

  return whitelist.privilege_level >= 4 || await env_variables.get_env_variable("OWNER") == to_check
}
