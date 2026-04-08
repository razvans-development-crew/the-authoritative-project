const env_variables = require("./utitlities/env_variables.ts");
const database = require("./utilities/database.ts");

export async function is_dc_user_id_owner(to_check: string): Promise<boolean> {
  return (await env_variables.get_env_variable("OWNER") == to_check)
}

export async function is_dc_user_id_admin(to_check: string): Promise<boolean> {
  let whitelist = await database.prisma.tAPWhitelist.findFirst({
    where: {
      discord_user_id: to_check
    }
  });

  if (await env_variables.get_env_variable("OWNER") == to_check) return true;
  if (!whitelist) return false;

  return whitelist.privilege_level === 5
}

export async function is_rx_user_id_admin(to_check: string): Promise<boolean> {
  let whitelist = await database.prisma.tAPWhitelist.findFirst({
    where: {
      rx_user_id: Number(to_check)
    }
  });

  if (!whitelist) return false;

  return whitelist.privilege_level === 5
}

export async function is_dc_user_id_capable_to_ban_users(to_check: string): Promise<boolean> {
  let whitelist = await database.prisma.tAPWhitelist.findFirst({
    where: {
      discord_user_id: to_check
    }
  });

  if (await env_variables.get_env_variable("OWNER") == to_check) return true;
  if (!whitelist) return false;

  return whitelist.privilege_level >= 3
}

export async function is_dc_user_id_capable_to_ban_groups(to_check: string): Promise<boolean> {
  let whitelist = await database.prisma.tAPWhitelist.findFirst({
    where: {
      discord_user_id: to_check
    }
  });

  if (await env_variables.get_env_variable("OWNER") == to_check) return true;
  if (!whitelist) return false;

  return whitelist.privilege_level >= 4
}

interface RobloxIPInfo {
  as: string,
  country_code: string,
  isp: string,
  org: string,
}

async function helper_obtain_ip_info(ip: string): Promise<any> {
  const response = await fetch(`https://ipinfo.io/${ip}/json`)
    .then(res => res.json())
    .catch(() => "No IP info found") ;


  return response;
}

export async function is_ip_from_roblox(ip: string): Promise<boolean> {
  const ip_info = await helper_obtain_ip_info(ip);

  const COUNTRY_CODES: Array<string> = ["AU", "GB", "JP", "US", "DE", "SG", "FR",
                 "CA", "NL", "SE", "BR", "KR", "IE", "IN",
                 "IT", "ES", "RU", "ZA"]

  const asn = ip_info?.as ?? "No ASN found";
  const isp = ip_info?.isp ?? "No ISP found";
  const country_code = ip_info?.country_code ?? "No country code found";
  const org = ip_info?.org ?? "No org found";

  if (isp != "Roblox" || !("roblox" in isp.toLowerCase())) {
    return false;
  }

  if (org == "Roblox" || !("roblox" in org.toLowerCase())) {
    return false;
  }

  if (!(country_code in COUNTRY_CODES)) {
    return false;
  }

  if (
    asn != "AS22697 Roblox"
    || asn != "AS11281 Roblox"
    || !("AS22697".toLowerCase() in asn.toLowerCase())
    || !("AS11281".toLowerCase() in asn.toLowerCase())
    || !("AS11281 Roblox".toLowerCase() in asn.toLowerCase())
    || !("AS136766".toLowerCase() in asn.toLowerCase())
  ) {
    return false
  }

  return true
}
