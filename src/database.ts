import { PrismaClient } from "@prisma/client";

export const prisma = new PrismaClient();

export async function connect() {
  await prisma.$connect();
}

export async function disconnect() {
  await prisma.$disconnect();
}

export async function get_whitelists() {
  let raw_whitelists = await prisma.tAPWhitelist.findMany();
  let whitelists: Record<string, any> = {};

  for (let whitelist of raw_whitelists) {
    whitelists[String(whitelist.discord_user_id)] = {
      discord_user_id: whitelist.discord_user_id,
      rx_user_id: Number(whitelist.rx_user_id),
      rx_user_name: whitelist.rx_user_name,
      rank: whitelist.rank,
      privilege_level: whitelist.privilege_level,
    }
  }

  return whitelists
}

export async function get_global_user_bans() {
  let raw_global_user_bans = await prisma.tAPGlobalUserBan.findMany();
  let global_user_bans: Record<string, any> = {};

  for (let global_user_ban of raw_global_user_bans) {
    global_user_bans[String(global_user_ban.rx_user_id)] = {
      moderator_dc_id: global_user_ban.moderator_dc_id,
      rx_user_id: Number(global_user_ban.rx_user_id),
      rx_user_name: global_user_ban.rx_user_name,
      reason: global_user_ban.reason,
      duration: global_user_ban.duration,
      banned_at: global_user_ban.banned_at,
    }
  }

  return global_user_bans
}

export async function get_global_group_bans() {
  let raw_global_group_bans = await prisma.tAPGlobalGroupBan.findMany();
  let global_group_bans: Record<string, any> = {};

  for (let global_group_ban of raw_global_group_bans) {
    global_group_bans[String(global_group_ban.rx_group_id)] = {
      moderator_dc_id: global_group_ban.moderator_dc_id,
      rx_group_id: global_group_ban.rx_group_id,
      rx_group_name: Number(global_group_ban.rx_group_name),
      reason: global_group_ban.reason,
      duration: global_group_ban.duration,
    }
  };

  return global_group_bans
}

export async function get_legacy_whitelists() {
  let raw_legacy_whitelists = await prisma.whitelist.findMany();
  let legacy_whitelists: Record<string, any> = {};

  for (let legacy_whitelist of raw_legacy_whitelists) {
    legacy_whitelists[String(legacy_whitelist.dc_user_id)] = {
      discord_user_id: legacy_whitelist.dc_user_id,
      rx_user_name: legacy_whitelist.rx_user_name,
      rx_user_id: Number(legacy_whitelist.rx_user_id),
      rank: legacy_whitelist.rank,
      privilege_level: legacy_whitelist.privilege_level,
    }
  };

  return legacy_whitelists;
}

export async function get_legacy_global_user_bans() {
  let raw_legacy_global_user_bans = await prisma.global_user_ban.findMany();
  let legacy_global_user_bans: Record<string, any> = {};

  for (let legacy_global_user_ban of raw_legacy_global_user_bans) {
    legacy_global_user_bans[String(legacy_global_user_ban.rx_user_id)] = {
      moderator_dc_id: legacy_global_user_ban.moderator,
      rx_user_id: Number(legacy_global_user_ban.rx_user_id),
      rx_user_name: legacy_global_user_ban.rx_user_name,
      reason: legacy_global_user_ban.reason,
      banned_at: legacy_global_user_ban.banned_at,
    }
  }

  return legacy_global_user_bans;
}

export async function get_legacy_global_group_bans() {
  let raw_legacy_global_group_bans = await prisma.global_group_ban.findMany()
  let legacy_global_group_bans: Record<string, any> = {};

  for (let legacy_global_group_ban of raw_legacy_global_group_bans) {
    legacy_global_group_bans[String(legacy_global_group_ban.group_id)] = {
      moderator_dc_id: legacy_global_group_ban.moderator,
      group_id: Number(legacy_global_group_ban.group_id),
      group_name: legacy_global_group_ban.group_name,
      reason: legacy_global_group_ban.reason,
      banned_at: legacy_global_group_ban.banned_at
    }
  }

  return legacy_global_group_bans
}

export async function jsonify(obj: any) {
  return JSON.stringify(obj);
}

export async function get_expired_bans() {
  let current_bans = await prisma.tAPGlobalUserBan.findMany();
  let expired_bans: Array<any> = [];

  for (let ban of current_bans) {
    if (ban.duration == -1 ) { continue };

    if ((new Date(ban.banned_at).getTime() + ban.duration * 24 * 60 * 60 * 1000) < new Date().getTime()) {
      expired_bans.push({
        moderator_dc_id: ban.moderator_dc_id,
        rx_user_id: Number(ban.rx_user_id),
        rx_user_name: ban.rx_user_name,
        reason: ban.reason,
        duration: ban.duration,
        banned_at: ban.banned_at
      })
    }
  }

  return expired_bans
}

export async function get_expired_group_bans() {
  let current_bans = await prisma.tAPGlobalGroupBan.findMany();
  let expired_bans: Array<any> = [];

  for (let ban of current_bans) {
    if ((new Date(ban.banned_at).getTime() + ban.duration * 24 * 60 * 60 * 1000) < new Date().getTime()) {
      expired_bans.push({
        moderator_dc_id: ban.moderator_dc_id,
        rx_group_id: ban.rx_group_id,
        rx_group_name: ban.rx_group_name,
        reason: ban.reason,
        duration: ban.duration,
      })
    }
  }

  return expired_bans
}
