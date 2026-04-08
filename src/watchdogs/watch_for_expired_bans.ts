import { logger } from "../utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";
import { get_expired_bans, get_expired_group_bans } from "../utilities/database.ts";

const database = require("../utilities/database.ts");

async function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function watch_for_expired_bans() {
  logger.write(LogLevel.Info, "Started watchdog for expired bans");

  while (true) {
    logger.write(LogLevel.Info, "Checking for expired bans...");

    try {
      const expired_bans = await get_expired_bans();
      const expired_group_bans = await get_expired_group_bans();

      for (let ban of expired_bans) {
        logger.write(LogLevel.Info, `Ban for ${ban.rx_user_name} (${ban.rx_user_id}) has expired.`);

        try {
          await database.prisma.tAPGlobalUserBan.delete({
            where: {
              rx_user_id: Number(ban.rx_user_id)
            }
          })
        } catch (err) {
          logger.write(LogLevel.Error, `Exception while deleting expired ban for ${ban.rx_user_name} (${ban.rx_user_id}): `, err);
        }
      }

      for (let ban of expired_group_bans) {
        logger.write(LogLevel.Info, `Ban for ${ban.rx_group_name} (${ban.rx_group_id}) has expired.`);

        try {
          await database.prisma.tAPGlobalGroupBan.delete({
            where: {
              rx_group_id: Number(ban.rx_group_id)
            }
          })
        } catch (err) {
          logger.write(LogLevel.Error, `Exception while deleting expired ban for ${ban.rx_group_name} (${ban.rx_group_id}): `, err);
        }
      }
    } catch (err) {
      logger.write(LogLevel.Error, `Exception while checking for expired bans: `, err);
    }

    await sleep(2000 * 60 * 60)
  }
}
