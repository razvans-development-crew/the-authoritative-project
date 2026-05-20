import { SlashCommandBuilder, CommandInteraction, ChatInputCommandInteraction, InteractionContextType } from "discord.js";
import { type Command } from "../../types/Command.ts";
import { logger } from "../../utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";
import { get_expired_bans } from "../../utilities/database.ts";

const database = require("../../utilities/database.ts");
const preconditions = require("../../utilities/preconditions.ts");

const command: Command = {
  data: new SlashCommandBuilder()
    .setName('check-for-expired-bans')
    .setDescription('Checks for expired user bans and removes them from the database.')
    .setContexts(
      InteractionContextType.BotDM,
      InteractionContextType.PrivateChannel,
      InteractionContextType.Guild
    ),
  async execute(interaction: ChatInputCommandInteraction) {
    if (!interaction.deferred) {
      await interaction.deferReply();
    }

    if (await preconditions.is_dc_user_id_owner(interaction.user.id) === false) {
      await interaction.followUp({ content: '> Missing privilege level: `6`.' });
      return;
    }

    try {
      const expired_bans = await get_expired_bans();

      for (let ban of expired_bans) {
        logger.write(LogLevel.Info, `Ban for ${ban.rx_user_name} (${ban.rx_user_id}) has expired.`);

        await database.prisma.tAPGlobalUserBan.delete({
          where: {
            rx_user_id: Number(ban.rx_user_id)
          }
        })
      }

      await interaction.followUp({ content: '> Finished checking for expired user bans.' });
    } catch (err) {
      await interaction.followUp({ content: '> An error has occurred while checking for expired bans.' });
      logger.write(LogLevel.Error, `Exception while checking for expired bans: `, err);

      return;
    }
  }
};

export default command;
