import { SlashCommandBuilder, CommandInteraction, ChatInputCommandInteraction, InteractionContextType} from "discord.js";
import { type Command } from "../../types/Command.ts";
import { logger } from "../../utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";

const database = require("../../utilities/database.ts");
const rozod_client = require("../../utilities/rozod_client.ts");
const preconditions = require("../../utilities/preconditions.ts");

const command: Command = {
  data: new SlashCommandBuilder()
    .setName('group-unban')
    .setDescription('Unbans a Roblox group.')
    .addNumberOption(option =>
      option
        .setName('group-id')
        .setDescription('The group ID to unban.')
        .setRequired(true)
    )
    .setContexts(
      InteractionContextType.BotDM,
      InteractionContextType.PrivateChannel,
      InteractionContextType.Guild
    ),
  async execute(interaction: ChatInputCommandInteraction) {
    if (!interaction.deferred) {
      await interaction.deferReply();
    }

    if (await preconditions.is_dc_user_id_capable_to_ban_groups(interaction.user.id) === false) {
      await interaction.followUp({ content: '> Missing privilege level: `4`.' });
      return;
    }

    const group_id = interaction.options.getNumber('group-id');
    const group_name = await rozod_client.get_group_name_from_id(String(group_id)) ?? "No group found";
    const target_ban_data = await database.prisma.tAPGlobalGroupBan.findFirst({
      where: {
        rx_group_id: group_id
      }
    });
    const moderator_whitelist_data = await database.prisma.tAPWhitelist.findFirst({
      where: {
        rx_user_id: interaction.user.id
      }
    });
    const admin_whitelist_data = await database.prisma.tAPWhitelist.findFirst({
      where: {
        discord_user_id: interaction.user.id
      }
    });

    if (group_name == "No group found") {
      await interaction.followUp({ content: '> The specified group does not exist.' });
      return;
    }

    if (!target_ban_data) {
      await interaction.followUp({ content: '> The specified group is not banned.' });
      return;
    }

    if (admin_whitelist_data.privilege_level < moderator_whitelist_data.privilege_level) {
      await interaction.followUp({ content: '> You cannot unban a group that was banned by someone with a privilege level higher than your own.' });
    }

    try {
      await database.prisma.tAPGlobalGroupBan.delete({
        where: {
          rx_group_id: group_id
        }
      })
    } catch (err) {
      await interaction.followUp({ content: '> An error has occurred while unbanning the group.' });
      logger.write(LogLevel.Error, `Exception while unbanning ${group_id}`, err);

      return;
    }

    await interaction.followUp({ content: `> [#${group_id}](https://fxroblox.com/groups/${group_id}) has been unbanned.` });
  }
}

export default command;
