import { SlashCommandBuilder, CommandInteraction, ChatInputCommandInteraction, InteractionContextType} from "discord.js";
import { type Command } from "../../types/Command.ts";
import { logger } from "../../utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";

const database = require("../../utilities/database.ts");
const rozod_client = require("../../utilities/rozod_client.ts");
const preconditions = require("../../utilities/preconditions.ts");

const command: Command = {
  data: new SlashCommandBuilder()
    .setName('group-ban')
    .setDescription('Bans a Roblox group.')
    .addNumberOption(option =>
      option
        .setName('group-id')
        .setDescription('The group ID to ban.')
        .setRequired(true)
    )
    .addStringOption(option =>
      option
        .setName('reason')
        .setDescription('The reason for the ban.')
        .setRequired(false)
    )
    .addNumberOption(option =>
      option
        .setName('duration')
        .setDescription('The duration of the ban in days (0 = permanent, the ban is permanent by default).')
        .setRequired(false)
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

    let duration = interaction.options.getNumber('duration') ?? -1;
    const reason = interaction.options.getString('reason') ?? "No reason provided";
    const group_id = interaction.options.getNumber('group-id');
    const group_name = await rozod_client.get_group_name_from_id(String(group_id)) ?? "No group found";
    const target_ban_data = await database.prisma.tAPGlobalGroupBan.findFirst({
      where: {
        rx_group_id: group_id
      }
    });

    if (group_name == "No group found") {
      await interaction.followUp({ content: '> The specified group does not exist.' });
      return;
    }

    if (interaction.options.getNumber("duration") == 0) {
      duration = -1;
    }

    if (target_ban_data) {
      try {
        await database.prisma.tAPGlobalGroupBan.update({
          where: {
            rx_group_id: group_id
          },
          data: {
            reason: reason,
            duration: duration
          }
        })
      } catch (err) {
        await interaction.followUp({ content: '> An error has occurred while updating the ban.' });
        logger.write(LogLevel.Error, `Exception while updating ${group_id}'s ban`, err);

        return;
      }

      await interaction.followUp({ content: '> Ban has been updated.' });
      return;
    }

    try {
      await database.prisma.tAPGlobalGroupBan.create({
        data: {
          moderator_dc_id: String(interaction.user.id),
          rx_group_id: group_id,
          rx_group_name: group_name,
          reason: reason,
          duration: duration
        }
      })
    } catch (err) {
      await interaction.followUp({ content: '> An error has occurred while creating the ban.' });
      logger.write(LogLevel.Error, `Exception while creating ${group_id}'s ban`, err);

      return;
    }

    await interaction.followUp({ content: `> [#${group_id}](https://fxroblox.com/groups/${group_id}) has been banned.` });
  }
}

export default command;
