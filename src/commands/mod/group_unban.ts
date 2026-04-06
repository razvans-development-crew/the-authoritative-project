import { SlashCommandBuilder, CommandInteraction, ChatInputCommandInteraction} from "discord.js";
import { type Command } from "../../types/Command.ts";
import { logger } from "../../logging.ts";
import { LogLevel } from "@sapphire/framework";

const database = require("../../database.ts");
const rozod_client = require("../../rozod_client.ts");
const preconditions = require("../../preconditions.ts");

const command: Command = {
  data: new SlashCommandBuilder()
    .setName('group-unban')
    .setDescription('Unbans a Roblox group.')
    .addNumberOption(option =>
      option
        .setName('group-id')
        .setDescription('The group ID to unban.')
        .setRequired(true)
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

    if (group_name == "No group found") {
      await interaction.followUp({ content: '> The specified group does not exist.' });
      return;
    }

    if (await database.prisma.tAPGlobalGroupBan.findFirst({
      where: {
        rx_group_id: group_id
      }
    }) == null) {
      await interaction.followUp({ content: '> The specified group is not banned.' });
      return;
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
