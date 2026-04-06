import { SlashCommandBuilder, CommandInteraction, ChatInputCommandInteraction} from "discord.js";
import { type Command } from "../../types/Command.ts";
import { logger } from "../../logging.ts";
import { LogLevel } from "@sapphire/framework";

const database = require("../../database.ts");
const rozod_client = require("../../rozod_client.ts");
const preconditions = require("../../preconditions.ts");

const command: Command = {
  data: new SlashCommandBuilder()
    .setName('unban')
    .setDescription('Unbans a Roblox user.')
    .addStringOption(option =>
      option
        .setName('roblox-user')
        .setDescription('The username of the Roblox user to unban.')
        .setRequired(true)
    ),
  async execute(interaction: ChatInputCommandInteraction) {
    if (!interaction.deferred) {
      await interaction.deferReply();
    }

    if (await preconditions.is_dc_user_id_capable_to_ban_users(interaction.user.id) === false) {
      await interaction.followUp({ content: '> Missing privilege level: `3`.' });
      return;
    }

    const username = interaction.options.getString('roblox-user');
    const user_id = await rozod_client.get_user_id_from_name(username);
    const target_whitelist_data = await database.prisma.tAPWhitelist.findFirst({
      where: {
        rx_user_id: user_id
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

    if (!target_whitelist_data) {
      await interaction.followUp({ content: '> The specified user is not banned.' });
      return;
    }

    if (admin_whitelist_data.privilege_level < moderator_whitelist_data.privilege_level) {
      await interaction.followUp({ content: '> You cannot unban someone who was banned by someone with a privilege level higher than your own.' });
    }

    try {
      await database.prisma.tAPGlobalUserBan.delete({
        where: {
          rx_user_name: username
        }
      })
    } catch (err) {
      await interaction.followUp({ content: '> An error has occurred while unbanning the user.' });
      logger.write(LogLevel.Error, `Exception while unbanning ${username}`, err);

      return;
    }

    await interaction.followUp({ content: `> [@${username}](https://fxroblox.com/users/${user_id}) has been unbanned.` });
  }
}

export default command;
