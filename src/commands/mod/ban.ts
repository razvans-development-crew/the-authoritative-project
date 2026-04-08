import { SlashCommandBuilder, CommandInteraction, ChatInputCommandInteraction} from "discord.js";
import { type Command } from "../../types/Command.ts";
import { logger } from "../../utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";
import { is_dc_user_id_capable_to_ban_groups } from "../../utilities/preconditions.ts";

const database = require("../../database.ts");
const rozod_client = require("../../rozod_client.ts");
const preconditions = require("../../preconditions.ts");

const command: Command = {
  data: new SlashCommandBuilder()
    .setName('ban')
    .setDescription('Bans a Roblox user.')
    .addStringOption(option =>
      option
        .setName('roblox-user')
        .setDescription('The username of the Roblox user to ban.')
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
    ),
  async execute(interaction: ChatInputCommandInteraction) {
    if (!interaction.deferred) {
      await interaction.deferReply();
    }

    if (await preconditions.is_dc_user_id_capable_to_ban_users(interaction.user.id) === false) {
      await interaction.followUp({ content: '> Missing privilege level: `3`.' });
      return;
    }

    let duration = interaction.options.getNumber('duration') ?? -1;
    const reason = interaction.options.getString('reason') ?? "No reason provided";
    const username = interaction.options.getString('roblox-user');
    const user_id = await rozod_client.get_user_id_from_name(username) ?? "No user found";
    const target_whitelist_data = await database.prisma.tAPWhitelist.findFirst({
      where: {
        rx_user_id: user_id
      }
    });

    if (user_id == "No user found") {
      await interaction.followUp({ content: '> The specified user does not exist.' });
      return;
    }

    if (target_whitelist_data && target_whitelist_data.privilege_level < 5) {
      await interaction.followUp({ content: '> You cannot ban someone with a privilege level higher than your own.' });
      return;
    }

    if (interaction.options.getNumber("duration") == 0) {
      duration = -1;
    }

    if (await database.prisma.tAPGlobalUserBan.findFirst({
      where: {
        rx_user_name: interaction.options.getString('roblox-user')
      }
    })) {
      try {
        await database.prisma.tAPGlobalUserBan.update({
          where: {
            rx_user_name: interaction.options.getString('roblox-user')
          },
          data: {
            reason: reason,
            duration: duration
          }
        })
      } catch (err) {
        await interaction.followUp({ content: '> An error has occurred while updating the ban.' });
        logger.write(LogLevel.Error, `Exception while updating ${username}'s ban`, err);

        return;
      }

      await interaction.followUp({ content: '> Ban has been updated.' });
      return;
    }

    try {
      await database.prisma.tAPGlobalUserBan.create({
        data: {
          moderator_dc_id: String(interaction.user.id),
          rx_user_name: username,
          rx_user_id: Number(user_id),
          reason: reason,
          duration: duration
        }
      })
    } catch (err) {
      await interaction.followUp({ content: '> An error has occurred while creating the ban.' });
      logger.write(LogLevel.Error, `Exception while creating ${username}'s ban`, err);

      return;
    }

    await interaction.followUp({ content: `> [@${username}](https://fxroblox.com/users/${user_id}) has been banned.` });
  }
}

export default command;
