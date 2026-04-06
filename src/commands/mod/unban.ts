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

    if (await database.prisma.tAPGlobalUserBan.findFirst({
      where: {
        rx_user_name: username
      }
    }) == null) {
      await interaction.followUp({ content: '> The specified user is not banned.' });
      return;
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
