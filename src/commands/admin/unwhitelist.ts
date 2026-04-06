import { SlashCommandBuilder, CommandInteraction, ChatInputCommandInteraction} from "discord.js";
import { type Command } from "../../types/Command.ts";
import { logger } from "../../logging.ts";
import { LogLevel } from "@sapphire/framework";

const database = require("../../database.ts");
const rozod_client = require("../../rozod_client.ts");
const preconditions = require("../../preconditions.ts");

const command: Command = {
  data: new SlashCommandBuilder()
    .setName('unwhitelist')
    .setDescription('Unwhitelists an user.')
    .addUserOption(option =>
      option
        .setName('discord-user')
        .setDescription('The Discord user to unwhitelist.')
        .setRequired(true)
    ),
  async execute(interaction: ChatInputCommandInteraction) {
    if (!interaction.deferred) {
      await interaction.deferReply();
    }

    const discord_user = interaction.options.getUser('discord-user');
    const admin_whitelist_data = await database.prisma.tAPWhitelist.findFirst({
      where: {
        discord_user_id: interaction.user.id
      }
    });
    const target_whitelist_data = await database.prisma.tAPWhitelist.findFirst({
      where: {
        discord_user_id: discord_user?.id
      }
    });

    if (admin_whitelist_data.privilege_level < 5) {
      await interaction.followUp({ content: '> Missing privilege level: `5`.' });
      return;
    }

    if (!target_whitelist_data) {
      await interaction.followUp({ content: '> The specified user is not whitelisted.' });
      return;
    }

    if (admin_whitelist_data.privilege_level < target_whitelist_data.privilege_level) {
      await interaction.followUp({ content: '> You cannot unwhitelist someone with a privilege level higher than your own.' });
      return;
    }

    try {
      await database.prisma.tAPWhitelist.delete({
        where: {
          discord_user_id: discord_user?.id
        }
      })
    } catch (err) {
      await interaction.followUp({ content: '> An error has occurred while unwhitelisting the user.' });
      logger.write(LogLevel.Error, `Exception while unwhitelisting ${discord_user?.username}`, err);

      return;
    }

    await interaction.followUp({ content: `> [@${discord_user?.username}](https://discord.com/users/${discord_user?.id}) has been unwhitelisted.` });
  }
}

export default command;
