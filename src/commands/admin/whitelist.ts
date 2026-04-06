import { SlashCommandBuilder, CommandInteraction, ChatInputCommandInteraction} from "discord.js";
import { type Command } from "../../types/Command.ts";
import { logger } from "../../logging.ts";
import { LogLevel } from "@sapphire/framework";

const database = require("../../database.ts");
const rozod_client = require("../../rozod_client.ts");
const preconditions = require("../../preconditions.ts");

const command: Command = {
  data: new SlashCommandBuilder()
    .setName('whitelist')
    .setDescription('Whitelists an user.')
    .addStringOption(option =>
      option
        .setName('roblox-user')
        .setDescription('The username of the Roblox user to whitelist.')
        .setRequired(true)
    )
    .addUserOption(option =>
      option
        .setName('discord-user')
        .setDescription('The Discord user to whitelist.')
        .setRequired(true)
    )
    .addStringOption(option =>
      option
        .setName('rank')
        .setDescription("The user's rank. Defaults to 'user'.")
        .setRequired(false)
    )
    .addNumberOption(option =>
      option
        .setName('privilege-level')
        .setDescription("The user's privilege level. Defaults to 0.")
        .setRequired(false)
    ),
  async execute(interaction: ChatInputCommandInteraction) {
    if (!interaction.deferred) {
      await interaction.deferReply();
    }

    if (await preconditions.is_dc_user_id_admin(interaction.user.id) === false) {
      await interaction.followUp({ content: '> Missing privilege level: `5`.' });
      return;
    }

    const username = interaction.options.getString('roblox-user');
    const discord_user = interaction.options.getUser('discord-user');
    const rank = interaction.options.getString('rank') ?? "user";
    const privilege_level = interaction.options.getNumber('privilege-level') ?? 0;
    const admin_whitelist_data = await database.prisma.tAPWhitelist.findFirst({
      where: {
        discord_user_id: interaction.user.id
      }
    });
    const roblox_user_id = await rozod_client.get_user_id_from_name(username) ?? "No user found";

    if (roblox_user_id == "No user found") {
      await interaction.followUp({ content: '> The specified user does not exist.' });
      return;
    }

    if (await preconditions.is_dc_user_id_owner(interaction.user.id) === false) {
      if (admin_whitelist_data.privilege_level < privilege_level) {
        await interaction.followUp({ content: '> You cannot whitelist someone with a privilege level higher than your own.' });
        return;
      }
    }

    if (privilege_level > 6) {
      await interaction.followUp({ content: '> Privilege level must be between 0 and 6.' });
      return;
    }

    if (await database.prisma.tAPWhitelist.findFirst({
      where: {
        rx_user_name: username
      }
    })) {
      await interaction.followUp({ content: '> The specified user is already whitelisted.' });
      return;
    }

    try {
      await database.prisma.tAPWhitelist.create({
        data: {
          discord_user_id: String(discord_user?.id),
          rx_user_name: username,
          rx_user_id: Number(roblox_user_id),
          rank: rank,
          privilege_level: privilege_level
        }
      })
    } catch (err) {
      await interaction.followUp({ content: '> An error has occurred while creating the whitelist.' });
      logger.write(LogLevel.Error, `Exception while creating ${username}'s whitelist`, err);

      return;
    }

    await interaction.followUp({ content: `> [@${username}](https://fxroblox.com/users/${roblox_user_id}) has been whitelisted as <@${discord_user?.id}>.` });
  }
}

export default command;
