import {
  SlashCommandBuilder,
  ChatInputCommandInteraction, EmbedBuilder,
  InteractionContextType
} from "discord.js";
import { type Command } from "../../types/Command.ts";

const database = require("../../utilities/database.ts");
const rozod_client = require("../../utilities/rozod_client.ts");

const command: Command = {
  data: new SlashCommandBuilder()
    .setName('roblox')
    .setDescription('Looks up a Roblox user.')
    .addStringOption(option =>
      option
        .setName('username')
        .setDescription('The username to look up')
        .setRequired(true)
    )
    .addBooleanOption(
      option => option
        .setName('legacy-lookup')
        .setDescription('Whether to lookup the user in the legacy database')
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

    const username = interaction.options.getString('username');

    const user_id = await rozod_client.get_user_id_from_name(username);
    const user_info = await rozod_client.get_user_info_from_id(user_id);

    if (user_info == "No user found") {
      await interaction.editReply({ content: "> The specified user does not exist." });
      return;
    }

    let user_database_info;
    let user_ban_info;

    if (interaction.options.getBoolean('legacy-lookup') === true) {
      user_database_info = await database.prisma.whitelist.findFirst({
        where: {
          rx_user_name: username
        }
      }) ?? "No info found";
    } else {
      user_database_info = await database.prisma.tAPWhitelist.findFirst({
        where: {
          rx_user_name: username
        }
      }) ?? "No info found";
    }

    if (interaction.options.getBoolean('legacy-lookup') === true) {
      user_ban_info = await database.prisma.global_user_ban.findFirst({
        where: {
          rx_user_name: username
        }
      }) ?? "No info found";
    } else {
      user_ban_info = await database.prisma.tAPGlobalUserBan.findFirst({
        where: {
          rx_user_name: username
        }
      }) ?? "No info found";
    }

    let fields = [
      {
        name: "Roblox Information",
        value: "**Username**: "
          + user_info.name
          + "\n**ID**: "
          + user_info.id
          + "\n**Created At**: `"
          + user_info.created
          + "`\n**Has Verified Badge**: "
          + (user_info.hasVerifiedBadge ? "Yes" : "No"),
        inline: false
      }
    ]

    if (interaction.options.getBoolean('legacy-lookup') === true && user_database_info != "No info found") {
      fields.push({
        name: "TAP Information (`v2` / `legacy`)",
        value: "**Whitelisted**: "
          + (user_database_info.rank === 1 ? "Yes" : "No")
          + "\n**Privilege Level**: "
          + String(user_database_info.privilege_level)
          + "\n**Linked Discord User**: <@"
          + String(user_database_info.dc_user_id)
          + ">\n**Rank**: "
          + user_database_info.rank,
        inline: false
      })
    } else if (interaction.options.getBoolean('legacy-lookup') === false && user_database_info != "No info found") {
      fields.push({
        name: "TAP Information (`v3`)",
        value: "**Whitelisted**: "
          + (user_database_info.rank === 1 ? "Yes" : "No")
          + "\n**Privilege Level**: "
          + String(user_database_info.privilege_level)
          + "\n**Linked Discord User**: <@"
          + String(user_database_info.discord_user_id)
          + ">\n**Rank**: " + user_database_info.rank,
        inline: false
      })
    }

    if (interaction.options.getBoolean('legacy-lookup') === true && user_ban_info != "No info found") {
      fields.push({
        name: "TAP Information (`v2` / `legacy`)",
        value: "**Banned**: "
          + (user_ban_info.banned_at ? "Yes" : "No")
          + "\n**Moderator**: "
          + user_ban_info.moderator
          + "\n**Reason**: "
          + String(user_ban_info.reason),
        inline: false
      })
    } else if (interaction.options.getBoolean('legacy-lookup') === false && user_ban_info != "No info found") {
      fields.push({
        name: "TAP Information (`v3`)",
        value: "**Banned**: "
          + (user_ban_info.banned_at ? "Yes" : "No")
          + "\n**Moderator**: "
          + user_ban_info.moderator_dc_id
          + "\n**Reason**: "
          + String(user_ban_info.reason)
          + "\n**Until**: "
          + String(user_ban_info.duration),
        inline: false
      })
    }

    const embed = new EmbedBuilder()
      .setTitle(`@${username} (\`${user_info.id}\`)`)
      .setURL(`https://fxroblox.com/users/${user_info.id}`)
      .setDescription(user_info.description)
      .addFields(fields)
      .setColor(0xCAA6F7)
      .setThumbnail(await rozod_client.get_user_avatar_icon(String(user_info.id)))

    await interaction.editReply({embeds: [embed]});
  },
}

export default command;
