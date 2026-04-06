import {
  SlashCommandBuilder,
  ChatInputCommandInteraction, EmbedBuilder
} from "discord.js";
import { type Command } from "../../types/Command.ts";

const database = require("../../database.ts");
const rozod_client = require("../../rozod_client.ts");

const command: Command = {
  data: new SlashCommandBuilder()
    .setName('discord')
    .setDescription('Looks up a Discord user.')
    .addUserOption(option =>
      option
        .setName('user')
        .setDescription('The user to look up. Defaults to the user invoking the command.')
        .setRequired(false)
    )
    .addBooleanOption(
      option => option
        .setName('legacy-lookup')
        .setDescription('Whether to lookup the user in the legacy database')
        .setRequired(false)
    ),
  async execute(interaction: ChatInputCommandInteraction) {
    await interaction.deferReply();

    const user = interaction.options.getUser('user') ?? interaction.user;

    let user_database_info;

    if (interaction.options.getBoolean('legacy-lookup') === true) {
      user_database_info = await database.prisma.whitelist.findFirst({
        where: {
          dc_user_id: user.id
        }
      }) ?? "No info found";
    } else {
      user_database_info = await database.prisma.tAPWhitelist.findFirst({
        where: {
          discord_user_id: user.id
        }
      }) ?? "No info found";
    }

    let fields = [
      {
        name: "Discord Information",
        value: "**Username**: "
          + user.username
          + "\n**ID**: "
          + user.id
          + "\n**Created At**: "
          + user.createdAt,
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
          + "\n**Linked Roblox User**: <@"
          + String(user_database_info.rx_user_id)
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
          + "\n**Linked Roblox User**: <@"
          + String(user_database_info.rx_user_id)
          + ">\n**Rank**: " + user_database_info.rank,
        inline: false
      })
    }

    const embed = new EmbedBuilder()
      .setTitle(`<@${user.id}> (\`${user.id}\`)`)
      .setURL(`https://discord.com/users/${user.id}`)
      .setDescription(user.tag)
      .addFields(fields)
      .setColor(0xCAA6F7)
      .setImage(user.avatarURL())

    await interaction.followUp({embeds: [embed]});
  }
}

export default command;
