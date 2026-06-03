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
    .setName('group')
    .setDescription('Looks up a Roblox group.')
    .addNumberOption(option =>
      option
        .setName('group-id')
        .setDescription('The group ID to look up')
        .setRequired(true)
    )
    .addBooleanOption(
      option => option
        .setName('legacy-lookup')
        .setDescription('Whether to lookup the group in the legacy database')
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

    const group_id = interaction.options.getNumber('group-id');
    const group_info = await rozod_client.get_group_info_from_id(String(group_id));

    if (group_info == "No group found") {
      await interaction.followUp({ content: "> The specified group does not exist." });
      return;
    }

    let group_ban_info;

    if (interaction.options.getBoolean('legacy-lookup') === true) {
      group_ban_info = await database.prisma.global_group_ban.findFirst({
        where: {
          group_id: Number(group_id),
        }
      }) ?? "No info found"
    } else {
      group_ban_info = await database.prisma.tAPGlobalGroupBan.findFirst({
        where: {
          rx_group_id: Number(group_id),
        }
      }) ?? "No info found"
    }

    let fields = [
      {
        name: "Group Information",
        value: "**Name**: "
          + group_info.name
          + "\n**ID**: `"
          + group_info.id
          + "`\n**Is Verified**: "
          + (group_info.hasVerifiedBadge ? "Yes" : "No")
          + `\n**Group Owner**: \`${group_info.owner.displayName}\` (${group_info.owner.username} / \`${group_info.owner.userId ?? "No ID found"}\`)`,
        inline: false
      }
    ]

    if (interaction.options.getBoolean('legacy-lookup') === true && group_ban_info != "No info found") {
      fields.push({
        name: "TAP Information (`v2` / `legacy`)",
        value: "**Banned**: "
          + (group_ban_info.banned_at ? "Yes" : "No")
          + "\n**Moderator**: `"
          + group_ban_info.moderator
          + "`\n**Reason**: "
          + String(group_ban_info.reason),
        inline: false
      })
    } else if (interaction.options.getBoolean('legacy-lookup') === false && group_ban_info != "No info found") {
      fields.push({
        name: "TAP Information (`v3`)",
        value: "**Banned**: "
          + (group_ban_info.banned_at ? "Yes" : "No")
          + "\n**Moderator**: "
          + group_ban_info.moderator_dc_id
          + "\n**Reason**: "
          + String(group_ban_info.reason)
          + "\n**Until**: "
          + group_ban_info.duration,
        inline: false
      })
    }

    const embed = new EmbedBuilder()
      .setTitle(`${group_info.name} (\`${group_info.id}\`)`)
      .setURL(`https://fxroblox.com/groups/${group_info.id}`)
      // .setDescription(group_info.description ?? "No description provided") // this line was problematic
      .addFields(fields)
      .setColor(0xCAA6F7)
      .setThumbnail(await rozod_client.get_group_icon(String(group_info.id)))

    try {
      embed.setDescription(group_info.description ?? "No description provided")
    } catch {
      embed.setDescription("No description provided")
    }

    await interaction.followUp({embeds: [embed]});
  }
}

export default command;
