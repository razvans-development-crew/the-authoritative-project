import { type Command } from "../../types/Command";
import { SlashCommandBuilder, ChatInputCommandInteraction, InteractionContextType } from "discord.js";
import { registry, type GeneratedKey } from "../../utilities/registry.ts";
import { logger } from "../../utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";
import { generate_random_string } from "../../utilities/helpers.ts";
import { get_env_variable } from "../../utilities/env_variables.ts";

const preconditions = require("../../utilities/preconditions.ts");
const database = require("../../utilities/database.ts");

export const command: Command = {
  data: new SlashCommandBuilder()
    .setName("generate-key")
    .setDescription("Generates an authentication key for the loader.")
    .addStringOption(option =>
      option.setName("key-type")
        .setDescription("Whether to use `loadstring`, `AssetService:LoadAssetAsync` or `require` for the loader key.")
        .setRequired(false)
        .addChoices(
          { name: "loadstring", value: "1" },
          { name: "AssetService:LoadAssetAsync", value: "2" },
          { name: "require", value: "3" },
        )
    )
    .setContexts(
      InteractionContextType.BotDM,
      InteractionContextType.PrivateChannel,
      InteractionContextType.Guild
    ),
  async execute(interaction: ChatInputCommandInteraction) {
    if (!interaction.deferred) {
      await interaction.deferReply({flags: "Ephemeral"});
    }

    if (await preconditions.is_dc_user_id_owner(interaction.user.id) === false) {
      await interaction.followUp({ content: '> Missing privilege level: `6`.\n> -# Note: this command is temporarily only available to the owner for testing.' });
      return;
    }

    const key_type = interaction.options.getString("key-type") ?? "3";
    const whitelist_info = await database.prisma.tAPWhitelist.findFirst({
      where: {
        discord_user_id: interaction.user.id,
      }
    });

    const key: GeneratedKey = {
      loader_key: await generate_random_string(24),
      unix_timestamp: Date.now(),
      roblox_user_id: whitelist_info?.roblox_user_id ?? ""
    };

    registry.generated_keys.push(key);

    if (key_type == "3") {
      await interaction.followUp("> ```lua\n> require(" + await get_env_variable("LOADER_ASSET_ID") + ")(\'" + whitelist_info.rx_user_name + "\', \'" + key.loader_key + "\')\n> -- This key expires in 25 seconds.\n> ```");
    } else if (key_type == "2") {
      await interaction.followUp("> ```lua\n> game:GetService(\"AssetService\"):LoadAssetAsync(" + await get_env_variable("LOADER_ASSET_ID") + ")(\'" + whitelist_info.rx_user_name + "\', \'" + key.loader_key + "\')\n> -- This key expires in 25 seconds.\n> ```");
    } else if (key_type == "1") {
      await interaction.followUp("> ```lua\n> loadstring(game:GetService(\"HttpService\"):RequestAsync({Method = \"GET\", Url = \"" + await get_env_variable("API_URL") + "api/v3/loader\", Headers = {[\"X-Loader-Key\"] = \'" + key.loader_key + "\'}}).Body)(\'" + whitelist_info.rx_user_name + "\', \'" + key.loader_key + "\')\n> -- This key expires in 25 seconds.\n> ```");
    }
  }
}

export default command;
