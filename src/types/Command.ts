import { ChatInputCommandInteraction, SlashCommandBuilder,
  type SlashCommandOptionsOnlyBuilder,
  SlashCommandSubcommandBuilder,
  SlashCommandSubcommandGroupBuilder
} from "discord.js";

export interface Command {
  data: SlashCommandBuilder | SlashCommandOptionsOnlyBuilder | SlashCommandSubcommandBuilder | SlashCommandSubcommandGroupBuilder;
  execute: (interaction: ChatInputCommandInteraction) => Promise<void>;
  group?: string;
}
