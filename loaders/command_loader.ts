import { pathToFileURL } from "url";
import { readdir } from "fs/promises";
import path from "path";
import { type Command } from "../types/Command.ts";
import { logger } from "../utilities/logging.ts";
import { LogLevel } from "@sapphire/framework";

export async function load_commands(dir: string): Promise<Map<string, Command>> {
  const commands = new Map<string, Command>();

  async function walk(current_path: string, group?: string) {
    const entries = await readdir(current_path, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(current_path, entry.name);

      if (entry.isDirectory()) {
        await walk(fullPath, entry.name);
      } else if (entry.name.endsWith(".ts")) {
        logger.write(LogLevel.Info, `Loading command ${entry.name}`);

        const file_url = pathToFileURL(fullPath).href;
        const mod = await import(file_url);

        const command: Command = mod.default;

        if (!command?.data || !command?.execute) {
          logger.write(LogLevel.Warn, `Command ${entry.name} is not a valid command`);
          continue;
        }

        command.group = group;

        commands.set(command.data.name, command);
      }
    }
  }

  await walk(dir);

  return commands;
}
