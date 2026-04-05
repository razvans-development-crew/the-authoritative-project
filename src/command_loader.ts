import fs from "fs";
import { pathToFileURL } from "url";
import { readdir } from "fs/promises";
import path from "path";
import { type Command } from "./types/Command.ts";
import { logger } from "./logging.ts";

export async function load_commands(dir: string): Promise<Map<string, Command>> {
  const commands = new Map<string, Command>();

  async function walk(currentPath: string, group?: string) {
    const entries = await readdir(currentPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);

      if (entry.isDirectory()) {
        await walk(fullPath, entry.name);
      } else if (entry.name.endsWith(".ts")) {
        const fileUrl = pathToFileURL(fullPath).href;
        const mod = await import(fileUrl);

        const command: Command = mod.default;

        if (!command?.data || !command?.execute) {
          logger.warn(`Skipping ${fullPath} because it doesn't export a command`);
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