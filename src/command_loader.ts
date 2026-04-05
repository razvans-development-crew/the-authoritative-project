

import { readdirSync } from "node:fs";
import { join } from "node:path";

const commands_dir = join(Deno.cwd(), "src", "commands");
const commands = readdirSync(commands_dir, { withFileTypes: true })
  .filter((dirent) => dirent.isFile())
  .map((dirent) => dirent.name);