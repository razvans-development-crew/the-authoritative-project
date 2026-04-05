import { readdirSync, statSync } from "fs";
import { join, relative, parse } from "path";
import { Elysia } from "elysia";
import { logger } from "./logging.ts";

export function load_routes(app: Elysia, routes_dir: string) {
  const walk_dir = (dir: string, prefix = "") => {
    const files = readdirSync(dir);
    for (const file of files) {
      const full_path = join(dir, file);
      const file_stat = statSync(full_path);
      
      if (file_stat.isDirectory()) {
        walk_dir(full_path, prefix + "/" + file);
      } else if (file_stat.isFile() && file.endsWith(".ts")) {
        const route_module = require(full_path);
        if (typeof route_module.register_route === "function") {
          logger.write({level: "info", timestamp: new Date().toISOString(), message: `Registering route ${full_path}`});
          route_module.register_route(app);
        }
      }
    }
  };
  
  walk_dir(routes_dir);
}