const env_variables = require("./env_variables.ts");

export async function is_owner(to_check: string): Promise<boolean> {
  return (await env_variables.get_env_variable("OWNER") === to_check)
}