export async function get_env_variable(key: string): Promise<string> {
  const value = process.env[key];

  if ( !value ) {
    throw new Error(`Environment variable ${key} is not set`);
  }

  return value
}