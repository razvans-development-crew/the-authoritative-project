import Denque from "denque";

export interface GeneratedKey {
  loader_key: string,
  unix_timestamp: number,
  roblox_user_id: string,
}

export interface Session {
  session_id: string,
  discord_channel_id: string,
  logs: Array<string>,
  stopped: boolean,
  unix_timestamp: number,
  job_id: string,
  session_name: string
}

export interface Registry {
  generated_keys: Array<GeneratedKey>,
  active_sessions: Array<Session>,

  // long poll
  request_queue: Denque<any>,
}

export const registry: Registry = {
  generated_keys: [],
  active_sessions: [],

  // long poll
  request_queue: new Denque<any>(),
};
