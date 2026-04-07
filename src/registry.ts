import Denque from "denque";

interface GeneratedKey {
  loader_key: string,
  unix_timestamp: number,
  roblox_user_id: string,
}

interface Registry {
  generated_keys: Array<GeneratedKey>,
  active_sessions: Array<any>, // i decide later

  // long poll
  request_queue: Denque<any>,
}

export const registry: Registry = {
  generated_keys: [],
  active_sessions: [],

  // long poll
  request_queue: new Denque<any>(),
};
