import Denque from "denque";

export const registry = {
  generated_keys: [],
  active_sessions: [],

  // long poll
  request_queue: new Denque<any>(),
};
