import { PinoLogger } from "@stegripe/pino-logger"

export const logger = new PinoLogger({
  formatters: {
    bindings: () => ({ pid: null })
  },
  transport: {
    target: "pino-pretty",
    options: {
      colorize: true
    }
  }
});