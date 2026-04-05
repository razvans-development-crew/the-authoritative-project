import { Elysia } from 'elysia'

const app = new Elysia()

app.get("/", () => {
  return "hi"
})

app.listen(8080)