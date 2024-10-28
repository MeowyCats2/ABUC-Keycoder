import type { TextChannel } from "discord.js";
import { client } from "./client.js";

export const dataMsg = await ((await client.channels.fetch("1300295288615075850")) as TextChannel).messages.fetch("1300296249647304788")
export const data = JSON.parse(await (await fetch([...dataMsg.attachments.values()][0].url)).text())
export const saveData = async () => await dataMsg.edit({
    "files": [
        {
            "attachment": Buffer.from(JSON.stringify(data), "utf8"),
            "name": "data.json"
        }
    ]
})