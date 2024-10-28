import { Client, Events, GatewayIntentBits } from "discord.js";

export const client = new Client({
	intents: [
		GatewayIntentBits.Guilds
	],
});

client.once(Events.ClientReady, readyClient => {
	console.log(`Ready! Logged in as ${readyClient.user.tag}`);
});

await client.login(process.env.token);