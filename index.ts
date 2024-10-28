import "./webserver.ts"
import { Events, Routes, SlashCommandBuilder, SlashCommandStringOption, SlashCommandBooleanOption, PermissionsBitField, ComponentType, ButtonStyle } from "discord.js";
import type { TextChannel } from "discord.js";
import { client } from "./client.ts"
import { data, saveData } from "./dataMsg.ts";
import { createHash, randomBytes } from "crypto";

interface keycode {
	hash: string,
	creation: string
}

client.on(Events.InteractionCreate, async interaction => {
	if (!interaction.isChatInputCommand()) return;
	if (interaction.commandName !== "send_keycode_message") return;
	await interaction.deferReply({
		ephemeral: true
	});
	(interaction.channel as TextChannel).send({
		content: "Obtain a keycode by clicking the button.",
		components: [
			{
				"components": [
					{
						"customId": "obtain_keycode",
						"label": "Obtain Keycode",
						"style": ButtonStyle.Primary,
						"type": ComponentType.Button
					}
				],
				"type": ComponentType.ActionRow
			}
		]
	})
	await interaction.followUp("Sent message!")
})

client.on(Events.InteractionCreate, async interaction => {
	if (interaction.isChatInputCommand()) {
		if (interaction.commandName !== "obtain_keycode") return;
	} else if (interaction.isButton()) {
		if (interaction.customId !== "obtain_keycode") return;
	} else {
		return
	}
	await interaction.deferReply({
		ephemeral: true
	});
	const keycode = randomBytes(16).toString("hex");
	if (!data.keycodes[interaction.user.id]) data.keycodes[interaction.user.id] = []
	data.keycodes[interaction.user.id].push({
		hash: createHash('sha256').update(keycode).digest('hex'),
		creation: (new Date()).toUTCString()
	});
	await saveData()
	await interaction.followUp(`Your keycode is \`${keycode}\`.`)
})

client.on(Events.InteractionCreate, async interaction => {
	if (!interaction.isChatInputCommand()) return;
	if (interaction.commandName !== "validate_keycode") return;
	await interaction.deferReply({
		ephemeral: true
	});
	const hash = createHash('sha256').update(interaction.options.getString("keycode")!).digest('hex');
	const userInfo = Object.entries(data.keycodes).find(info => (info[1] as keycode[]).find((keycodeInfo: keycode) => keycodeInfo.hash === hash))
	if (!userInfo) return await interaction.followUp("This keycode doesn't exist.")
	const keycodes = (userInfo[1] as keycode[]).sort((a, b) => Date.parse(b.creation) - Date.parse(a.creation))
	const isLatest = keycodes[0].hash === hash
	if (!isLatest) {
		const keycodeIndex = keycodes.findIndex(code => code.hash === hash)
		const expiry = Date.parse(keycodes[keycodeIndex - 1].creation) + 1000 * 60 * 60 * 24 * 3
		if (expiry < Date.now()) return await interaction.followUp(`This keycard owned by <@${userInfo[0]}> expired on <t:${expiry}>.`)
			return await interaction.followUp(`:warning: This keycard belongs to <@${userInfo[0]}> but a new one was recently created and will expire on <t:${expiry / 1000}>. If you believe their keycode got leaked, do not accept it.`)
		}
	await interaction.followUp(`This keycode belongs to <@${userInfo[0]}>.`)
})

client.on(Events.InteractionCreate, async interaction => {
	if (!interaction.isChatInputCommand()) return;
	if (interaction.commandName !== "validate_self") return;
	await interaction.deferReply({
		ephemeral: true
	});
	const hash = createHash('sha256').update(interaction.options.getString("keycode")!).digest('hex');
	const userInfo = Object.entries(data.keycodes).find(info => (info[1] as keycode[]).find((keycodeInfo: keycode) => keycodeInfo.hash === hash))
	if (!userInfo) return await interaction.followUp("This keycode doesn't exist.")
	const keycodes = (userInfo[1] as keycode[]).sort((a, b) => Date.parse(b.creation) - Date.parse(a.creation))
	const isLatest = keycodes[0].hash === hash
	if (!isLatest) {
		const keycodeIndex = keycodes.findIndex(code => code.hash === hash)
		const expiry = Date.parse(keycodes[keycodeIndex - 1].creation) + 1000 * 60 * 60 * 24 * 3
		if (expiry < Date.now()) return await interaction.followUp(`This keycard owned by <@${userInfo[0]}> expired on <t:${expiry}>.`)
		await (interaction.channel as TextChannel).send(`:warning: <@${interaction.user.id}>'s keycard belongs to <@${userInfo[0]}> but a new one was recently created and will expire on <t:${expiry / 1000}>. If you believe their keycode got leaked, do not accept it.`)
		return await interaction.followUp("Recently expired keycard.")
	}
	await (interaction.channel as TextChannel).send(`<@${interaction.user.id}>'s keycode belongs to <@${userInfo[0]}>.`)
	await interaction.followUp("Keycard validated.")
})

for (const keycodeList of Object.values(data.keycodes) as keycode[][]) {
	if (keycodeList.length < 2) continue;
	let expiredKeycodes = []
	for (let keycodeIndex = 1; keycodeIndex < keycodeList.length; keycodeIndex++) {
		const expiry = Date.parse(keycodeList[keycodeIndex - 1].creation) + 1000 * 60 * 60 * 24 * 3
		if (expiry < Date.now()) expiredKeycodes.push(keycodeList[keycodeIndex].hash)
	}
	for (const expiredHash of expiredKeycodes) {
		keycodeList.splice(keycodeList.findIndex(currentKeycode => currentKeycode.hash === expiredHash), 1)
	}
}
await saveData()

const commands = [
	new SlashCommandBuilder()
	.setName("send_keycode_message")
	.setDescription("Make the bot send a message for keycode obtaining.")
	.setDefaultMemberPermissions(PermissionsBitField.Flags.ManageGuild),
	new SlashCommandBuilder()
	.setName("obtain_keycode")
	.setDescription("Get assigned a keycode by running this command."),
	new SlashCommandBuilder()
	.setName("validate_keycode")
	.setDescription("Check if a keycode is valid and who it belongs to.")
	.addStringOption(
		new SlashCommandStringOption()
		.setName("keycode")
		.setDescription("The keycode to check.")
		.setRequired(true)
	),
	new SlashCommandBuilder()
	.setName("validate_self")
	.setDescription("Validate yourself with a keycode.")
	.addStringOption(
		new SlashCommandStringOption()
		.setName("keycode")
		.setDescription("The keycode to validate yourself with.")
		.setRequired(true)
	)
]
await client.rest.put(Routes.applicationCommands(client.application!.id), {"body": commands})