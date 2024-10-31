import "./webserver.ts"
import { Events, Routes, SlashCommandBuilder, SlashCommandStringOption, SlashCommandBooleanOption, SlashCommandAttachmentOption, PermissionsBitField, ComponentType, ButtonStyle } from "discord.js";
import type { TextChannel } from "discord.js";
import { client } from "./client.ts"
import { data, saveData } from "./dataMsg.ts";
import { createHash, randomBytes } from "crypto";

interface Keycode {
	key: string,
	creation: string
}

const algorithm = {
	"name": "RSASSA-PKCS1-v1_5",
	"modulusLength": 4096,
	"publicExponent": new Uint8Array([1, 0, 1]),
	"hash": "SHA-256"
}

const hexToUintArray = (hexString: string) =>
	Uint8Array.from(hexString.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));
  
const arrayBufferToHex = (buffer: ArrayBufferLike) => [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, '0')).join("");

//console.log(arrayBufferToHex(await crypto.subtle.sign(algorithm, keyPair.privateKey, new TextEncoder().encode(JSON.stringify({})))))
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
	const keyPair = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
	data.keycodes[interaction.user.id] ??= []
	const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey)
	data.keycodes[interaction.user.id].push({
		key: JSON.stringify(publicKey),
		creation: (new Date()).toUTCString()
	});
	//await saveData()
	await interaction.followUp({
		"content": "Make sure to download keypair.json as you won't be able to see it again!",
		"files": [
			{
				"attachment": Buffer.from(JSON.stringify({
					publicKey: JSON.stringify(publicKey),
					privateKey: JSON.stringify(await crypto.subtle.exportKey("jwk", keyPair.privateKey))
				}), "utf8"),
				"name": "keypair.json"
			}
		]
	})
})

client.on(Events.InteractionCreate, async interaction => {
	if (!interaction.isChatInputCommand()) return;
	if (interaction.commandName !== "validate_verification") return;
	await interaction.deferReply();
	const verification = JSON.parse(await (await fetch(interaction.options.getAttachment("verification")?.url!)).text())
	const signatureHex = verification.signature
	if (!signatureHex || signatureHex.length === 0 || signatureHex.length % 2 === 1) return await interaction.followUp("You must input a valid signature.")
	const signature = hexToUintArray(signatureHex)
	const jwtToken = JSON.parse(verification.key)
	const parsed = JSON.parse(verification.data)
	if (!data.keycodes[parsed.user]?.find?.((currentKeycode: Keycode) => currentKeycode.key === verification.key)) {
		if (parsed.date < Date.now() - 1000 * 60 * 60 * 24 * 3) {
			return await interaction.followUp("This verification has expired.")
		} else {
			return await interaction.followUp("Verification not found.")
		}
	}
	const publicKey = await crypto.subtle.importKey("jwk", jwtToken, algorithm, false, ["verify"])
	try {
		console.log(signature.buffer)
		console.log(typeof verification.data)
		if (await crypto.subtle.verify(algorithm, publicKey, signature, new TextEncoder().encode(verification.data))) {
			await interaction.followUp(`This keycode belongs to <@${parsed.user}>, and was validated on <t:${Math.floor(parsed.date / 1000)}>${parsed.status !== "safe" ? " but was marked as " + parsed.status : ""}.`)
		} else {
			await interaction.followUp("Incorrect key!")
		}
	} catch (e) {
		console.error(e)
		await interaction.followUp("Invalid key!")
	}
})

client.on(Events.InteractionCreate, async interaction => {
	if (!interaction.isChatInputCommand()) return;
	if (interaction.commandName !== "validate_self") return;
	await interaction.deferReply({
		ephemeral: true
	});
	console.log(data.keycodes)
	const keyPair = JSON.parse(await (await fetch(interaction.options.getAttachment("key_pair")?.url!)).text())
	const publicKey = keyPair.publicKey
	if (!publicKey) return await interaction.followUp("Please provide the public key argument!")
	const userInfo = Object.entries(data.keycodes).find(info => (info[1] as Keycode[]).find((keycodeInfo: Keycode) => keycodeInfo.key === publicKey))
	if (!userInfo) return await interaction.followUp("This keycode doesn't exist.")
	const keycodes = (userInfo[1] as Keycode[]).sort((a, b) => Date.parse(b.creation) - Date.parse(a.creation))
	const isLatest = keycodes[0].key === publicKey
	let response = `This keycard belongs to <@${userInfo[0]}>`
	let status = "safe";
	if (!isLatest) {
		const keycodeIndex = keycodes.findIndex(code => code.key === publicKey)
		const expiry = Date.parse(keycodes[keycodeIndex - 1].creation) + 1000 * 60 * 60 * 24 * 3
		if (expiry < Date.now()) {
			response = `This keycard owned by <@${userInfo[0]}> expired on <t:${expiry}>.`
			status = "expired"
		} else {
			response = `:warning: This keycard belongs to <@${userInfo[0]}> but a new one was recently created and will expire on <t:${expiry / 1000}>. If you believe their keycode got leaked, do not accept it.`
			status = "old"
		}
	}
	const jwtToken = JSON.parse(keyPair.privateKey)
	let privateKey = null
	try {
		privateKey = await crypto.subtle.importKey("jwk", jwtToken, algorithm, false, ["sign"])
	} catch (e) {
		return await interaction.followUp("Invalid key!")
	}
	const verificationData = JSON.stringify({
		date: Date.now(),
		user: interaction.user.id,
		status
	})
	const signature = arrayBufferToHex(await crypto.subtle.sign(algorithm, privateKey, new TextEncoder().encode(verificationData)))
	await interaction.followUp("Sent!")
	await interaction.followUp({
		"content": response,
		"files": [
			{
				"attachment": Buffer.from(JSON.stringify({
					key: publicKey,
					signature,
					data: verificationData
				}), "utf8"),
				"name": "verification.json"
			}
		]
	})
})
/*
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
await saveData()*/

const commands = [
	new SlashCommandBuilder()
	.setName("send_keycode_message")
	.setDescription("Make the bot send a message for keycode obtaining.")
	.setDefaultMemberPermissions(PermissionsBitField.Flags.ManageGuild),
	new SlashCommandBuilder()
	.setName("obtain_keycode")
	.setDescription("Get assigned a keycode by running this command."),
	new SlashCommandBuilder()
	.setName("validate_verification")
	.setDescription("Check if a verification is valid.")
	.addAttachmentOption(
		new SlashCommandAttachmentOption()
		.setName("verification")
		.setDescription("The verification to check.")
		.setRequired(true)
	),
	new SlashCommandBuilder()
	.setName("validate_self")
	.setDescription("Validate yourself with a private key.")
	.addAttachmentOption(
		new SlashCommandAttachmentOption()
		.setName("key_pair")
		.setDescription("The keypair.json you previously downloaded.")
		.setRequired(true)
	)
]
await client.rest.put(Routes.applicationCommands(client.application!.id), {"body": commands})