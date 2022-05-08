import {
	ChunkToProcess,
	JSONSchema,
	PayloadMessage,
	PayloadToProcess,
} from "..";
import { CipherText } from "node-seal/implementation/cipher-text";
import { PlainText } from "node-seal/implementation/plain-text";
import { REWARD_TIMEOUT_MS } from "./constants.js";
import FHEModule from "./FHEModule.js";
import { OperationType } from "./OperationType.js";
import { add, subtract, multiply, exponentiate } from "./OperationsCalculator";
import { WebsocketEventTypes } from "./WebsocketEventTypes.js";

class BreadwinnerWorker {
	public static instance: BreadwinnerWorker;
	private apiKey?: string;
	private websocketConnection?: WebSocket;

	public static getInstance(): BreadwinnerWorker {
		if (!this.instance) {
			this.instance = new BreadwinnerWorker();
		}

		return this.instance;
	}

	private requestPayload() {
		this.websocketConnection?.send(
			JSON.stringify({ type: WebsocketEventTypes.REQUEST_CHUNK })
		);
	}

	private onWebsocketOpen(event: Event) {
		console.log("open", event);
		this.requestPayload();
	}

	private onWebsocketError(event: Event) {
		console.log("error", event);
	}

	private onWebsocketClosed(event: Event) {
		console.log("closed", event);
	}

	private async processChunk(
		chunk: ChunkToProcess,
		payload: PayloadToProcess
	): Promise<string> {
		// 1. Parse operations pipeline schema.
		const parsedJSONSchema = JSON.parse(payload.jsonSchema) as JSONSchema;

		// 2. Initialize FHE module and load public key.
		await FHEModule.initFHEContext(parsedJSONSchema.schemeType);
		FHEModule.setPublicKey(payload.publicKey);
		console.log(chunk, payload);

		// 3. Populate map with the encrypted data and encoded plaintext values.
		const operandsAndResultsMap = new Map<
			string | number,
			CipherText | PlainText
		>();
		const columnsData = JSON.parse(chunk.columnsData) as Record<
			string,
			string
		>;

		Object.entries(columnsData).forEach(([field, data]) => {
			const cipherText = FHEModule.seal!.CipherText();
			cipherText.load(FHEModule.context!, data);
			operandsAndResultsMap.set(`d${field}`, cipherText);
		});

		parsedJSONSchema.operations.forEach((operation, operationIndex) => {
			operation.operands.forEach((operand) => {
				if ("plaintextValue" in operand && !("isRaw" in operand)) {
					const plainText = FHEModule.encode(
						new Array(chunk.length).fill(operand.plaintextValue)
					);
					operandsAndResultsMap.set(`p${operationIndex}`, plainText);
				}
			});
		});

		// 4. Load specialized keys.
		const galoisKeys = FHEModule.seal!.GaloisKeys();

		if (payload.galoisKeys) {
			galoisKeys.load(FHEModule.context!, payload.galoisKeys);
		}

		const relinKeys = FHEModule.seal!.RelinKeys();

		if (payload.relinKeys) {
			relinKeys.load(FHEModule.context!, payload.relinKeys);
		}

		// 5. Evaluate operations and store their results.
		const evaluator = FHEModule.seal?.Evaluator(FHEModule.context!);

		if (evaluator) {
			for (const [
				index,
				operation,
			] of parsedJSONSchema.operations.entries()) {
				switch (operation.type) {
					case OperationType.ADD: {
						operandsAndResultsMap.set(
							index,
							add(
								evaluator,
								galoisKeys,
								...operation.operands.map((operand) => ({
									type: operand.type,
									data: operandsAndResultsMap.get(
										operand.field
									)!,
								}))
							)
						);
						break;
					}
					case OperationType.SUBTRACT: {
						operandsAndResultsMap.set(
							index,
							subtract(
								evaluator,
								...operation.operands.map((operand) => ({
									type: operand.type,
									data: operandsAndResultsMap.get(
										operand.field
									)!,
								}))
							)
						);
						break;
					}
					case OperationType.MULTIPLY: {
						operandsAndResultsMap.set(
							index,
							multiply(
								evaluator,
								relinKeys,
								...operation.operands.map((operand) => ({
									type: operand.type,
									data: operandsAndResultsMap.get(
										operand.field
									)!,
								}))
							)
						);
						break;
					}
					case OperationType.EXPONENTIATION: {
						operandsAndResultsMap.set(
							index,
							exponentiate(
								evaluator,
								relinKeys,
								operandsAndResultsMap.get(
									operation.operands[0].field
								)! as CipherText,
								operation.operands[1].plaintextValue as number
							)
						);
						break;
					}
				}
			}
		} else {
			throw new Error("Evaluator not available.");
		}

		// 6. Extract the last operation's result, to submit it to the server.
		const result = operandsAndResultsMap
			.get(parsedJSONSchema.operations.length - 1)!
			.save();

		// 7. Perform cleanup, deallocating any memory.
		operandsAndResultsMap.forEach((value) => {
			value.delete();
		});
		FHEModule.deallocate();

		return result;
	}

	private async processPayload(event: MessageEvent<string>) {
		if (event.data) {
			const { payload, token } = JSON.parse(event.data) as PayloadMessage;
			const chunkToProcess = payload.chunk;

			console.log("Received payload to process", payload);

			const result = await this.processChunk(chunkToProcess, payload);

			console.log("processing result", result);

			this.websocketConnection?.send(
				JSON.stringify({
					type: WebsocketEventTypes.SEND_CHUNK_PROCESSING_RESULT,
					data: {
						chunkId: chunkToProcess.id,
						result,
						token,
					},
				})
			);
		}

		setTimeout(() => this.requestPayload(), REWARD_TIMEOUT_MS);
	}

	private initializeWebsocketConnection() {
		this.websocketConnection = new WebSocket(
			"wss://localhost:8420",
			this.apiKey
		);
		this.websocketConnection.onmessage = (event) =>
			this.processPayload(event);
		this.websocketConnection.onerror = (event) =>
			this.onWebsocketError(event);
		this.websocketConnection.onclose = (event) =>
			this.onWebsocketClosed(event);
		this.websocketConnection.onopen = (event) =>
			this.onWebsocketOpen(event);
	}

	public init(apiKey: string) {
		this.apiKey = apiKey;

		if (this.websocketConnection) {
			this.websocketConnection.close();
		}

		this.initializeWebsocketConnection();
	}
}

const instance = BreadwinnerWorker.getInstance();

addEventListener("message", async (e) => {
	instance.init(e.data[0]);
});
