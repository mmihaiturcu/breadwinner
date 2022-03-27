import { ChunkToProcess, PayloadMessage, PayloadToProcess } from "..";
import { CipherText } from "node-seal/implementation/cipher-text";
import { PlainText } from "node-seal/implementation/plain-text";
import { REWARD_TIMEOUT_MS } from "./constants.js";
import FHEModule from "./FHEModule.js";
import { Operations } from "./Operations.js";
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

	private processChunk(
		chunk: ChunkToProcess,
		payload: PayloadToProcess
	): string {
		console.log(chunk, payload);
		const dataObject = new Map<string | number, CipherText | PlainText>();
		const columnsData = JSON.parse(chunk.columnsData) as Record<
			string,
			string
		>;

		Object.entries(columnsData).forEach(([field, data]) => {
			const cipherText = FHEModule.seal!.CipherText();
			cipherText.load(FHEModule.context!, data);
			dataObject.set(`d${field}`, cipherText);
		});

		payload.jsonSchema.operations.forEach((operation, operationIndex) => {
			operation.operands.forEach((operand) => {
				if ("plaintextValue" in operand && !("isRaw" in operand)) {
					const plainText = FHEModule.batchEncoder!.encode(
						Int32Array.from(
							new Array(chunk.length).fill(operand.plaintextValue)
						)
					)!;
					dataObject.set(`p${operationIndex}`, plainText);
				}
			});
		});

		const galoisKeys = FHEModule.seal!.GaloisKeys();

		if (payload.galoisKeys) {
			galoisKeys.load(FHEModule.context!, payload.galoisKeys);
		}

		const relinKeys = FHEModule.seal!.RelinKeys();

		if (payload.relinKeys) {
			relinKeys.load(FHEModule.context!, payload.relinKeys);
		}

		const evaluator = FHEModule.seal?.Evaluator(FHEModule.context!);

		if (evaluator) {
			for (const [
				index,
				operation,
			] of payload.jsonSchema.operations.entries()) {
				switch (operation.name) {
					case Operations.ADD: {
						dataObject.set(
							index,
							add(
								evaluator,
								galoisKeys,
								...operation.operands.map((operand) => ({
									type: operand.type,
									data: dataObject.get(operand.field)!,
								}))
							)
						);
						break;
					}
					case Operations.SUBTRACT: {
						dataObject.set(
							index,
							subtract(
								evaluator,
								...operation.operands.map((operand) => ({
									type: operand.type,
									data: dataObject.get(operand.field)!,
								}))
							)
						);
						break;
					}
					case Operations.MULTIPLY: {
						dataObject.set(
							index,
							multiply(
								evaluator,
								relinKeys,
								...operation.operands.map((operand) => ({
									type: operand.type,
									data: dataObject.get(operand.field)!,
								}))
							)
						);
						break;
					}
					case Operations.EXPONENTIATION: {
						dataObject.set(
							index,
							exponentiate(
								evaluator,
								relinKeys,
								dataObject.get(
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

		const result = dataObject
			.get(payload.jsonSchema.operations.length - 1)!
			.save();

		// Perform cleanup, deallocating any memory.
		dataObject.forEach((value) => {
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

			await FHEModule.initFHEContext();
			FHEModule.setPublicKey(payload.publicKey);

			const result = this.processChunk(chunkToProcess, payload);

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
		this.websocketConnection.onmessage = (event: MessageEvent<string>) =>
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
