export { OperandTypes } from "./src/OperandTypes";
export { Operations } from "./src/Operations";

import BreadwinnerModule from "./src/BreadwinnerModule";
import FHEModule from "./src/FHEModule";

import { CipherText } from "node-seal/implementation/cipher-text";
import { PlainText } from "node-seal/implementation/plain-text";
import { OperandTypes } from "./src/OperandTypes";
import { Operations } from "./src/Operations";

export interface ChunkToProcess {
	id: number;
	length: number;
	columnsData: string;
}

export interface Operand {
	type: OperandTypes;
	field: string;
	plaintextValue?: number | string;
	isRaw?: boolean;
}

export interface BreadwinnerCipherText extends CipherText {
	instance: {
		constructor: {
			name: string;
		};
	};
}

export interface BreadwinnerPlainText extends PlainText {
	instance: {
		constructor: {
			name: string;
		};
	};
}

export interface CalculatorOperand {
	type: OperandTypes;
	data: BreadwinnerCipherText | BreadwinnerPlainText;
}
export interface OperationDTO {
	name: Operations;
	operands: Operand[];
	resultType: OperandTypes;
}

export interface JSONSchema {
	totalDataLength: number;
	operations: OperationDTO[];
}

export interface PayloadToProcess {
	id: number;
	jsonSchema: string;
	chunk: ChunkToProcess;
	publicKey: string;
	galoisKeys?: string;
	relinKeys?: string;
}

export interface PayloadMessage {
	payload: PayloadToProcess;
	token: string;
}

export interface KeyPair {
	publicKey: string;
	privateKey: string;
}

export { BreadwinnerModule, FHEModule };
