import { CipherText } from "node-seal/implementation/cipher-text";
import { Evaluator } from "node-seal/implementation/evaluator";
import { GaloisKeys } from "node-seal/implementation/galois-keys";
import { PlainText } from "node-seal/implementation/plain-text";
import { RelinKeys } from "node-seal/implementation/relin-keys";
import FHEModule from "./FHEModule";
import { OperandTypes } from "./OperandTypes";
import { CalculatorOperand } from "..";

export function add(
	evaluator: Evaluator,
	galoisKeys: GaloisKeys,
	...operands: CalculatorOperand[]
): CipherText {
	if (
		operands.length === 1 &&
		operands[0].type === OperandTypes.ARRAY &&
		operands[0].data.instance.constructor.name === "Ciphertext"
	) {
		// Sum vector elements
		return evaluator.sumElements(
			operands[0].data as CipherText,
			galoisKeys,
			FHEModule.seal!.SchemeType.bgv
		)!;
	} else if (operands.length === 2) {
		if (
			operands.every(
				(operand) =>
					operand.data.instance.constructor.name === "Ciphertext"
			)
		) {
			return evaluator.add(
				operands[0].data as CipherText,
				operands[1].data as CipherText
			)!;
		} else {
			const indexOfTypesMap = new Map<
				"Plaintext" | "Ciphertext",
				PlainText | CipherText
			>();
			indexOfTypesMap.set(
				"Plaintext",
				operands.find(
					(operand) =>
						operand.data.instance.constructor.name === "Plaintext"
				)!.data
			);
			indexOfTypesMap.set(
				"Ciphertext",
				operands.find(
					(operand) =>
						operand.data.instance.constructor.name === "Ciphertext"
				)!.data
			);

			return evaluator.addPlain(
				indexOfTypesMap.get("Ciphertext") as CipherText,
				indexOfTypesMap.get("Plaintext") as PlainText
			)!;
		}
	} else {
		throw new Error("Unsupported operand types.");
	}
}

export function subtract(
	evaluator: Evaluator,
	...operands: CalculatorOperand[]
): CipherText {
	if (
		operands.length === 2 &&
		operands.every(
			(operand) => operand.data.instance.constructor.name === "Ciphertext"
		)
	) {
		return evaluator.sub(
			operands[0].data as CipherText,
			operands[1].data as CipherText
		)!;
	} else if (
		operands.length === 2 &&
		operands.some(
			(operand) => operand.data.instance.constructor.name === "Plaintext"
		)
	) {
		// case to handle subtracting a number from an array
		return evaluator.subPlain(
			operands[0].data as CipherText,
			operands[1].data as PlainText
		)!;
	} else {
		throw new Error("Unsupported operand types.");
	}
}

export function multiply(
	evaluator: Evaluator,
	relinKeys: RelinKeys,
	...operands: CalculatorOperand[]
): CipherText {
	if (operands.length === 2) {
		if (
			operands.every(
				(operand) =>
					operand.data.instance.constructor.name === "Ciphertext"
			)
		) {
			// Ciphertext * Ciphertext (numbers or array, it doesn't matter.)
			const cipher = evaluator.multiply(
				operands[0].data as CipherText,
				operands[1].data as CipherText
			)!;

			return evaluator.relinearize(cipher, relinKeys)!;
		} else {
			// Ciphertext * Plaintext (order matters, we need to call multiplyPlain correctly)
			const indexOfTypesMap = new Map<
				"Plaintext" | "Ciphertext",
				PlainText | CipherText
			>();
			indexOfTypesMap.set(
				"Plaintext",
				operands.find(
					(operand) =>
						operand.data.instance.constructor.name === "Plaintext"
				)!.data
			);
			indexOfTypesMap.set(
				"Ciphertext",
				operands.find(
					(operand) =>
						operand.data.instance.constructor.name === "Ciphertext"
				)!.data
			);
			const cipher = evaluator.multiplyPlain(
				indexOfTypesMap.get("Ciphertext") as CipherText,
				indexOfTypesMap.get("Plaintext") as PlainText
			)!;

			return evaluator.relinearize(cipher, relinKeys)!;
		}
	} else {
		throw new Error("Unsupported operand types.");
	}
}

export function exponentiate(
	evaluator: Evaluator,
	relinKeys: RelinKeys,
	cipherTextOperand: CipherText,
	exponent: number
): CipherText {
	return evaluator.exponentiate(cipherTextOperand, exponent, relinKeys)!;
}
