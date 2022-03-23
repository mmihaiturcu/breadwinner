declare module 'breadwinner' {
    import { CipherText } from 'node-seal/implementation/cipher-text';
    import { PlainText } from 'node-seal/implementation/plain-text';

    export enum WebsocketEventTypes {
        REQUEST_CHUNK = '0',
        SEND_CHUNK_PROCESSING_RESULT = '1',
    }

    export enum Operations {
        ADD,
        SUBTRACT,
        MULTIPLY,
        EXPONENTIATION,
    }

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

    export enum OperandTypes {
        NUMBER,
        ARRAY,
        NONE,
    }

    interface BreadwinnerCipherText extends CipherText {
        instance: {
            constructor: {
                name: string;
            };
        };
    }

    interface BreadwinnerPlainText extends PlainText {
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
        jsonSchema: JSONSchema;
        chunk: ChunkToProcess;
        publicKey: string;
        galoisKeys?: string;
        relinKeys?: string;
    }

    export interface KeyPair {
        publicKey: string;
        privateKey: string;
    }
}
