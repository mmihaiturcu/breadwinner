import SEAL from "node-seal";

import { SEALLibrary } from "node-seal/implementation/seal";
import { Context } from "node-seal/implementation/context";
import { PublicKey } from "node-seal/implementation/public-key";
import { SecretKey } from "node-seal/implementation/secret-key";
import { CipherText } from "node-seal/implementation/cipher-text";
import { KeyGenerator } from "node-seal/implementation/key-generator";
import { BatchEncoder } from "node-seal/implementation/batch-encoder";
import { GaloisKeys } from "node-seal/implementation/galois-keys";
import { Encryptor } from "node-seal/implementation/encryptor";
import { Decryptor } from "node-seal/implementation/decryptor";
import { RelinKeys } from "node-seal/implementation/relin-keys";
import { KeyPair } from "..";

export class FHEModule {
	public static instance: FHEModule;
	public seal: null | SEALLibrary;
	public context: null | Context;
	public batchEncoder: null | BatchEncoder;
	public encryptor: null | Encryptor;
	public decryptor: null | Decryptor;
	public keyGenerator: null | KeyGenerator;
	public publicKey: null | PublicKey;
	public privateKey: null | SecretKey;
	public galoisKeys: null | GaloisKeys;
	public relinKeys: null | RelinKeys;

	private constructor() {
		this.seal = null;
		this.context = null;
		this.batchEncoder = null;
		this.encryptor = null;
		this.decryptor = null;
		this.keyGenerator = null;
		this.publicKey = null;
		this.privateKey = null;
		this.galoisKeys = null;
		this.relinKeys = null;
	}

	async initFHEContext(): Promise<void> {
		const seal = await SEAL();
		const schemeType = seal.SchemeType.bgv;
		const securityLevel = seal.SecurityLevel.tc128;
		const polyModulusDegree = 8192;
		// const bitSizes = [36, 36, 37];
		const bitSize = 40; // Controls the max number that we can work with / encrypt.

		const encParms = seal.EncryptionParameters(schemeType);

		// Set the PolyModulusDegree
		encParms.setPolyModulusDegree(polyModulusDegree);

		// Create a suitable set of CoeffModulus primes (works for BGV too)
		encParms.setCoeffModulus(
			seal.CoeffModulus.BFVDefault(polyModulusDegree)
		);

		// Set the PlainModulus to a prime of bitSize 20.
		encParms.setPlainModulus(
			seal.PlainModulus.Batching(polyModulusDegree, bitSize)
		);

		// Create a new Context
		const context = seal.Context(
			encParms, // Encryption Parameters
			true, // ExpandModChain
			securityLevel // Enforce a security level
		);

		if (!context.parametersSet()) {
			throw new Error(
				"Could not set the parameters in the given context. Please try different encryption parameters."
			);
		}

		this.seal = seal;
		this.context = context;
		// Create a BatchEncoder (only BGV SchemeType), switch to CKKSEncoder instead for the CKKS scheme.
		this.batchEncoder = this.seal.BatchEncoder(this.context);
		this.keyGenerator = this.seal.KeyGenerator(this.context);
	}
	generateKeys(): {
		publicKey: string;
		privateKey: string;
	} {
		if (this.seal && this.context && this.keyGenerator) {
			this.privateKey = this.keyGenerator.secretKey();
			this.publicKey = this.keyGenerator.createPublicKey();
			this.initializeEncryptor();
			this.initializeDecryptor();

			return {
				publicKey: this.publicKey.save(),
				privateKey: this.privateKey.save(),
			};
		} else {
			throw new Error("FHE Module has not been initialized.");
		}
	}
	generateGaloisKeys(): string {
		if (this.seal && this.context && this.keyGenerator) {
			////////////////////////
			// Keys
			////////////////////////

			this.galoisKeys = this.keyGenerator.createGaloisKeys();

			return this.galoisKeys.save();
		} else {
			throw new Error("FHE Module has not been initialized.");
		}
	}
	generateRelinKeys(): string {
		if (this.seal && this.context && this.keyGenerator) {
			this.relinKeys = this.keyGenerator.createRelinKeys();
			return this.relinKeys.save();
		} else {
			throw new Error("FHE Module has not been initialized.");
		}
	}
	setPublicKey(publicKey: string) {
		if (this.seal && this.context) {
			this.publicKey = this.seal.PublicKey();
			this.publicKey.load(this.context, publicKey);
		} else {
			throw new Error("FHE Module has not been initialized.");
		}
	}
	encryptData(data: number[]): string {
		if (this.seal && this.context && this.batchEncoder && this.encryptor) {
			////////////////////////
			// Instances
			////////////////////////

			// Or a CKKSEncoder (only CKKS SchemeType)
			// const encoder = seal.CKKSEncoder(context)

			// Create a Decryptor to decrypt CipherTexts

			// Encode data to a PlainText
			const plainTextA = this.batchEncoder.encode(
				Int32Array.from(data) // This could also be a Uint32Array
			);

			if (plainTextA) {
				// Encrypt a PlainText
				const cipherTextA = this.encryptor.encrypt(plainTextA);

				if (cipherTextA) {
					const encryptedBase64Data = cipherTextA.save();
					cipherTextA.delete();
					return encryptedBase64Data;
				} else {
					throw new Error("Ciphertext could not be created.");
				}
			} else {
				throw new Error("Plaintext could not be created.");
			}
		} else {
			throw new Error("FHE Module has not been initialized.");
		}
	}
	decryptData(encryptedData: CipherText): Int32Array | Uint32Array {
		if (this.seal && this.context && this.decryptor && this.batchEncoder) {
			// Decrypt a CipherText
			const plainTextD = this.decryptor.decrypt(encryptedData);

			if (plainTextD) {
				// `signed` defaults to 'true' if not specified and will return an Int32Array.
				// If you have encrypted a Uint32Array and wish to decrypt it, set
				// this to false.
				const decoded = this.batchEncoder.decode(
					plainTextD,
					true // Can be omitted since this defaults to true.
				);
				plainTextD.delete();
				return decoded;
			} else {
				throw new Error("Could not decrypt ciphertext.");
			}
		} else {
			throw new Error("FHE Module has not been initialized");
		}
	}

	setKeyPair(keyPair: KeyPair) {
		if (this.seal && this.context) {
			this.publicKey = this.seal.PublicKey();
			this.publicKey.load(this.context, keyPair.publicKey);
			this.privateKey = this.seal.SecretKey();
			this.privateKey.load(this.context, keyPair.privateKey);
			this.initializeEncryptor();
			this.initializeDecryptor();
		} else {
			throw new Error("FHE Module has not been initialized.");
		}
	}

	initializeEncryptor() {
		if (this.seal && this.context && this.publicKey) {
			this.encryptor?.delete();
			this.encryptor = this.seal.Encryptor(this.context, this.publicKey);
		} else {
			throw new Error("FHE Module has not been initialized.");
		}
	}

	initializeDecryptor() {
		if (this.seal && this.context && this.privateKey) {
			this.decryptor?.delete();
			this.decryptor = this.seal.Decryptor(this.context, this.privateKey);
		} else {
			throw new Error("FHE Module has not been initialized.");
		}
	}

	deallocate() {
		this.context?.delete();
		this.batchEncoder?.delete();
		this.encryptor?.delete();
		this.decryptor?.delete();
		this.keyGenerator?.delete();
		this.publicKey?.delete();
		this.privateKey?.delete();
		this.galoisKeys?.delete();
		this.relinKeys?.delete();
	}

	public static getInstance(): FHEModule {
		if (!this.instance) {
			this.instance = new FHEModule();
		}

		return this.instance;
	}
}

export default FHEModule.getInstance();
