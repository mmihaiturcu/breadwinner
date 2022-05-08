class BreadwinnerModule {
	private static instance: BreadwinnerModule;
	private worker?: Worker;

	public static getInstance(): BreadwinnerModule {
		if (!this.instance) {
			this.instance = new BreadwinnerModule();
		}

		return this.instance;
	}

	public init(apiKey: string) {
		if (this.worker) {
			this.worker.terminate();
		}

		this.worker = new Worker(
			new URL("./BreadwinnerWorker.worker.js", import.meta.url)
		);
		this.worker.postMessage([apiKey]);
	}

	public disconnect() {
		this.worker?.terminate();
	}
}

export default BreadwinnerModule.getInstance();
