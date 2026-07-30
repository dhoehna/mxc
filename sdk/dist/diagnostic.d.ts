/**
 * Send a diagnostic log message to the MXC diagnostic console.
 *
 * Messages are best-effort and non-blocking. If the console is not
 * running, the message is silently dropped.
 *
 * Each message is sent as a newline-delimited JSON envelope so the
 * console can split coalesced stream writes back into individual messages.
 *
 * @param message - The log message to send
 */
export declare function diagLog(message: string): void;
/**
 * Close the diagnostic pipe connection. Called during cleanup.
 */
export declare function diagClose(): void;
//# sourceMappingURL=diagnostic.d.ts.map