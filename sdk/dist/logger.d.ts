/**
 * Appends timestamped log lines to a file.
 * Emits console.warn if the file cannot be opened, then degrades to no-op.
 */
export declare class FileLogger {
    private fd;
    constructor(filePath: string);
    log(level: 'info' | 'warn' | 'error', message: string, data?: Record<string, unknown>): void;
    close(): void;
}
//# sourceMappingURL=logger.d.ts.map