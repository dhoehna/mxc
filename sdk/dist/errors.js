// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Typed error thrown by the MXC SDK in response to a wire-format error
 * envelope. Discriminate by comparing `.code` to a wire-format error code
 * string; the TypeScript string-literal union gives the same IDE
 * completion as a class hierarchy without the multiplicative class count.
 */
export class MxcError extends Error {
    code;
    details;
    constructor(code, message, details) {
        super(message);
        this.code = code;
        this.details = details;
        // Restore the prototype chain so `instanceof MxcError` keeps working
        // after the TypeScript ES2020 → ES5-compatible class downlevelling.
        Object.setPrototypeOf(this, new.target.prototype);
        this.name = 'MxcError';
    }
}
/**
 * Constructs an `MxcError` from a wire-format error code. Accepts a plain
 * `string` so callers parsing a wire envelope don't need to narrow first;
 * unknown codes still produce an `MxcError` with `.code` set to whatever
 * was on the wire.
 */
export function mxcErrorFromCode(code, message, details) {
    return new MxcError(code, message, details);
}
//# sourceMappingURL=errors.js.map