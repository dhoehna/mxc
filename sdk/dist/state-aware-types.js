// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
const ISO_USER_INSPECT = Symbol.for('nodejs.util.inspect.custom');
/**
 * Entra credentials, supplied at provision to opt into an Entra-backed
 * sandbox and at start to authenticate the session. `wamToken` is treated
 * as a secret: `util.inspect` and `console.log` redact it. `JSON.stringify`
 * is unaffected — the wire envelope carries the token verbatim.
 */
export class IsolationSessionUserConfig {
    upn;
    wamToken;
    constructor(upn, wamToken) {
        this.upn = upn;
        this.wamToken = wamToken;
    }
    [ISO_USER_INSPECT]() {
        return `IsolationSessionUserConfig { upn: '${this.upn}', wamToken: '<redacted>' }`;
    }
}
//# sourceMappingURL=state-aware-types.js.map