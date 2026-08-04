import { DataProtectionScope, FilePersistence, PersistenceCachePlugin, PersistenceCreator } from "@azure/msal-node-extensions";
import { chmod, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { getXdrDirectory } from "./config.js";
export class SecureCacheUnavailableError extends Error {
    constructor() { super("OS-backed secure token storage is unavailable. Run claude-defender-xdr-login interactively to approve an owner-only unencrypted file cache, or fix the OS keychain/secret service."); this.name = "SecureCacheUnavailableError"; }
}
async function prepare(path) { await mkdir(dirname(path), { recursive: true, mode: 0o700 }); await chmod(dirname(path), 0o700); }
export async function createPersistentCache(allowUnencryptedFallback, directory = getXdrDirectory()) {
    const path = join(directory, "msal-cache.bin");
    await prepare(path);
    try {
        const p = await PersistenceCreator.createPersistence({ cachePath: path, dataProtectionScope: DataProtectionScope.CurrentUser, serviceName: "claude-defender-xdr", accountName: "msal-token-cache", usePlaintextFileOnLinux: false });
        if (!(await p.verifyPersistence()))
            throw new Error("secure persistence verification failed");
        await chmod(path, 0o600).catch(() => undefined);
        return { cachePlugin: new PersistenceCachePlugin(p), persistence: p, security: "os-protected", path };
    }
    catch {
        if (!allowUnencryptedFallback)
            throw new SecureCacheUnavailableError();
    }
    const fallbackPath = join(directory, "msal-cache.unencrypted.json"), p = await FilePersistence.create(fallbackPath);
    await chmod(fallbackPath, 0o600);
    if (!(await p.verifyPersistence()))
        throw new Error("Owner-only token cache verification failed");
    return { cachePlugin: new PersistenceCachePlugin(p), persistence: p, security: "owner-only-file", path: fallbackPath };
}
//# sourceMappingURL=cache.js.map