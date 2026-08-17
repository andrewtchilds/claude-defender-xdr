import { chmod, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { getXdrDirectory } from "./config.js";
export class SecureCacheUnavailableError extends Error {
    constructor() {
        super("OS-backed secure token storage is unavailable. Run claude-defender-xdr-login interactively to approve an owner-only unencrypted file cache, or fix the OS keychain/secret service.");
        this.name = "SecureCacheUnavailableError";
    }
}
/**
 * `@azure/msal-node-extensions` pulls in the native `keytar` binding, which throws at
 * require-time when its prebuilt binary is missing. Importing it lazily keeps the rest of
 * the server — notably the offline `xdr_get_schema` tool — usable on such installs.
 */
function loadExtensions() {
    return import("@azure/msal-node-extensions");
}
async function prepareDirectory(path) {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    await chmod(dirname(path), 0o700);
}
/**
 * Prefers the OS credential store (Keychain / DPAPI / Secret Service). Falls back to a
 * 0600 plaintext file only when the caller has already obtained explicit user approval.
 */
export async function createPersistentCache(allowUnencryptedFallback, directory = getXdrDirectory()) {
    const securePath = join(directory, "msal-cache.bin");
    await prepareDirectory(securePath);
    try {
        const { DataProtectionScope, PersistenceCachePlugin, PersistenceCreator } = await loadExtensions();
        const persistence = await PersistenceCreator.createPersistence({
            cachePath: securePath,
            dataProtectionScope: DataProtectionScope.CurrentUser,
            serviceName: "claude-defender-xdr",
            accountName: "msal-token-cache",
            usePlaintextFileOnLinux: false,
        });
        if (!(await persistence.verifyPersistence()))
            throw new Error("secure persistence verification failed");
        await chmod(securePath, 0o600).catch(() => undefined);
        return {
            cachePlugin: new PersistenceCachePlugin(persistence),
            persistence,
            security: "os-protected",
            path: securePath,
        };
    }
    catch {
        if (!allowUnencryptedFallback)
            throw new SecureCacheUnavailableError();
    }
    const { FilePersistence, PersistenceCachePlugin } = await loadExtensions();
    const fallbackPath = join(directory, "msal-cache.unencrypted.json");
    const persistence = await FilePersistence.create(fallbackPath);
    await chmod(fallbackPath, 0o600);
    if (!(await persistence.verifyPersistence())) {
        throw new Error("Owner-only token cache verification failed");
    }
    return {
        cachePlugin: new PersistenceCachePlugin(persistence),
        persistence,
        security: "owner-only-file",
        path: fallbackPath,
    };
}
//# sourceMappingURL=cache.js.map