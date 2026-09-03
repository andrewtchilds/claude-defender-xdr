import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { createServer } from "./server.js";

// Claude Code still opens with the 2025-11-25 protocol (2.1.238 does), so legacy clients are
// served through the SDK's shim, which fulfils input_required server-side. Rejecting them
// would take every tool away from current installs.
void serveStdio(createServer, { legacy: "serve" });
