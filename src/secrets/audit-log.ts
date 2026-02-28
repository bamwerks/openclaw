/**
 * Audit logging for credential access and grants.
 * 
 * Writes JSONL (JSON Lines) to {dataDir}/audit/credentials.jsonl.
 * Each line is a JSON object with event details.
 */

import { mkdir, appendFile, stat, rename } from "node:fs/promises";
import { join } from "node:path";
import { STATE_DIR } from "../config/paths.js";

/** Max audit log size before rotation (5MB). */
const MAX_LOG_SIZE = 5 * 1024 * 1024;

/**
 * Audit log entry.
 */
export interface AuditEntry {
  /** Event type */
  event:
    | "credential_accessed"
    | "metadata_accessed"
    | "grant_created"
    | "grant_revoked"
    | "credential_resolved"
    | "credential_denied";
  /** Secret name */
  name: string;
  /** Tool name (for credential_resolved) */
  tool?: string;
  /** Timestamp (milliseconds since epoch) */
  timestamp: number;
  /** Additional context */
  details?: Record<string, unknown>;
}

/**
 * Get audit log file path.
 */
function getAuditLogPath(): string {
  return join(STATE_DIR, "audit", "credentials.jsonl");
}

/**
 * Log an audit entry.
 * @param entry Audit entry to log
 */
export async function auditLog(entry: AuditEntry): Promise<void> {
  const logPath = getAuditLogPath();
  const logDir = join(STATE_DIR, "audit");
  
  // Ensure audit directory exists with restricted permissions
  await mkdir(logDir, { recursive: true, mode: 0o700 });
  
  // Rotate if log exceeds max size
  try {
    const stats = await stat(logPath);
    if (stats.size > MAX_LOG_SIZE) {
      const rotatedPath = logPath.replace(".jsonl", `.${Date.now()}.jsonl`);
      await rename(logPath, rotatedPath);
    }
  } catch {
    // File doesn't exist yet, no rotation needed
  }
  
  // Append JSON line
  const line = JSON.stringify(entry) + "\n";
  await appendFile(logPath, line, { encoding: "utf-8", mode: 0o600 });
}
