import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import qrcode from "qrcode-terminal";
import { confirm } from "@clack/prompts";
import { danger } from "../globals.js";
import { defaultRuntime } from "../runtime.js";
import { loadConfig } from "../config/config.js";
import { STATE_DIR } from "../config/paths.js";
import { renderTable } from "../terminal/table.js";
import { theme } from "../terminal/theme.js";
import { formatDocsLink } from "../terminal/links.js";

// Vault management (our implementation)
import {
  deleteSecret,
  getSecret,
  grantSecret,
  listSecrets,
  revokeSecret,
  setSecret,
  setupTotp,
  type SecretTier,
} from "../secrets/index.js";
import { getRegistry } from "../secrets/registry.js";

// Config auditing (upstream implementation)
import { runSecretsApply } from "../secrets/apply.js";
import { resolveSecretsAuditExitCode, runSecretsAudit } from "../secrets/audit.js";
import { runSecretsConfigureInteractive } from "../secrets/configure.js";
import { isSecretsApplyPlan, type SecretsApplyPlan } from "../secrets/plan.js";
import { addGatewayClientOptions, callGatewayFromCli, type GatewayRpcOpts } from "./gateway-rpc.js";

// ============================================================================
// Types
// ============================================================================

type SecretsOpts = {
  tier?: string;
  description?: string;
  value?: string;
  ttl?: string;
  confirm?: boolean;
  json?: boolean;
};

type SecretsReloadOptions = GatewayRpcOpts & { json?: boolean };

type SecretsAuditOptions = {
  check?: boolean;
  json?: boolean;
};

type SecretsConfigureOptions = {
  apply?: boolean;
  yes?: boolean;
  planOut?: string;
  providersOnly?: boolean;
  skipProviderSetup?: boolean;
  json?: boolean;
};

type SecretsApplyOptions = {
  from: string;
  dryRun?: boolean;
  json?: boolean;
};

// ============================================================================
// Helpers
// ============================================================================

function parseTier(tier: string | undefined): SecretTier {
  if (!tier) return "controlled";
  const normalized = tier.toLowerCase();
  if (normalized === "open" || normalized === "controlled" || normalized === "restricted") {
    return normalized;
  }
  throw new Error(`Invalid tier: ${tier}. Must be open, controlled, or restricted.`);
}

function formatGrantStatus(valid: boolean, expiresAt?: number, remainingMinutes?: number): string {
  if (!valid || !expiresAt) return theme.muted("—");
  if (expiresAt <= Date.now()) return theme.error("expired");
  if (remainingMinutes !== undefined) {
    const h = Math.floor(remainingMinutes / 60);
    const m = remainingMinutes % 60;
    return theme.success(h > 0 ? `${h}h ${m}m` : `${m}m`);
  }
  return theme.success("valid");
}

async function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on("data", (chunk) => chunks.push(chunk));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8").trim()));
    process.stdin.on("error", reject);
  });
}

function readPlanFile(pathname: string): SecretsApplyPlan {
  const raw = fs.readFileSync(pathname, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (!isSecretsApplyPlan(parsed)) {
    throw new Error(`Invalid secrets plan file: ${pathname}`);
  }
  return parsed;
}

// ============================================================================
// CLI Registration
// ============================================================================

export function registerSecretsCli(program: Command) {
  const secrets = program
    .command("secrets")
    .description("Secrets management: vault storage and config auditing")
    .addHelpText(
      "after",
      () =>
        `\n${theme.muted("Docs:")} ${formatDocsLink("/gateway/secrets", "docs.openclaw.ai/gateway/secrets")}\n`,
    );

  // =========================================================================
  // VAULT MANAGEMENT COMMANDS (our implementation)
  // =========================================================================

  secrets
    .command("list")
    .description("List all registered secrets in the vault")
    .option("--json", "Output JSON", false)
    .action(async (opts: SecretsOpts) => {
      try {
        const secretsList = await listSecrets();
        
        if (opts.json) {
          defaultRuntime.log(JSON.stringify(secretsList, null, 2));
          return;
        }

        if (!secretsList.length) {
          defaultRuntime.log(theme.muted("No secrets registered."));
          return;
        }

        const tableWidth = Math.max(60, (process.stdout.columns ?? 120) - 1);
        defaultRuntime.log(
          renderTable({
            width: tableWidth,
            columns: [
              { key: "Name", header: "Name", minWidth: 20, flex: true },
              { key: "Tier", header: "Tier", minWidth: 12 },
              { key: "Grant", header: "Grant Status", minWidth: 15 },
              { key: "Expires", header: "Expires", minWidth: 12 },
            ],
            rows: secretsList.map((s) => ({
              Name: s.name,
              Tier: s.tier === "open" 
                ? theme.success(s.tier) 
                : s.tier === "restricted" 
                  ? theme.error(s.tier) 
                  : theme.warn(s.tier),
              Grant: s.tier === "open"
                ? theme.muted("always")
                : s.grant.valid
                  ? formatGrantStatus(s.grant.valid, s.grant.expiresAt, s.grant.remainingMinutes)
                  : theme.error("none"),
              Expires: s.tier === "open"
                ? theme.muted("n/a")
                : s.grant.expiresAt
                  ? new Date(s.grant.expiresAt).toLocaleString()
                  : theme.muted("—"),
            })),
          }),
        );
        defaultRuntime.log();
        defaultRuntime.log(
          theme.muted(`Total: ${secretsList.length} secret${secretsList.length === 1 ? "" : "s"}`),
        );
      } catch (err) {
        defaultRuntime.error(danger(String(err)));
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("get <name>")
    .description("Get a secret value (requires valid grant for controlled/restricted)")
    .option("--json", "Output JSON", false)
    .action(async (name: string, opts: SecretsOpts) => {
      try {
        const result = await getSecret(name);
        
        if (opts.json) {
          defaultRuntime.log(JSON.stringify(result, null, 2));
          return;
        }

        if (result.type === "metadata") {
          defaultRuntime.log(theme.warn("No active grant. Metadata only:"));
          defaultRuntime.log(`  ${theme.muted("Name:")}  ${result.metadata.name}`);
          defaultRuntime.log(`  ${theme.muted("Tier:")}  ${result.metadata.tier}`);
          defaultRuntime.log(`  ${theme.muted("Ref:")}   ${result.metadata.ref}`);
          if (result.metadata.hint) {
            defaultRuntime.log(`  ${theme.muted("Hint:")}  ${result.metadata.hint}`);
          }
          defaultRuntime.log();
          defaultRuntime.log(theme.muted(`Use 'openclaw secrets grant ${name}' to get access.`));
        } else {
          defaultRuntime.log(result.value);
        }
      } catch (err) {
        defaultRuntime.error(danger(String(err)));
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("set <name>")
    .description("Set or update a secret")
    .option("--tier <tier>", "Access tier: open, controlled, restricted", "controlled")
    .option("--value <value>", "Secret value (if not provided, reads from stdin)")
    .option("--description <desc>", "Description for this secret")
    .action(async (name: string, opts: SecretsOpts) => {
      try {
        const tier = parseTier(opts.tier);
        const value = opts.value ?? await readStdin();
        
        if (!value) {
          defaultRuntime.error(danger("Secret value cannot be empty."));
          defaultRuntime.exit(1);
          return;
        }

        await setSecret(name, value, { tier, description: opts.description });
        defaultRuntime.log(theme.success(`Secret '${name}' set (tier: ${tier}).`));
      } catch (err) {
        defaultRuntime.error(danger(String(err)));
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("delete <name>")
    .description("Delete a secret from the vault")
    .option("--yes", "Skip confirmation prompt", false)
    .action(async (name: string, opts: SecretsOpts) => {
      try {
        if (!opts.confirm) {
          const answer = await confirm({
            message: `Delete secret '${name}'? This cannot be undone.`,
            initialValue: false,
          });
          if (!answer) {
            defaultRuntime.log(theme.muted("Cancelled."));
            return;
          }
        }

        await deleteSecret(name);
        defaultRuntime.log(theme.success(`Secret '${name}' deleted.`));
      } catch (err) {
        defaultRuntime.error(danger(String(err)));
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("grant <name>")
    .description("Grant temporary access to a controlled/restricted secret")
    .option("--ttl <minutes>", "Grant duration in minutes")
    .option("--json", "Output JSON", false)
    .action(async (name: string, opts: SecretsOpts) => {
      try {
        const ttlMinutes = opts.ttl ? parseInt(opts.ttl, 10) : undefined;
        const result = await grantSecret(name, ttlMinutes);
        
        if (opts.json) {
          defaultRuntime.log(JSON.stringify(result, null, 2));
          return;
        }

        defaultRuntime.log(theme.success(`Grant created for '${name}'.`));
        defaultRuntime.log(`  ${theme.muted("Expires:")} ${new Date(result.expiresAt).toLocaleString()}`);
        defaultRuntime.log(`  ${theme.muted("Duration:")} ${result.ttlMinutes} minutes`);
      } catch (err) {
        defaultRuntime.error(danger(String(err)));
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("revoke <name>")
    .description("Revoke active grant for a secret")
    .action(async (name: string) => {
      try {
        await revokeSecret(name);
        defaultRuntime.log(theme.success(`Grant revoked for '${name}'.`));
      } catch (err) {
        defaultRuntime.error(danger(String(err)));
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("setup-totp <name>")
    .description("Setup TOTP (Time-based One-Time Password) for a secret")
    .option("--json", "Output JSON", false)
    .action(async (name: string, opts: SecretsOpts) => {
      try {
        const result = await setupTotp(name);
        
        if (opts.json) {
          defaultRuntime.log(JSON.stringify(result, null, 2));
          return;
        }

        defaultRuntime.log(theme.success(`TOTP configured for '${name}'.`));
        defaultRuntime.log();
        defaultRuntime.log("Scan this QR code with your authenticator app:");
        defaultRuntime.log();
        qrcode.generate(result.uri, { small: true });
        defaultRuntime.log();
        defaultRuntime.log(`Or enter this secret manually: ${theme.success(result.secret)}`);
      } catch (err) {
        defaultRuntime.error(danger(String(err)));
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("info")
    .description("Show secrets registry and configuration")
    .option("--json", "Output JSON", false)
    .action(async (opts: SecretsOpts) => {
      try {
        await loadConfig();
        const registry = getRegistry();
        
        if (opts.json) {
          defaultRuntime.log(JSON.stringify(registry, null, 2));
          return;
        }

        defaultRuntime.log(`${theme.success("Secrets Registry:")}`);
        defaultRuntime.log(`  ${theme.muted("Open tier:")}        Always accessible`);
        defaultRuntime.log(`  ${theme.muted("Controlled tier:")}  Requires grant (default TTL varies)`);
        defaultRuntime.log(`  ${theme.muted("Restricted tier:")}  Requires grant (short TTL)`);
        defaultRuntime.log();
        
        const auditLogPath = path.join(STATE_DIR, "audit", "credentials.jsonl");
        defaultRuntime.log(`${theme.success("Audit Logging:")}`);
        defaultRuntime.log(`  ${theme.muted("Log file:")}         ${auditLogPath}`);
        defaultRuntime.log(`  ${theme.muted("Events logged:")}    credential access, grants, denials`);
        
        const secretsCount = registry.secrets.length;
        if (secretsCount > 0) {
          defaultRuntime.log();
          defaultRuntime.log(`${theme.success("Registered Secrets:")} ${secretsCount}`);
        }
      } catch (err) {
        defaultRuntime.error(danger(String(err)));
        defaultRuntime.exit(1);
      }
    });

  // =========================================================================
  // CONFIG AUDITING COMMANDS (upstream implementation)
  // =========================================================================

  addGatewayClientOptions(
    secrets
      .command("reload")
      .description("Re-resolve secret references in config and atomically swap runtime snapshot")
      .option("--json", "Output JSON", false),
  ).action(async (opts: SecretsReloadOptions) => {
    try {
      const result = await callGatewayFromCli("secrets.reload", opts, undefined, {
        expectFinal: false,
      });
      if (opts.json) {
        defaultRuntime.log(JSON.stringify(result, null, 2));
        return;
      }
      const warningCount = Number(
        (result as { warningCount?: unknown } | undefined)?.warningCount ?? 0,
      );
      if (Number.isFinite(warningCount) && warningCount > 0) {
        defaultRuntime.log(`Secrets reloaded with ${warningCount} warning(s).`);
        return;
      }
      defaultRuntime.log("Secrets reloaded.");
    } catch (err) {
      defaultRuntime.error(danger(String(err)));
      defaultRuntime.exit(1);
    }
  });

  secrets
    .command("audit")
    .description("Audit config files for plaintext secrets, unresolved refs, and precedence drift")
    .option("--check", "Exit non-zero when findings are present", false)
    .option("--json", "Output JSON", false)
    .action(async (opts: SecretsAuditOptions) => {
      try {
        const report = await runSecretsAudit();
        if (opts.json) {
          defaultRuntime.log(JSON.stringify(report, null, 2));
        } else {
          defaultRuntime.log(
            `Secrets audit: ${report.status}. plaintext=${report.summary.plaintextCount}, unresolved=${report.summary.unresolvedRefCount}, shadowed=${report.summary.shadowedRefCount}, legacy=${report.summary.legacyResidueCount}.`,
          );
          if (report.findings.length > 0) {
            for (const finding of report.findings.slice(0, 20)) {
              defaultRuntime.log(
                `- [${finding.code}] ${finding.file}:${finding.jsonPath} ${finding.message}`,
              );
            }
            if (report.findings.length > 20) {
              defaultRuntime.log(
                theme.muted(`... and ${report.findings.length - 20} more finding(s).`),
              );
            }
          }
        }
        if (opts.check) {
          const exitCode = resolveSecretsAuditExitCode(report.status);
          if (exitCode !== 0) {
            defaultRuntime.exit(exitCode);
          }
        }
      } catch (err) {
        defaultRuntime.error(danger(String(err)));
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("configure")
    .description("Interactive wizard to migrate plaintext secrets to secret references")
    .option("--apply", "Apply changes immediately (skip plan file)", false)
    .option("--yes", "Skip confirmations", false)
    .option("--plan-out <path>", "Write plan to file instead of applying")
    .option("--providers-only", "Only migrate model provider credentials", false)
    .option("--skip-provider-setup", "Skip provider credential setup", false)
    .option("--json", "Output JSON", false)
    .action(async (opts: SecretsConfigureOptions) => {
      try {
        await runSecretsConfigureInteractive(opts);
      } catch (err) {
        defaultRuntime.error(danger(String(err)));
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("apply")
    .description("Apply a secrets migration plan")
    .requiredOption("--from <path>", "Plan file to apply")
    .option("--dry-run", "Show what would be changed without applying", false)
    .option("--json", "Output JSON", false)
    .action(async (opts: SecretsApplyOptions) => {
      try {
        const plan = readPlanFile(opts.from);
        const result = await runSecretsApply(plan, { dryRun: opts.dryRun });
        if (opts.json) {
          defaultRuntime.log(JSON.stringify(result, null, 2));
        } else {
          if (opts.dryRun) {
            defaultRuntime.log(theme.muted("Dry run - no changes made."));
          } else {
            defaultRuntime.log(theme.success("Secrets migration applied."));
          }
        }
      } catch (err) {
        defaultRuntime.error(danger(String(err)));
        defaultRuntime.exit(1);
      }
    });
}
