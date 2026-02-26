import type { Command } from "commander";
import qrcode from "qrcode-terminal";
import path from "node:path";
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
import { loadConfig } from "../config/config.js";
import { STATE_DIR } from "../config/paths.js";
import { getRegistry } from "../secrets/registry.js";
import { renderTable } from "../terminal/table.js";
import { theme } from "../terminal/theme.js";
import { defaultRuntime } from "../runtime.js";

type SecretsOpts = {
  tier?: string;
  description?: string;
  value?: string;
  ttl?: string;
  confirm?: boolean;
  json?: boolean;
};

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

export function registerSecretsCli(program: Command) {
  const secrets = program.command("secrets").description("Manage secrets with tiered access control");

  secrets
    .command("list")
    .description("List all registered secrets")
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
                  ? theme.success("✓ valid")
                  : theme.error("✗ needs grant"),
              Expires: s.tier === "open" 
                ? theme.muted("—")
                : formatGrantStatus(s.grant.valid, s.grant.expiresAt, s.grant.remainingMinutes),
            })),
          }).trimEnd(),
        );
      } catch (err) {
        defaultRuntime.error(`Failed to list secrets: ${(err as Error).message}`);
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("get")
    .description("Retrieve a secret value")
    .argument("<name>", "Secret name")
    .option("--json", "Output JSON", false)
    .action(async (name: string, opts: SecretsOpts) => {
      try {
        const value = await getSecret(name);
        if (!value) {
          defaultRuntime.error(`Secret '${name}' not found or access denied`);
          return defaultRuntime.exit(2);
        }
        defaultRuntime.log(opts.json ? JSON.stringify({ name, value }, null, 2) : value);
      } catch (err) {
        defaultRuntime.error(`Failed to get secret: ${(err as Error).message}`);
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("set")
    .description("Store a secret")
    .argument("<name>", "Secret name")
    .option("--tier <tier>", "Access tier (open|controlled|restricted)", "controlled")
    .option("--description <desc>", "Secret description")
    .option("--value <value>", "Secret value (or read from stdin)")
    .action(async (name: string, opts: SecretsOpts) => {
      try {
        const tier = parseTier(opts.tier);
        let value = opts.value || (!process.stdin.isTTY ? await readStdin() : "");
        
        if (!value) {
          defaultRuntime.error("No value provided. Use --value or pipe to stdin.");
          return defaultRuntime.exit(1);
        }

        await setSecret(name, value, tier, opts.description);
        defaultRuntime.log(`${theme.success("✓")} Secret '${theme.command(name)}' stored (tier: ${tier})`);
      } catch (err) {
        defaultRuntime.error(`Failed to set secret: ${(err as Error).message}`);
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("grant")
    .description("Create a time-limited grant (requires TOTP)")
    .argument("<name>", "Secret name")
    .argument("<code>", "6-digit TOTP code")
    .option("--ttl <minutes>", "Grant duration in minutes")
    .option("--json", "Output JSON", false)
    .action(async (name: string, code: string, opts: SecretsOpts) => {
      try {
        const ttlMinutes = opts.ttl ? parseInt(opts.ttl, 10) : undefined;
        if (ttlMinutes !== undefined && (isNaN(ttlMinutes) || ttlMinutes <= 0)) {
          defaultRuntime.error("TTL must be a positive number");
          return defaultRuntime.exit(1);
        }

        const result = await grantSecret(name, code, ttlMinutes);
        const output = opts.json
          ? JSON.stringify({ name, expiresAt: result.expiresAt }, null, 2)
          : `${theme.success("✓")} Grant created for '${theme.command(name)}' until ${new Date(result.expiresAt).toLocaleString()}`;
        defaultRuntime.log(output);
      } catch (err) {
        defaultRuntime.error(`Failed to grant access: ${(err as Error).message}`);
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("revoke")
    .description("Revoke a grant")
    .argument("<name>", "Secret name")
    .action(async (name: string) => {
      try {
        await revokeSecret(name);
        defaultRuntime.log(`${theme.success("✓")} Grant revoked for '${theme.command(name)}'`);
      } catch (err) {
        defaultRuntime.error(`Failed to revoke grant: ${(err as Error).message}`);
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("delete")
    .description("Delete a secret permanently")
    .argument("<name>", "Secret name")
    .requiredOption("--confirm", "Confirm deletion")
    .action(async (name: string, opts: SecretsOpts) => {
      if (!opts.confirm) {
        defaultRuntime.error("Deletion requires --confirm flag");
        defaultRuntime.exit(1);
        return;
      }

      try {
        await deleteSecret(name);
        defaultRuntime.log(`${theme.success("✓")} Secret '${theme.command(name)}' deleted`);
      } catch (err) {
        defaultRuntime.error(`Failed to delete secret: ${(err as Error).message}`);
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("setup-totp")
    .description("Generate TOTP secret for grant validation")
    .option("--json", "Output JSON", false)
    .action(async (opts: SecretsOpts) => {
      try {
        const result = await setupTotp();
        
        if (opts.json) {
          defaultRuntime.log(JSON.stringify(result, null, 2));
        } else {
          defaultRuntime.log(theme.heading("TOTP Setup"));
          defaultRuntime.log("");
          
          // Show QR code in terminal
          const qrOutput = await new Promise<string>((resolve) => {
            qrcode.generate(result.uri, { small: true }, (output: string) => {
              resolve(output);
            });
          });
          defaultRuntime.log(qrOutput);
          
          defaultRuntime.log(`${theme.success("Secret:")} ${result.secret}`);
          defaultRuntime.log(`${theme.success("URI:")}    ${result.uri}`);
          defaultRuntime.log("");
          defaultRuntime.log(theme.muted("Scan the QR code above, or enter the secret manually in your authenticator app."));
        }
      } catch (err) {
        defaultRuntime.error(`Failed to setup TOTP: ${(err as Error).message}`);
        defaultRuntime.exit(1);
      }
    });

  secrets
    .command("info")
    .description("Show credential broker configuration and status")
    .option("--json", "Output JSON", false)
    .action(async (opts: SecretsOpts) => {
      try {
        const cfg = loadConfig();
        const registry = getRegistry();
        const auditLogPath = path.join(STATE_DIR, "audit", "credentials.jsonl");
        
        const mode = cfg.security?.credentials?.mode ?? "legacy";
        const brokerEnabled = cfg.security?.credentials?.broker?.enabled ?? false;
        const backendType = (cfg.secrets as any)?.backend ?? "keychain";
        const interceptTools = cfg.security?.credentials?.broker?.interceptTools ?? [];
        
        if (opts.json) {
          defaultRuntime.log(JSON.stringify({
            securityMode: mode,
            backendType,
            broker: {
              enabled: brokerEnabled,
              interceptTools: interceptTools.length > 0 ? interceptTools : "all",
            },
            secretsCount: registry.length,
            auditLog: auditLogPath,
          }, null, 2));
          return;
        }

        defaultRuntime.log(theme.heading("Credential Broker Status"));
        defaultRuntime.log("");
        defaultRuntime.log(`${theme.success("Security Mode:")}    ${mode}`);
        defaultRuntime.log(`${theme.success("Backend:")}          ${backendType}`);
        defaultRuntime.log(`${theme.success("Broker:")}           ${brokerEnabled ? theme.success("enabled") : theme.muted("disabled")}`);
        
        if (brokerEnabled) {
          if (interceptTools.length === 0) {
            defaultRuntime.log(`${theme.success("Intercept Tools:")}  ${theme.warn("all tools")}`);
          } else {
            defaultRuntime.log(`${theme.success("Intercept Tools:")}  ${interceptTools.join(", ")}`);
          }
        }
        
        defaultRuntime.log(`${theme.success("Secrets Count:")}    ${registry.length}`);
        defaultRuntime.log(`${theme.success("Audit Log:")}        ${theme.muted(auditLogPath)}`);
      } catch (err) {
        defaultRuntime.error(`Failed to get info: ${(err as Error).message}`);
        defaultRuntime.exit(1);
      }
    });
}
