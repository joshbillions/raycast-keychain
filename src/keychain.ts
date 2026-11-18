import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { isAbsolute } from "node:path";

export type KeychainItem = { service: string; account: string; secret: string };

// `security -i` reads each command into a 4096-byte buffer. A line of 4096 bytes or more is split and its first chunk
// still runs, saving a truncated item, and to the login keychain once the keychain path is cut off. A line of exactly
// 4095 bytes leaves its newline behind as an empty command, which resets the exit status, so a failed add reports success.
export const MAX_LINE_BYTES = 4094;

export type EncodedAdd = { ok: true; line: string } | { ok: false; overBy: number };

export type SaveResult = { verified: true } | { verified: false; reason: string };

type Run = { code: number | null; stdout: string; stderr: string };

const SECURITY = "/usr/bin/security";
const NOT_FOUND = 44;
const HEX_DIGITS_PER_BYTE = 2;

const hex = (text: string) => Buffer.from(text, "utf8").toString("hex");
const quote = (text: string) => `"${text.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;

export function encodeAdd({ service, account, secret }: KeychainItem, keychain: string): EncodedAdd {
  const args = ["add-generic-password", "-U", "-s", quote(service), "-a", quote(account), "-X", hex(secret)];
  const line = [...args, quote(keychain)].join(" ");
  const overBy = Buffer.byteLength(line, "utf8") - MAX_LINE_BYTES;
  return overBy > 0 ? { ok: false, overBy } : { ok: true, line };
}

export function tooLongMessage(overBy: number): string {
  const secretBytesOver = Math.ceil(overBy / HEX_DIGITS_PER_BYTE);
  return `Secret is ${secretBytesOver} ${secretBytesOver === 1 ? "byte" : "bytes"} too long for the keychain CLI`;
}

export async function itemExists(service: string, account: string, keychain: string): Promise<boolean> {
  assertKeychainExists(keychain);
  const found = await security(["find-generic-password", "-s", service, "-a", account, keychain]);
  if (found.code === NOT_FOUND) return false;
  if (found.code !== 0) throw new Error(reason(found));
  return true;
}

export async function saveItem(item: KeychainItem, keychain: string): Promise<SaveResult> {
  assertKeychainExists(keychain);
  if (item.secret === "") throw new Error("Secret is empty");
  const encoded = encodeAdd(item, keychain);
  if (!encoded.ok) throw new Error(tooLongMessage(encoded.overBy));
  // A control character ends or truncates the command the same way an oversized line does.
  if (/\p{Cc}/u.test(encoded.line)) throw new Error("Service, account, and keychain cannot contain control characters");

  const added = await security(["-i"], `${encoded.line}\n`);
  if (added.code !== 0) throw new Error(reason(added));

  const read = await security(["find-generic-password", "-s", item.service, "-a", item.account, "-w", keychain]);
  // The add succeeded, so the secret is saved even when the readback cannot run, such as after a denied access prompt.
  if (read.code !== 0) return { verified: false, reason: reason(read) };
  const stored = read.stdout.replace(/\n$/, "");
  if (stored !== item.secret && stored !== hex(item.secret)) {
    throw new Error("Keychain readback did not match what was written");
  }
  return { verified: true };
}

// `security` writes to the login keychain when the keychain path it is given does not exist. A relative path can name
// a different file for `security` than for this process, so only an absolute path is checked.
function assertKeychainExists(keychain: string): void {
  if (!isAbsolute(keychain) || !existsSync(keychain)) throw new Error(`Keychain not found: ${keychain}`);
}

function reason({ code, stderr }: Run): string {
  const messages = stderr
    .split("\n")
    .filter((line) => line.startsWith("security: "))
    .map((line) => line.slice("security: ".length));
  return messages.join(" ") || stderr.trim().split("\n").at(-1) || `security exited with code ${code}`;
}

function security(args: string[], input = ""): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn(SECURITY, args);
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.on("error", reject);
    child.stdin.end(input);
  });
}
