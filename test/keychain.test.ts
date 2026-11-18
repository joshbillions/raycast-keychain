import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, relative } from "node:path";
import { after, before, test } from "node:test";
import { encodeAdd, itemExists, MAX_LINE_BYTES, saveItem, type KeychainItem } from "../src/keychain.ts";

const dir = mkdtempSync(join(tmpdir(), "keychain-add-test-"));
const keychain = join(dir, "t.keychain-db");
const keychainPassword = randomUUID();
const loginKeychain = join(homedir(), "Library/Keychains/login.keychain-db");
const services = new Set<string>();

function security(...args: string[]) {
  return spawnSync("/usr/bin/security", args, { encoding: "utf8" });
}

function testService(name: string): string {
  const full = `keychain-add-test-${name}`;
  services.add(full);
  return full;
}

function assertStored({ service, account, secret }: KeychainItem) {
  const found = security("find-generic-password", "-s", service, "-a", account, "-w", keychain);
  assert.equal(found.status, 0, `${service} / ${account} is readable from the throwaway keychain`);
  const printed = found.stdout.replace(/\n$/, "");
  const hex = Buffer.from(secret, "utf8").toString("hex");
  assert.ok(printed === secret || printed === hex, `${service} / ${account} reads back the exact secret`);
}

function inLoginKeychain(service: string): boolean {
  const found = security("find-generic-password", "-s", service, loginKeychain);
  assert.ok(found.status === 0 || found.status === 44, `${service} lookup in the login keychain ran`);
  return found.status === 0;
}

before(() => {
  assert.equal(security("create-keychain", "-p", keychainPassword, keychain).status, 0, "throwaway keychain created");
  assert.equal(security("unlock-keychain", "-p", keychainPassword, keychain).status, 0, "throwaway keychain unlocked");
  assert.ok(existsSync(keychain), "throwaway keychain file exists");
});

after(() => {
  const deleted = security("delete-keychain", keychain);
  rmSync(dir, { recursive: true, force: true });
  const leaked: string[] = [];
  for (const name of services) {
    while (inLoginKeychain(name)) {
      leaked.push(name);
      const removed = security("delete-generic-password", "-s", name, loginKeychain);
      assert.equal(removed.status, 0, `${name} removed from the login keychain`);
    }
  }
  assert.deepEqual(leaked, [], "no test item reached the login keychain");
  assert.equal(deleted.status, 0, "throwaway keychain deleted");
});

test("an ASCII secret reads back unchanged", async () => {
  const item = {
    service: testService("ascii"),
    account: "username",
    secret: "correct-horse-battery-staple-0123456789",
  };
  assert.deepEqual(await saveItem(item, keychain), { verified: true }, "save is verified by readback");
  assertStored(item);
});

test("a secret with quotes, backslashes, unicode, and whitespace reads back unchanged", async () => {
  const item = {
    service: testService("tricky-secret"),
    account: "username",
    secret: `a b"c'd\\e ünï 🔑\nline two\tend`,
  };
  assert.deepEqual(await saveItem(item, keychain), { verified: true }, "save is verified by readback");
  assertStored(item);
});

test("service and account may contain spaces, quotes, and backslashes", async () => {
  const item = {
    service: testService(`spaced "quoted" back\\slash`),
    account: `user "x" \\ y ü`,
    secret: "hunter2-not-real",
  };
  assert.deepEqual(await saveItem(item, keychain), { verified: true }, "save is verified by readback");
  assertStored(item);
  assert.equal(await itemExists(item.service, item.account, keychain), true, "item is found by its exact names");
});

test("saving the same service and account again replaces the secret", async () => {
  const first = { service: testService("replace"), account: "username", secret: "first-value" };
  const second = { ...first, secret: "second-value" };
  assert.deepEqual(await saveItem(first, keychain), { verified: true }, "first save is verified by readback");
  assert.deepEqual(await saveItem(second, keychain), { verified: true }, "replacing save is verified by readback");
  assertStored(second);
});

test("itemExists reports whether a service and account are stored", async () => {
  const item = { service: testService("exists"), account: "username", secret: "exists-value" };
  assert.equal(await itemExists(item.service, item.account, keychain), false, "absent before saving");
  assert.deepEqual(await saveItem(item, keychain), { verified: true }, "save is verified by readback");
  assert.equal(await itemExists(item.service, item.account, keychain), true, "present after saving");
  assert.equal(await itemExists(item.service, "other-account", keychain), false, "another account is still absent");
});

test("a command of exactly MAX_LINE_BYTES saves intact and one byte more is refused without writing", async () => {
  const name = testService("boundary");
  const lineBytes = (account: string, secret: string) => {
    const encoded = encodeAdd({ service: name, account, secret }, keychain);
    assert.ok(encoded.ok, "short command encodes");
    return Buffer.byteLength(encoded.line, "utf8");
  };
  const roomForSecretHex = (account: string) => MAX_LINE_BYTES - lineBytes(account, "");
  const account = roomForSecretHex("bøundary") % 2 === 0 ? "bøundary" : "bøundary!";
  const atLimit = { service: name, account, secret: "s".repeat(roomForSecretHex(account) / 2) };

  const encoded = encodeAdd(atLimit, keychain);
  assert.ok(encoded.ok, "command at the limit encodes");
  assert.equal(Buffer.byteLength(encoded.line, "utf8"), MAX_LINE_BYTES, "command is exactly at the limit");
  assert.deepEqual(await saveItem(atLimit, keychain), { verified: true }, "save at the limit is verified by readback");
  assertStored(atLimit);

  const overLimit = { ...atLimit, account: `${account}x` };
  assert.deepEqual(encodeAdd(overLimit, keychain), { ok: false, overBy: 1 }, "one byte over is refused by the encoder");
  await assert.rejects(saveItem(overLimit, keychain), /1 byte too long/, "saveItem refuses the oversized command");
  assert.equal(await itemExists(overLimit.service, overLimit.account, keychain), false, "nothing was written");
});

test("a failing command of exactly MAX_LINE_BYTES still exits nonzero from security -i", () => {
  const head = 'find-generic-password -s "keychain-add-test-absent-';
  const tail = `" "${keychain}"`;
  const line = head + "x".repeat(MAX_LINE_BYTES - Buffer.byteLength(head + tail, "utf8")) + tail;
  assert.equal(Buffer.byteLength(line, "utf8"), MAX_LINE_BYTES, "lookup command is exactly at the limit");
  const lookup = spawnSync("/usr/bin/security", ["-i"], { input: `${line}\n`, encoding: "utf8" });
  assert.notEqual(lookup.status, 0, "lookup of a missing item reports failure");
});

test("an empty secret is refused without writing", async () => {
  const item = { service: testService("empty-secret"), account: "username", secret: "" };
  await assert.rejects(saveItem(item, keychain), /empty/, "saveItem refuses an empty secret");
  assert.equal(await itemExists(item.service, item.account, keychain), false, "nothing was written");
});

test("control characters in the account are refused without writing", async () => {
  const item = { service: testService("control-char"), account: "pass\tword", secret: "control-value" };
  await assert.rejects(saveItem(item, keychain), /control characters/, "saveItem refuses a control character");
  assert.equal(await itemExists(item.service, item.account, keychain), false, "nothing was written");
});

test("a keychain file that does not exist is refused without writing", async () => {
  const missing = join(dir, "missing.keychain-db");
  const item = { service: testService("missing-keychain"), account: "username", secret: "missing-value" };
  assert.ok(!existsSync(missing), "keychain path does not exist");
  await assert.rejects(saveItem(item, missing), /not found/, "saveItem refuses a missing keychain");
  await assert.rejects(itemExists(item.service, item.account, missing), /not found/, "itemExists refuses it too");
  const relativeToCwd = relative(process.cwd(), keychain);
  assert.ok(existsSync(relativeToCwd), "relative path names the throwaway keychain from the working directory");
  await assert.rejects(saveItem(item, relativeToCwd), /Keychain not found/, "saveItem refuses a relative keychain path");
  assert.equal(inLoginKeychain(item.service), false, "nothing was written to the login keychain");
  assert.equal(
    await itemExists(item.service, item.account, keychain),
    false,
    "nothing was written to the throwaway keychain",
  );
});
