# Keychain Add

A Raycast command that saves a secret to your macOS login keychain or to your Agents keychain. It does the job of this command:

```sh
security add-generic-password -s my-service -a username -w
```

That command has two traps. At the `-w` prompt, `security` silently cuts the secret at 128 characters. Leave out `-w` and it saves an empty password. This extension sends the secret hex-encoded on the stdin of `/usr/bin/security -i`, so it never appears in a process list. It then reads the item back and reports an error if the stored secret does not match.

## Install

1. Run `npm install`.
2. Run `npm run dev` once to import the extension into Raycast.

## Use

Open **Add Keychain Password**, pick a keychain, fill in the service, account, and secret, and press ⌘↵. If the item already exists in that keychain, the command asks before it replaces it. If the clipboard holds the same secret, the command clears the clipboard.

The Keychain picker offers two keychains:

- **Login** is `~/Library/Keychains/login.keychain-db`.
- **Agents** is `~/Library/Keychains/agents.keychain-db`. It locks itself, so macOS may ask for its password when you save to it while it is locked.

The picker starts on the keychain you last saved to. The account field starts with the last account you saved.

The extension refuses a keychain file that does not exist. Given a missing path, `security` would save the item to the login keychain without saying so.

## Secret length limit

`security -i` reads each command into a fixed-size buffer. A command longer than 4,095 bytes is split, and the first part still runs, which saves a cut-off secret. At exactly 4,095 bytes, `security` reports success for a command that failed, so the extension refuses any command over 4,094 bytes. Each secret byte takes two hex characters, so the longest secret is about 2,000 ASCII characters, a little less with long service, account, or keychain names.

## Read items from scripts

`/usr/bin/security` creates each new item, so the item's access list trusts it. Once the keychain is unlocked, scripts can read that secret without an access prompt. Replacing an item that another app created keeps that app's access list, so reading it may prompt. Pass the keychain path to read from one keychain:

```sh
security find-generic-password -s my-service -a username -w ~/Library/Keychains/agents.keychain-db
```

`-w` prints a secret that contains non-ASCII characters or newlines as hex. Decode such a secret with `xxd`:

```sh
security find-generic-password -s my-service -a username -w | xxd -r -p
```

## Tests

`npm test` saves items to a throwaway keychain in a temporary directory and checks that a missing keychain file is refused. When the run ends, it deletes that keychain. If any test item reached the login keychain, it deletes that item and fails the run.
