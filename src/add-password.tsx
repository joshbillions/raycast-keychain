import {
  Action,
  ActionPanel,
  Alert,
  Clipboard,
  confirmAlert,
  Form,
  Icon,
  showHUD,
  showToast,
  Toast,
} from "@raycast/api";
import { showFailureToast, useCachedState, useForm } from "@raycast/utils";
import { homedir } from "node:os";
import { join } from "node:path";
import { encodeAdd, itemExists, saveItem, tooLongMessage, type KeychainItem, type SaveResult } from "./keychain";

const KEYCHAINS = {
  login: { title: "Login", path: join(homedir(), "Library/Keychains/login.keychain-db") },
  agents: { title: "Agents", path: join(homedir(), "Library/Keychains/agents.keychain-db") },
} as const;
type KeychainId = keyof typeof KEYCHAINS;

const isKeychainId = (id: string): id is KeychainId => Object.hasOwn(KEYCHAINS, id);

const nameError = (label: string) => (value: string | undefined) => {
  if (!value?.trim()) return `${label} is required`;
  if (/\p{Cc}/u.test(value)) return `${label} cannot contain control characters`;
};

export default function Command() {
  const [lastAccount, setLastAccount] = useCachedState("last-account", "");
  const [lastKeychain, setLastKeychain] = useCachedState<string>("last-keychain", "login");
  const { handleSubmit, itemProps, reset, setValidationError } = useForm<KeychainItem & { keychain: KeychainId }>({
    initialValues: { keychain: isKeychainId(lastKeychain) ? lastKeychain : "login", account: lastAccount },
    validation: {
      service: nameError("Service"),
      account: nameError("Account"),
      secret: (value) => (value ? undefined : "Secret is required"),
    },
    async onSubmit({ keychain, ...values }) {
      const item = { ...values, service: values.service.trim(), account: values.account.trim() };
      const { title, path } = KEYCHAINS[keychain];
      const encoded = encodeAdd(item, path);
      if (!encoded.ok) {
        setValidationError("secret", tooLongMessage(encoded.overBy));
        return false;
      }

      const label = `${item.service} / ${item.account}`;
      let toast: Toast;
      let result: SaveResult;
      try {
        if (await itemExists(item.service, item.account, path)) {
          const replace = await confirmAlert({
            title: "Replace Keychain Item?",
            message: `${label} already exists in the ${title} keychain.`,
            primaryAction: { title: "Replace", style: Alert.ActionStyle.Destructive },
          });
          if (!replace) return false;
        }

        toast = await showToast({ style: Toast.Style.Animated, title: "Saving to keychain" });
        result = await saveItem(item, path);
      } catch (error) {
        await showFailureToast(error, { title: "Couldn't save to keychain" });
        return false;
      }

      setLastAccount(item.account);
      setLastKeychain(keychain);
      const clipboardCleared = (await Clipboard.readText())?.trim() === item.secret.trim();
      if (clipboardCleared) await Clipboard.clear();
      reset({ keychain, service: "", account: item.account, secret: "" });
      await toast.hide();
      const outcome = result.verified ? `${[...item.secret].length} chars verified` : `not verified: ${result.reason}`;
      await showHUD(`Saved ${label} to ${title} · ${outcome}${clipboardCleared ? " · clipboard cleared" : ""}`);
    },
  });

  return (
    <Form
      actions={
        <ActionPanel>
          <Action.SubmitForm title="Save to Keychain" icon={Icon.Key} onSubmit={handleSubmit} />
        </ActionPanel>
      }
    >
      <Form.Dropdown
        id={itemProps.keychain.id}
        title="Keychain"
        value={itemProps.keychain.value}
        onChange={(id) => {
          if (isKeychainId(id)) itemProps.keychain.onChange?.(id);
        }}
      >
        {Object.entries(KEYCHAINS).map(([id, { title }]) => (
          <Form.Dropdown.Item key={id} value={id} title={title} />
        ))}
      </Form.Dropdown>
      <Form.Description text="Replaces an existing item only after you confirm." />
      <Form.TextField title="Service" placeholder="my-service" autoFocus {...itemProps.service} />
      <Form.TextField title="Account" placeholder="username" {...itemProps.account} />
      <Form.PasswordField title="Secret" {...itemProps.secret} />
    </Form>
  );
}
