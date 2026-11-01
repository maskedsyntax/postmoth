# Native messaging host manifests

`dev.postmoth.native_host.json.in` is filled in at install time:

* `@HOST_PATH@`: absolute path of `postmoth-native-host`
  (`/usr/bin/postmoth-native-host` for packages).
* `@ALLOWED_ORIGINS@`: the exact `chrome-extension://<id>/` origins of
  the published extension. Never a wildcard (spec §8.5).

The host also checks `argv[1]` against IDs compiled into the binary
(`RELEASE_EXTENSION_IDS`, plus `DEV_EXTENSION_ID` in debug builds or with
the `dev-extension` feature), so a manifest edited to allow another
extension still gets nothing.

## Locations

Per-user installs (what `scripts/dev-native-host.sh` writes):

| Browser  | Directory |
|----------|-----------|
| Chrome   | `~/.config/google-chrome/NativeMessagingHosts/` |
| Chromium | `~/.config/chromium/NativeMessagingHosts/` |
| Brave    | `~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/` |

System-wide installs (packages):

| Browser  | Directory |
|----------|-----------|
| Chrome   | `/etc/opt/chrome/native-messaging-hosts/` |
| Chromium | `/etc/chromium/native-messaging-hosts/` |
| Brave    | `/etc/opt/chrome/native-messaging-hosts/` is read by Brave too; verify per release |

Each browser must be tested independently (spec §8.5); the Brave
system path in particular needs confirmation on a real install.

## Development extension ID

The unpacked extension in `extensions/chromium` pins its ID with the
public key in `dev-extension-key.b64` (the manifest `key` field), giving
`nnbgdhodaoggiiakpcmnlkgalgkoecbk`. The matching private key is not
needed for unpacked loading and is not kept anywhere.
