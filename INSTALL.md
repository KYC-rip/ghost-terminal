# Installing Ripley Terminal

Ripley Terminal ships as **unsigned** builds — on purpose. Code-signing (an Apple
Developer ID, or a Windows CA certificate) would tie every release to a legal
identity, which defeats the point of a privacy wallet. Instead, authenticity is
proven with **GPG-signed checksums** and **reproducible builds** — the same trust
model Monero, Tor, and Tails use. Trust comes from *verification*, not a certificate.

## 1. Verify your download (do this first)

Every release includes `SHA256SUMS` and a detached signature `SHA256SUMS.asc`.

```sh
# Import the maintainer's signing key (replace with the published fingerprint)
gpg --recv-keys <MAINTAINER_GPG_FINGERPRINT>

# Confirm the checksums file itself is authentic (signed by that key)
gpg --verify SHA256SUMS.asc SHA256SUMS

# Confirm your downloaded file matches the (now-trusted) checksums
sha256sum --ignore-missing -c SHA256SUMS
```

Install **only if both** the GPG verify and the hash check pass. If either fails,
the download is corrupt or tampered with — do not run it.

> The maintainer signs `SHA256SUMS` offline with a pseudonymous key; the private key
> never touches CI. Publish the key fingerprint somewhere cross-referenceable
> (project site, repo, socials) so users can pin it.

## 2. Install + first launch

### Linux — `.AppImage` (recommended) or `.deb`
```sh
chmod +x "Ripley Terminal_*.AppImage"
./"Ripley Terminal_"*.AppImage
```
Some distros need FUSE: `sudo apt install libfuse2`. (`.deb`: `sudo apt install ./ripley-terminal_*.deb`.)
On **Qubes/Whonix**, run it inside the workstation qube and set routing to your
gateway's SOCKS proxy in Settings (e.g. `10.152.152.10:9050`) — no bundled Tor is
started in that mode.

### macOS — `.dmg`
Because the app is unsigned, macOS will say it "can't be opened" / "is from an
unidentified developer." To open it the first time:

- **Right-click** the app → **Open** → **Open** again, **or**
- Clear the quarantine flag:
  ```sh
  xattr -dr com.apple.quarantine "/Applications/Ripley Terminal.app"
  ```

### Windows — `.exe` / `.msi`
SmartScreen will warn ("Windows protected your PC"). Click **More info → Run anyway**.

## Reproducible builds

Releases are built in CI from pinned dependencies (`.github/workflows/tauri-build.yml`)
on the open-source tree. You — or anyone — can rebuild from source and compare the
resulting hashes against `SHA256SUMS`. That independent reproducibility, not a vendor
signature, is the real guarantee of what you're running.
