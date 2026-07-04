# Installing Ripley Terminal

Ripley Terminal ships as **unsigned** builds — on purpose. Code-signing (an Apple
Developer ID, or a Windows CA certificate) would tie every release to a legal
identity, which defeats the point of a privacy wallet. Instead, authenticity is
proven with **build-provenance attestation** and **reproducible builds** — the same
spirit Monero, Tor, and Tails use. Trust comes from *verification*, not a certificate.

## 1. Verify your download (do this first)

Every binary is **attested** in CI: a keyless cryptographic proof (GitHub OIDC +
the Sigstore public transparency log) that *this exact file* was built by this
repository's public workflow, from a known commit — and not swapped or tampered with
afterward. Verify it with the GitHub CLI ([`gh`](https://cli.github.com)):

```sh
# Proves the file was built by KYC-rip/ripley-terminal's CI (substitute your filename)
gh attestation verify "Ripley Terminal_2.0.0_universal.dmg" --repo KYC-rip/ripley-terminal
```

A passing check prints the workflow and commit that produced the file. Install
**only if it passes**. If it fails, the download is corrupt or tampered with — do
not run it.

You can also cross-check integrity against the published checksums:

```sh
sha256sum  --ignore-missing -c SHA256SUMS    # Linux
shasum -a 256 --ignore-missing -c SHA256SUMS # macOS
```

> Trust here is rooted in GitHub + Sigstore (that their signing/transparency
> infrastructure and this repo's account are not compromised), backed by reproducible
> builds that let anyone rebuild and compare. An author-held **GPG signature may be
> added in a future release** as an additional, independent layer — it is not required
> to verify a build today.

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
resulting hashes against `SHA256SUMS`. That independent reproducibility, combined with
the build-provenance attestation, is the real guarantee of what you're running — no
vendor signature required.
