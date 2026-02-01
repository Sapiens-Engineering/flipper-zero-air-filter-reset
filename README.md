# Xiaomi Filter Reset

A Flipper Zero application to reset Xiaomi air purifier filter counters by writing zeros to the NFC tag's Block 8.

Xiaomi air purifiers use NTAG NFC tags embedded in their filters to track usage. When the filter counter reaches a threshold, the purifier prompts for replacement—even if the filter still has life left. This app bypasses that limitation by resetting the counter to zero.

## Features

- Scans NTAG tags on Xiaomi air purifier filters
- Derives the authentication password from the tag's UID
- Reads current filter status (Block 8) before writing
- Writes zeros to reset the filter counter
- Verifies the write operation
- Displays before/after data for potential manual revert

## How It Works

### Password Generation Algorithm

Xiaomi protects their filter NFC tags with a 4-byte password derived from the tag's 7-byte UID using SHA-1:

1. Compute SHA-1 hash of the 7-byte UID
2. Use the first byte of the hash as an index seed
3. Extract 4 password bytes at computed indices:
   - `hash[seed % 20]`
   - `hash[(seed + 5) % 20]`
   - `hash[(seed + 13) % 20]`
   - `hash[(seed + 17) % 20]`

#### Example

```
UID:        04:A0:3C:AA:1E:70:80
SHA-1:      bcaf806333ccf720cd441a167f914fbe6ea4a513
Seed:       0xBC = 188 (first byte of hash)

Indices:
  188 % 20      = 8   → hash[8]  = 0xCD
  (188 + 5) % 20  = 13  → hash[13] = 0x91
  (188 + 13) % 20 = 1   → hash[1]  = 0xAF
  (188 + 17) % 20 = 5   → hash[5]  = 0xCC

Password:   CD:91:AF:CC
```

### NFC Communication Protocol

The app communicates with the filter's NTAG tag using ISO14443-3A protocol:

| Step | Command | Bytes | Description |
|------|---------|-------|-------------|
| 1. Scan | - | - | Read 7-byte UID from tag |
| 2. Auth | `PWD_AUTH` | `1B XX XX XX XX` | Authenticate with derived password |
| 3. Read | `READ` | `30 08` | Read Block 8 (returns 16 bytes) |
| 4. Write | `WRITE` | `A2 08 00 00 00 00` | Write 4 zero bytes to Block 8 |
| 5. Verify | `READ` | `30 08` | Read Block 8 again to confirm |

**Note**: The NTAG WRITE command returns a 4-bit ACK rather than a standard frame, which may cause a timeout. The app handles this by verifying the write with a subsequent read.

## Building

### Prerequisites

1. Install [rustup](https://rustup.rs/):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Install the nightly toolchain:
   ```bash
   rustup toolchain install nightly
   ```

3. Add the ARM target:
   ```bash
   rustup target add --toolchain nightly thumbv7em-none-eabihf
   ```

4. Install Flipper Zero tools:
   ```bash
   cargo install --locked flipperzero-tools
   ```

### Build

```bash
cargo build --release
```

The resulting `.fap` binary will be at:
```
target/thumbv7em-none-eabihf/release/flipper-xiaomi-filter-reset.fap
```

### Deploy to Flipper Zero

Copy the app to your Flipper:

```bash
storage send target/thumbv7em-none-eabihf/release/flipper-xiaomi-filter-reset.fap /ext/apps/xiaomi.fap
```

### Debugging

To view debug output from the app:

1. Copy the app to your Flipper (see above)

2. Connect to the Flipper CLI and enable logging:
   ```bash
   serial_cli
   ```
   Then in the CLI:
   ```
   log
   ```

3. Start the app on your Flipper and interact with it—debug messages will appear in the CLI

## Usage

1. **Start the app** on your Flipper Zero
2. **Press "Yes"** to begin scanning
3. **Place the Flipper** on the filter's NFC tag (location varies by model—check top or bottom of filter)
4. **Review the tag info**: UID and derived password are displayed
5. **Press "Write"** to reset the filter counter
6. **Check the result**: The app shows Block 8 data before and after the write

The "Before" data can be used to manually revert the filter if needed.

## Acknowledgements

This project would not be possible without the research and reverse engineering work by:

- **unethical.info** — Original research and password algorithm discovery  
  https://unethical.info/2024/01/24/hacking-my-air-purifier/

- **Hackaday** — Coverage and additional details  
  https://hackaday.com/2024/01/26/hacking-a-xiaomi-air-purifiers-filter-drm-to-extend-its-lifespan/

- **Milan Gajic** — Online password calculator tool  
  https://milan.gajic.eu/tinkering/tools/xiaomi-filter-reset

Thank you for sharing your findings with the community!

## Support

If this project helped you extend the life of your air purifier filter, consider supporting its development. Every contribution is greatly appreciated and helps keep the project maintained.

**Bitcoin**

```
bc1qpvu2sywgh5cgcn3raq6vswtxhkpljlrx906pgd
```

![Bitcoin QR Code](assets/btc-qr.png)


Thank you for your support!

## License

This project is licensed under the [MIT License](LICENSE).
