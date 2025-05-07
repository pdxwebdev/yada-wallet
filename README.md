# Yada ESP32 Hardware Wallet (Rotating Keys)

A minimalist Bitcoin hardware wallet on an ESP32 with a TFT touchscreen, featuring a rotating key scheme for enhanced security with a companion hot wallet.

The device generates QR codes containing the current Bitcoin address, its WIF private key, the next address, and a hash commitment for sequence verification. This allows a hot wallet to manage funds for one address at a time without needing the root mnemonic or PIN.

## Core Features

*   BIP39 Mnemonic generation and secure storage (NVS).
*   6-digit PIN protection for wallet access.
*   Hierarchical Deterministic (HD) key derivation (BIP32).
*   **Key Rotation QR Data:** `addr_n | WIF_n | addr_n+1 | H(H(pk_n+2))`
*   TFT Touchscreen UI for PIN entry, mnemonic display, and key rotation.
*   Designed for offline, air-gapped operation.

## Hardware

*   ESP32 Development Board
*   TFT LCD Display with XPT2046 Touchscreen (ILI9341 or similar, configured for TFT_eSPI)
    *   Default pins defined in the `.ino` and TFT_eSPI's `User_Setup.h`.

## Software Dependencies (Arduino Libraries)

*   **TFT_eSPI** (by Bodmer) - Configure `User_Setup.h` for your display.
*   **XPT2046_Touchscreen** (by Paul Stoffregen)
*   **uBitcoin** (by Stepan Snigirev)
*   **QRCodeGenerator** (by Tom Magnier or compatible)
*   `bip39_wordlist.h` (required in sketch directory)

## Setup (Arduino IDE)

1.  Install ESP32 Core.
2.  Install the libraries listed above via Arduino Library Manager.
3.  **Crucially, configure `User_Setup.h` in your TFT_eSPI library folder** to match your specific display and ESP32 pin connections.
4.  Place `bip39_wordlist.h` (containing the BIP39 English wordlist array) in your sketch directory.
5.  Select your ESP32 board, COM port, and upload.

## Usage Flow

1.  **First Boot:** Set PIN, new mnemonic generated. **Backup this mnemonic securely!** Confirm backup.
2.  **Subsequent Boots:** Enter PIN using "Cycle" (bottom-left) and "Next/OK" (top-left) touch buttons.
3.  **Wallet View:**
    *   Displays QR for current rotation `n`.
    *   "< Prev" / "Next >" (bottom-left / top-left touch) to navigate rotations.
    *   "..." (top-right touch) to view root mnemonic.

## Security Note

The security of your funds relies on keeping your root mnemonic secret and the device physically secure. This software is experimental. **Use at your own risk.**

## How the QR Rotation Works

Each QR provides the hot wallet with:
1.  `addr_n`: Current address to receive funds.
2.  `WIF_n`: Private key to spend from `addr_n`.
3.  `addr_n+1`: Next address to anticipate.
4.  `H(H(pk_n+2))`: Hash of the public key for `n+2`, for verifying sequence integrity with the next QR scan.

This allows the hot wallet to operate with only one private key at a time.

## Contributing

Contributions, bug reports, and feature requests are welcome via Issues or Pull Requests.

