# ESP32 Yada Hardware Wallet (3-QR Display)

A hardware wallet proof-of-concept for ESP32 + OLED display implementing the YadaCoin key rotation security model. Displays 3 separate QR codes for Address, Next Hash (H+1), and Next+1 Hash (H+2).

**Purpose:** Securely generate keys and the specific hash data required by the Yada protocol, making them easily scannable.

## Core Features

*   **Generates/Loads:** Standard 12-word BIP39 mnemonic.
*   **PIN Protected:** Uses a 6-digit PIN as part of the key derivation (KDP).
*   **Yada Key Rotation:** Calculates keys based on `m/83696968'/39'/PIN'/Index'`.
*   **3 QR Codes Displayed:**
    1.  **Current Address**
    2.  **Next Public Key Hash (H+1)**
    3.  **Next+1 Public Key Hash (H+2)**
*   **Navigation:** Left/Right buttons change the rotation index.
*   **View Mnemonic:** Hold both buttons to see the root phrase.
*   **Storage:** Saves mnemonic securely on the ESP32 (NVS).

## What it DOES NOT Do

*   Connect to the internet or any blockchain.
*   Create or sign transactions.
*   Store the on-chain key log.
    *(It's a secure key and data generator for the Yada protocol)*

## Hardware Needed

*   ESP32 Board
*   SSD1306 OLED Display (128x64 I2C)
*   2 Push Buttons

## Software Needed

*   Arduino IDE + ESP32 Core
*   Libraries: `U8g2`, `Arduino Bitcoin Library`, `QRCodeGenerator`
*   `bip39_wordlist.h` file (included in repo)

## Basic Usage

1.  **Setup:** Install libraries, connect hardware, upload code.
2.  **Power On:** Device initializes.
3.  **Enter PIN:** Use Left to cycle digit, Right to confirm.
4.  **(First Time Only):** Backup the 12-word mnemonic shown. Confirm with Right button.
5.  **Wallet View:** See rotation index and 3 QR codes.
    *   **Scan:** Use a QR app (cover adjacent codes).
    *   **Navigate:** Use Left/Right buttons for previous/next rotation.
    *   **View Secret:** Hold BOTH buttons. Press any single button to return.
