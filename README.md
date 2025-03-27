# Yada Wallet (ESP32 Hardware Wallet)

This project implements a **secure, air-gapped hardware wallet** using an ESP32 and an OLED screen. It is designed for **YadaCoin** key generation and **secure key rotation** using a password-protected derivation system inspired by BIP85 and the YadaCoin whitepaper.

---

## 🔐 Features

- Enter a 6-digit password (KDP) using **two buttons** (Ledger-style navigation)
- Derives a **root HD wallet** + 3 **child wallets**
- Each child uses a multi-rotation derivation for brute-force resistance
- Displays:
  - Public Address
  - 12-word mnemonic
  - WIF QR code
- Child wallets include a **pre-rotated key hash** for on-chain validation (key log security)

---

## 🎮 Controls

| Action                    | Button(s)           |
|---------------------------|---------------------|
| Cycle PIN digit           | Right button (D25)  |
| Confirm PIN digit         | Left button (D26)   |
| Cycle wallets (after PIN) | Left button         |

---

## 🧠 How It Works

1. **Password Input**
   - 6-digit PIN entered via buttons
   - Used as the passphrase in BIP32 HD wallet derivation

2. **Root Wallet**
   - Derived directly from the master seed + PIN
   - Displays full mnemonic and address

3. **Child Wallets**
   - Derived from custom path: `m/83696968'/39'/0'/12'/n'`
   - HMAC-SHA512 of child private key → 128 bits entropy → child mnemonic

4. **Key Log Hashing**
   - Public key from each child → SHA256 hash
   - Printed to Serial Monitor as `Pre-rotated Key Hash`
   - Enables future blockchain-side validation

---

## 🔧 Requirements

- ESP32 Dev Board
- SSD1306 128x64 OLED Display (I2C)
- 2 push buttons (D25 and D26)
- Libraries:
  - `U8g2`
  - `Preferences`
  - `QRCodeGenerator`
  - `Bitcoin.h` (from uBitcoin)
  - `mbedtls`

---

## 📦 Installation

1. Clone this repo to your Arduino sketch folder
2. Install dependencies via Library Manager
3. Connect:
   - OLED to I2C (usually GPIO21 SDA, GPIO22 SCL)
   - Buttons to GPIO25 and GPIO26 (with pull-down resistors)
4. Upload to your ESP32

---

## 🔒 License

This project is based on the YadaCoin protocol and uses the YadaCoin Open Source License v1.1.

This code is shared for educational and research purposes only.

Commercial use, blockchain forks, or branding use without permission from the original authors is not allowed.

Original License: [YadaCoin Open Source License v1.1](https://github.com/yadacoin/yadacoin/blob/master/LICENSE.txt)

For commercial inquiries, contact: info@yadacoin.io

---

## 🧪 Status

✅ PIN entry and wallet cycling working
✅ QR code displayed for each wallet
✅ Public address and mnemonic shown
✅ Key log hash printed via Serial
