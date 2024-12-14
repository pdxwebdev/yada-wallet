## Overview
The Yada Hardware Wallet is a secure, offline hardware wallet designed for cryptocurrency storage, running on the ESP32 microcontroller. This wallet generates private keys, encodes them in Wallet Import Format (WIF), and generates public addresses, all while displaying the information securely on an OLED screen. The wallet operates air-gapped, ensuring maximum security by never connecting to the internet.

## Features
- Generates and securely stores private keys in WIF format.
- Displays the Wallet Import Format (WIF) and public address on an OLED screen.
- Air-gapped operation for enhanced security.
- Optional flashing LED indicators for key actions (e.g., WIF display, address display).
- Data persistence using the ESP32’s Preferences library, allowing keys to survive reboots.
- Built-in Base58Check encoding for Bitcoin-like key structures.
