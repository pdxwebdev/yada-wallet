Yada Hardware Wallet (ESP32 + TFT Touch)

Offline Bitcoin / YadaCoin wallet that lives entirely on an ESP32 with a 2.8” ILI9341 screen and XPT2046 touch panel.Boot once → pick a 6‑digit PIN → write down the 12‑word seed → scan rotating QR codes to sign transactions air‑gapped.

Heads‑up — hobby project; no formal security audit.

Why you might care

Touch UI (Prev / Next + hidden mnemonic button)

BIP‑39 seed + HD derivation (seed → PIN‑salted path → per‑rotation child)

Each QR = address | hash(next PK) | hash²(next+1 PK) → forward‑secure

Seed stored once in ESP32 NVS; PIN is never written to flash

Hardware quick‑list

Part

Tested board

ESP32‑2432S028R (ILI9341 + XPT2046)

✅

Any ESP32 DevKit + matching TFT/touch

Install & Flash (Arduino IDE)

Boards Manager → ESP32 by Espressif

Select ESP32 Dev Module

Clone repo → open yada_hw_wallet.ino

Add libraries (Library Manager):

uBitcoin, TFT_eSPI, XPT2046_Touchscreen, QRCodeGenerator

Copy bip39_wordlist.h next to the sketch

Compile & Upload @ 921 600 baud


First‑boot cheat‑sheet

Cycle (left) to choose each PIN digit, Next/OK (right) to confirm.

Wallet generates seed → write it down → tap Backed Up.

Main screen shows rotation 0 QR.

< Prev / Next > flip rotations

… tiny button (top‑right) reveals seed.
