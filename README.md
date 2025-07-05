# Yada Hardware Wallet

A air-gapped Yadacoin Hardware Wallet for ESP32, specifically demonstrated with the **ESP32-2432S028R (CYD / Cheap Yellow Display)**, featuring a TFT touchscreen. It generates, stores, and displays Yadacoin private keys (WIF) and addresses using a BIP39 mnemonic and a 6-digit PIN.

**Disclaimer:** This is an experimental project. **Use with extreme caution, for educational purposes only. You are solely responsible for the security of your funds.**

## Core Features

- Air-gapped Yadacoin key management.
- BIP39 mnemonic generation & NVS storage.
- 6-digit PIN protection for wallet access and key derivation.
- Hierarchical Deterministic (HD) key derivation using mnemonic + PIN.
- QR code display for: `Address_N | WIF_N | Address_N+1 | Address_N+2`.
- Touchscreen interface for navigation.
- Option to view root mnemonic after PIN auth.

## Hardware Requirements

- **ESP32 Microcontroller:** This project is specifically set up for the **ESP32-2432S028R (often sold as "Cheap Yellow Display" or CYD)**. Other ESP32 boards with compatible TFT/Touch may work with `User_Setup.h` and pin adjustments.
- **Integrated TFT Display with XPT2046 Touch Controller:** As found on the ESP32-2432S028R (typically ILI9341 based, 320x240).
- Appropriate wiring (pre-wired on CYD boards; see `User_Setup.h` for TFT pins, main sketch for touch pins if building custom).

## Where to buy

- **Amazon US:** https://a.co/d/dtqs2Db
- **Amazon FR:** https://amzn.eu/d/aYF3yTz
- **Amazon CA:** https://a.co/d/emPTzCq

## Software & Setup

1.  **Arduino IDE:**

    - Download from: [arduino.cc/en/software](https://www.arduino.cc/en/software/)
    - Install the ESP32 Core for Arduino.

2.  **Install Libraries:**

    - In Arduino IDE: `Tools > Manage Libraries...`
    - Install:

      - `uBitcoin` (by Stepan Snigirev) [https://github.com/pdxwebdev/uBitcoin] (this fork patches a compile error, use this fork.)
      - `TFT_eSPI` (by Bodmer)
      - `XPT2046_Touchscreen` (by Paul Stoffregen)
      - `QRCodeGenerator` (by Felix Erdmann) - URL: [https://github.com/felixerdy/QRCodeGenerator]

    - **Manual Install for `BigNumber`:**
      - Download ZIP: [https://github.com/nickgammon/BigNumber](https://github.com/nickgammon/BigNumber)
      - In Arduino IDE: `Sketch > Include Library > Add .ZIP Library...` and select the downloaded file.

3.  **Create `bip39_wordlist.h`:**

    - In the Arduino IDE, next to your main `.ino` sketch tab, click the small downward arrow (or "Sketch" menu) and select "New Tab".
    - Name the file `bip39_wordlist.h`.
    - Copy the content for this file from the `YADA/bip39_wordlist.h` file in the [project repository](https://github.com/pdxwebdev/yada-wallet/blob/main/YADA/bip39_wordlist.h).

4.  **Configure `TFT_eSPI` Library (for ESP32-2432S028R / CYD):**

    - Locate your `TFT_eSPI` library folder (usually `Documents\Arduino\libraries\TFT_eSPI\`).
    - Replace the content of `User_Setup.h` with the following configuration, which is tailored for the **ESP32-2432S028R (CYD)** board for the **TFT display only** (touch SPI pins are handled in the main sketch):

    ```cpp
    //                            USER DEFINED SETTINGS
    //   Set driver type, fonts to be loaded, pins used and SPI control method etc.
    //   Specifically for TFT_eSPI library configuration. Touch SPI pins (SCK, MOSI, MISO)
    //   are handled separately in the main sketch for this hardware configuration.
    //
    //   See the User_Setup_Select.h file if you wish to be able to define multiple
    //   setups and then easily select which setup file is used by the compiler.
    //
    //   >>>> IMPORTANT <<<<
    //   Ensure >> EITHER << this file is used by uncommenting ONLY the lines you need
    //   >> OR << that you have commented out all includes in User_Setup_Select.h
    //   and are editing the correct setup file in the User_Setups folder.
    //   If unsure, it's often simpler to comment out all includes in User_Setup_Select.h
    //   and use this main User_Setup.h file.
    //

    // Define the setup name for diagnostic purposes
    #define USER_SETUP_INFO "ESP32-2432S028R CYD Setup (TFT Only Config)"


    // ##################################################################################
    // Section 1. Call up the right driver file and any options for it
    // ##################################################################################

    // Define the driver for your specific screen
    #define ILI9341_DRIVER       // Driver for ESP32-2432S028R

    // --- Ensure all other drivers are commented out ---
    //#define ILI9341_2_DRIVER
    //#define ST7735_DRIVER
    // ... (all other drivers commented out) ...
    //#define GC9A01_DRIVER

    // --- Optional settings ---
    // #define TFT_RGB_ORDER TFT_BGR // Try TFT_BGR if colours are inverted
    // #define TFT_INVERSION_ON


    // ##################################################################################
    // Section 2. Define the pins that are used to interface with the **TFT DISPLAY**
    // ##################################################################################

    // Define pins for the ESP32-2432S028R (CYD) board **DISPLAY** connection
    // These likely use the HSPI peripheral by default when VSPI is claimed by touch
    #define TFT_MISO 12 // Master In Slave Out pin (SPI Data In) - Needed if reading from TFT
    #define TFT_MOSI 13 // Master Out Slave In pin (SPI Data Out) - FOR TFT
    #define TFT_SCLK 14 // SPI Clock pin - FOR TFT
    #define TFT_CS   15 // Chip select control pin - FOR TFT
    #define TFT_DC   2  // Data Command control pin - FOR TFT
    #define TFT_RST  -1 // Set TFT_RST to -1 if display RESET is connected to ESP32 board RST

    #define TFT_BL   21 // LED back-light control pin
    #define TFT_BACKLIGHT_ON HIGH // Level to turn ON back-light (HIGH or LOW)

    // Touch screen chip select pin - **STILL NEEDED HERE** for the XPT2046 library constructor
    #define TOUCH_CS 33

    // NOTE: The touch SCK (25), MISO (39), MOSI (32), and IRQ (36) pins are now
    //       defined and handled in the main sketch using a separate VSPI instance.
    //       The SPI pins defined above (12, 13, 14) are for the TFT connection only.

    // --- Comment out all other pin definition blocks ---
    // ... (Legacy NodeMCU, Alternate ESP32, M5Stack, Parallel, STM32 etc blocks all commented out) ...


    // ##################################################################################
    // Section 3. Define the fonts that are to be used here
    // ##################################################################################

    // Comment out the fonts you dont need to save space
    #define LOAD_GLCD   // Font 1. Original Adafruit 8 pixel font needs ~1820 bytes in FLASH
    #define LOAD_FONT2  // Font 2. Small 16 pixel high font, needs ~3534 bytes in FLASH, 96 characters
    #define LOAD_FONT4  // Font 4. Medium 26 pixel high font, needs ~5848 bytes in FLASH, 96 characters
    #define LOAD_FONT6  // Font 6. Large 48 pixel font, needs ~2666 bytes in FLASH, only characters 1234567890:-.apm
    #define LOAD_FONT7  // Font 7. 7 segment 48 pixel font, needs ~2438 bytes in FLASH, only characters 1234567890:.
    #define LOAD_FONT8  // Font 8. Large 75 pixel font needs ~3256 bytes in FLASH, only characters 1234567890:-.
    //#define LOAD_FONT8N // Font 8. Alternative to Font 8 above, slightly narrower, so 3 digits fit a 160 pixel wide TFT
    #define LOAD_GFXFF  // FreeFonts. Include access to the 48 Adafruit_GFX free fonts FF1 to FF48 and custom fonts

    #define SMOOTH_FONT // Include smooth font support


    // ##################################################################################
    // Section 4. Other options
    // ##################################################################################

    // Define the SPI clock frequency (hz) for the **TFT controller**
    // Often 27MHz is stable, 40MHz is often achievable for ILI9341
    #define SPI_FREQUENCY       40000000 // Increased frequency, try 27000000 if unstable

    // Define the SPI clock frequency for reading from the TFT controller
    #define SPI_READ_FREQUENCY  20000000

    // Define the SPI clock frequency for the touch controller (MAY NOT BE USED by TFT_eSPI now, but good practice)
    #define SPI_TOUCH_FREQUENCY 2500000

    // --- Comment out options not needed ---
    // #define USE_HSPI_PORT // Let TFT_eSPI choose default (likely HSPI if VSPI is used for touch)
    // #define SUPPORT_TRANSACTIONS // Enabled automatically for ESP32
    // ... (other options commented out) ...
    ```

5.  **Upload:** Connect your ESP32-2432S028R (CYD), select the correct board (e.g., "ESP32 Dev Module" or a specific profile if you have one for CYD) and port in Arduino IDE, and upload the sketch.

## Usage Overview

- **First Boot:**
  1.  Enter a 6-digit PIN.
  2.  A 12-word mnemonic will be generated and displayed. **WRITE THESE DOWN SECURELY.**
  3.  Confirm backup. Mnemonic is saved to device NVS.
  4.  Re-enter your PIN to access the wallet.
- **Wallet View:**
  - Displays QR code with Address/WIF/Next Addresses.
  - **Bottom-Left Touch:** "Prev" address rotation.
  - **Bottom-Right Touch:** "Next" address rotation.
  - **Top-Right Touch (Small Button):** Show secret mnemonic.

## Key Derivation

Keys are derived using a multi-stage process:

1.  **Root:** 12-word BIP39 Mnemonic (no passphrase).
2.  **Base Wallet Key:** Derived from `m/0'` and then a 4-level hardened path based on your 6-digit PIN (e.g., `m/0'/pin_idx0'/pin_idx1'/pin_idx2'/pin_idx3'`).
3.  **Address Rotation:** Each subsequent address (`addr_n`, `addr_n+1`, etc.) is derived by further applying 4-level hardened paths based on the same PIN.

This means the PIN is crucial for both unlocking the stored mnemonic _and_ for deriving the actual addresses displayed.

## Support This Project

If you find Yada Hardware Wallet useful and appreciate the effort that has gone into its development, please consider a small donation to support continued improvements and new features. Thank you for your support!

- **yadacoin (YADA):** 14kMCpqj1tXyVioViA39P1NRC475aQdESx
