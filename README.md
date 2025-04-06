## What it Does

*   Generates a 12-word recovery phrase on first use.
*   Stores the phrase on the ESP32.
*   Requires a 6-digit PIN for access.
*   Displays QR codes on an OLED screen for:
    *   Current Address
    *   Hash of next public key: `H(Pk+1)`
    *   Hash of hash of 2nd next public key: `H(H(Pk+2))`
*   Uses two buttons for navigation (Next/Previous/Confirm).
*   Can show the stored recovery phrase if you hold both buttons.

## Hardware Needed

*   ESP32 Development Board
*   SSD1306 OLED Display (128x64, I2C)
*   2 Push Buttons
*   Wires / Breadboard

## Software Needed

*   Arduino IDE or PlatformIO
*   ESP32 Board Support for your IDE
*   Libraries (Install via Arduino Library Manager or PlatformIO):
    *   `U8g2lib`
    *   `QRCodeGenerator`
    *   `uBitcoin` (or `Bitcoin`)
*   `bip39_wordlist.h` file (needs to be in the project folder)

## How to Set Up

1.  Connect the OLED (SDA/SCL) and buttons to your ESP32.
2.  Check the pin numbers near the top of the `.ino` file and change if needed:
    ```c++
    const int buttonLeft = 26;
    const int buttonRight = 25;
    // Default I2C pins usually work (SDA=21, SCL=22)
    ```
3.  Install the required libraries listed above.
4.  Make sure `bip39_wordlist.h` is in the same folder as your `.ino` file.
5.  Compile and upload the code to your ESP32.

## How to Use

1.  **Power on:** Shows "Enter Wallet PIN".
2.  **Enter PIN:** Left button cycles digits (0-9), Right button confirms digit and moves next.
3.  **First Time:**
    *   It will show a 12-word recovery phrase.
    *   Write this down and keep it safe. This is your backup.
    *   Press the Right button to confirm you saved it.
4.  **Wallet View:**
    *   Shows a QR code (Address, H(Pk+1), or H(H+Pk+2)).
    *   **Right Button:** Shows the next QR code type. After H(H+2), goes to the next address index.
    *   **Left Button:** Shows the previous QR code type. Before Address, goes to the previous address index.
    *   **Hold Both Buttons:** Shows your secret recovery phrase. Press any single button to go back.
