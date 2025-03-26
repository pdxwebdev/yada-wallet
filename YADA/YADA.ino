#include <Arduino.h>
#include <Bitcoin.h>
#include <Networks.h>
#include <U8g2lib.h>
#include <Preferences.h>
#include <QRCodeGenerator.h>
#include "bip39_wordlist.h" // Ensure this file exists and contains the wordlist array

#include <mbedtls/md.h>      // For HMAC-SHA512
#include <mbedtls/sha256.h>  // For SHA-256

// --- Hardware Pins ---
const int buttonLeft = 26;  // GPIO 26
const int buttonRight = 25; // GPIO 25
// --- Display Setup ---
// Use hardware I2C: SDA (usually GPIO21), SCL (usually GPIO22) - Check your board!
U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0);

// --- Preferences ---
Preferences prefs;

// --- Button State ---
bool buttonLeftPressed = false;     // Current raw state
bool buttonRightPressed = false;    // Current raw state
bool buttonLeftTriggered = false;   // State after debounce & edge detection
bool buttonRightTriggered = false;  // State after debounce & edge detection
unsigned long lastDebounceTime = 0;
unsigned long debounceDelay = 50; // ms debounce time
bool prevButtonLeftState = false;
bool prevButtonRightState = false;


// --- State Variables ---
enum AppState {
    STATE_PASSWORD_ENTRY,
    STATE_WALLET_VIEW,
    STATE_ERROR
};
AppState currentState = STATE_PASSWORD_ENTRY;
String errorMessage = ""; // To store error messages for display

// --- Password Entry State ---
const int PIN_LENGTH = 6;
char password[PIN_LENGTH + 1]; // 6-digit KDP + null terminator
int currentDigitIndex = 0;      // Which digit position are we editing (0-5)
int currentDigitValue = 0;      // The value (0-9) being cycled for the current position
bool passwordConfirmed = false;

// --- Wallet View State ---
int displayIndex = 0; // 0 for root, 1-3 for children (adjust max as needed)
const int MAX_CHILD_WALLETS = 3; // Example: Root + 3 Children = 4 total views
// bool showMasterQR = false; // Kept for potential future use, but not directly used


// ========================================
// Crypto & Utility Functions
// ========================================
String sha256Hex(const uint8_t* data, size_t len) {
  uint8_t hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0); // 0 for SHA-256
  mbedtls_sha256_update(&ctx, data, len);
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);

  String hex = "";
  for (int i = 0; i < 32; i++) {
    if (hash[i] < 0x10) hex += "0";
    hex += String(hash[i], HEX);
  }
  return hex;
}

// NOTE: This function implements BIP39 checksum generation.
// It assumes 16 bytes (128 bits) entropy for 12 words.
String generateMnemonicFromEntropy(const uint8_t* entropy, size_t length) {
  if (length != 16) { // This version assumes 128 bits (16 bytes) for 12 words
      Serial.println("Error: generateMnemonicFromEntropy currently only supports 16 bytes entropy.");
      return "";
  }

  // Calculate checksum length: entropy length in bits / 32
  uint8_t checksum_len_bits = (length * 8) / 32; // 128 / 32 = 4 bits for 12 words

  // Calculate SHA256 hash of the entropy for checksum
  uint8_t hash[32];
  mbedtls_sha256(entropy, length, hash, 0); // 0 for SHA-256

  // Get the first checksum_len_bits from the hash
  uint8_t checksum = hash[0] >> (8 - checksum_len_bits);

  // Combine entropy and checksum bits to form indices for the wordlist
  int total_bits = (length * 8) + checksum_len_bits; // e.g., 128 + 4 = 132 bits
  int num_words = total_bits / 11; // 132 / 11 = 12 words

  String mnemonic = "";
  uint16_t word_val = 0;
  uint8_t bit_offset = 0; // Current bit position in the combined data (entropy + checksum)

  for (int i = 0; i < num_words; i++) {
    word_val = 0;
    for (int j = 0; j < 11; j++) { // Read 11 bits for each word
      int current_total_bit = bit_offset + j;
      int byte_index = current_total_bit / 8;
      int bit_in_byte = 7 - (current_total_bit % 8);

      uint8_t bit_value;
      if (byte_index < length) {
        // Get bit from entropy
        bit_value = (entropy[byte_index] >> bit_in_byte) & 1;
      } else {
        // Get bit from checksum
        int checksum_bit_index = current_total_bit - (length * 8);
        // Make sure we don't read beyond checksum length (shouldn't happen if total_bits % 11 == 0)
        if (checksum_bit_index < checksum_len_bits) {
            bit_value = (checksum >> (checksum_len_bits - 1 - checksum_bit_index)) & 1;
        } else {
            bit_value = 0; // Should not happen for standard BIP39 lengths
            Serial.println("Warning: Read beyond checksum bits!");
        }
      }

      word_val = (word_val << 1) | bit_value;
    }
    bit_offset += 11; // Move to the start of the next 11-bit chunk

    // Check index validity (should be 0-2047)
    if (word_val >= 2048) {
        Serial.print("Error: Invalid word index calculated: "); Serial.println(word_val);
        return ""; // Error in calculation
    }

    mnemonic += String(wordlist[word_val]);
    if (i < num_words - 1) {
      mnemonic += " ";
    }
  }

  return mnemonic;
}


// ========================================
// Display Functions
// ========================================

void displayErrorScreen(String msg) {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "ERROR:");
    // Simple text wrapping
    int y = 25;
    int maxCharsPerLine = u8g2.getDisplayWidth() / u8g2.getMaxCharWidth();
    int currentPos = 0;
    while (currentPos < msg.length()) {
        int len = min((int)msg.length() - currentPos, maxCharsPerLine);
        // Try to break at space for cleaner wrapping
        if (currentPos + len < msg.length()) {
            int lastSpace = -1;
            for (int i = len - 1; i >= 0; --i) {
                if (msg.charAt(currentPos + i) == ' ') {
                    lastSpace = i;
                    break;
                }
            }
            // Only use space break if it's not the very first char and not too short
            if (lastSpace > 0 && len - lastSpace < 10) { // Avoid breaking very short lines after space
                len = lastSpace;
            }
        }
        u8g2.drawStr(0, y, msg.substring(currentPos, currentPos + len).c_str());
        y += u8g2.getMaxCharHeight() + 2;
        currentPos += len;
         // Skip leading space on next line if we broke at a space
         if (currentPos < msg.length() && msg.charAt(currentPos) == ' ') currentPos++;
        if (y > u8g2.getDisplayHeight() - 10) break; // Prevent overflow
    }
    u8g2.setFont(u8g2_font_5x7_tr);
    u8g2.drawStr(0, u8g2.getDisplayHeight()-5, "Press any button...");
    u8g2.sendBuffer();
    currentState = STATE_ERROR;
}

// Updated displayQRAndWords function with mnemonic on the right
void displayQRAndWords(String qrText, String pubAddr, String mnemonic) {
  QRCode qrcode;
  // Using version 4 QR code might be tight for some WIFs, but usually okay.
  // Increase version (e.g., 5) if QR codes are too dense or fail to scan.
  uint8_t qrcodeData[qrcode_getBufferSize(4)];
  qrcode_initText(&qrcode, qrcodeData, 4, ECC_LOW, qrText.c_str());

  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_5x7_tr); // Font for title

  // --- Draw Title ---
   String title;
   if (displayIndex == 0) {
       title = "Root Wallet";
   } else {
       title = "Child " + String(displayIndex);
   }
   // Left-aligned title to maximize space
   u8g2.drawStr(2, 7, title.c_str());


  // --- Draw QR Code ---
  int qrSize = qrcode.size;
  int pixelSize = 1; // Use 1x1 pixels for QR to save space
  int qrDisplaySize = qrSize * pixelSize;
  // Position QR code more to the left
  int offsetX = 5;
  int offsetY = 12; // Top margin + title space

  for (uint8_t y = 0; y < qrSize; y++) {
    for (uint8_t x = 0; x < qrSize; x++) {
      if (qrcode_getModule(&qrcode, x, y)) {
         // Always draw pixel for pixelSize = 1
         u8g2.drawPixel(offsetX + x, offsetY + y);
      }
    }
  }

  // --- Draw Mnemonic Words (Right Side) ---
  u8g2.setFont(u8g2_font_4x6_tr); // Use small font for words
  int wordsStartX = offsetX + qrDisplaySize + 5; // Start words to the right of QR + padding
  int lineY = offsetY - 2; // Start words slightly above QR top align better with title maybe
  int wordCount = 0;
  int lineCount = 0;
  String line = "";
  int wordHeight = u8g2.getMaxCharHeight() + 1; // Height of one line of words

  // Ensure mnemonic string is valid before processing
  if (mnemonic.length() > 0 && mnemonic != "Generation Error") {
      // Add a space at the end to ensure the last word(s) are processed
      String tempMnemonic = mnemonic + " ";

      for (int i = 0; i < tempMnemonic.length(); i++) {
          char c = tempMnemonic.charAt(i);
          if (c == ' ') { // End of a word
              line += ' '; // Add space between the two words on a line (will trim later)
              wordCount++;
              // Draw every 2 words
              if (wordCount % 2 == 0) {
                  line.trim(); // Trim leading/trailing space before drawing
                  // Check if line fits horizontally
                  if (wordsStartX + u8g2.getStrWidth(line.c_str()) <= u8g2.getDisplayWidth()) {
                     u8g2.drawStr(wordsStartX, lineY, line.c_str());
                  } else {
                     // Word pair too long, maybe draw truncated or skip? Draw truncated for now.
                     String truncatedLine = line;
                     while (wordsStartX + u8g2.getStrWidth(truncatedLine.c_str()) > u8g2.getDisplayWidth() && truncatedLine.length() > 0) {
                         truncatedLine.remove(truncatedLine.length() - 1);
                     }
                     u8g2.drawStr(wordsStartX, lineY, truncatedLine.c_str());
                  }

                  lineY += wordHeight; // Move Y for next line
                  line = ""; // Reset line buffer
                  lineCount++;
                  if (lineCount >= 6) break; // Stop after 6 lines (12 words)
              }
          } else {
              line += c;
          }
      }
  } else {
      // Optionally display a message if mnemonic isn't available/valid
       u8g2.drawStr(wordsStartX, lineY, "Mnemonic");
       u8g2.drawStr(wordsStartX, lineY + wordHeight, "not shown");
       lineCount = 2; // Account for the two lines used
  }


  // --- Draw Public Address ---
  u8g2.setFont(u8g2_font_4x6_tr); // Keep small font
  // Calculate Y position below the taller of QR or Mnemonic words
  int bottomOfQr = offsetY + qrDisplaySize;
  int bottomOfWords = offsetY - 2 + (lineCount * wordHeight);
  int addrY = max(bottomOfQr, bottomOfWords) + 3; // Position below the taller element + margin

  // Ensure address is not drawn off-screen
  if (addrY > u8g2.getDisplayHeight() - 14) {
      addrY = u8g2.getDisplayHeight() - 14; // Pull it up if too low
  }
  // And ensure it doesn't overlap QR/Words if they are very tall
  if (addrY < bottomOfQr + 3) addrY = bottomOfQr + 3;
  if (addrY < bottomOfWords + 3) addrY = bottomOfWords + 3;


  String pubLine1 = "(Public Addr)";
  int addrWidth1 = u8g2.getStrWidth(pubLine1.c_str());
  // Center the address labels
  u8g2.drawStr((u8g2.getDisplayWidth() - addrWidth1) / 2, addrY, pubLine1.c_str());

  int addrMaxWidth = u8g2.getDisplayWidth() - 4;
  int addrMaxChars = addrMaxWidth / u8g2.getMaxCharWidth();
  String addrLine2 = pubAddr;
  if (pubAddr.length() > addrMaxChars) {
     // Simple truncation with ellipsis
     addrLine2 = pubAddr.substring(0, addrMaxChars - 1) + "~";
  }
  int addrWidth2 = u8g2.getStrWidth(addrLine2.c_str());
  u8g2.drawStr((u8g2.getDisplayWidth() - addrWidth2) / 2, addrY + 7, addrLine2.c_str());


  // --- Draw Navigation Hints (Optional, can clutter) ---
  // u8g2.setFont(u8g2_font_4x6_tr);
  // u8g2.drawStr(0, u8g2.getDisplayHeight()-1, "< Cycle"); // Left hint

  u8g2.sendBuffer();

  // --- Log details to Serial (no change needed here) ---
  Serial.println("----- Wallet Info -----");
  Serial.println("Type: " + title);
  Serial.println("Public Address: " + pubAddr);
  Serial.println("Mnemonic: " + mnemonic);
  Serial.println("WIF/QR Text: " + qrText);
}


void showPasswordEntryScreen() {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x10_tr); // Font for digits

  // Title
  const char* title = "Enter KDP PIN";
  int titleWidth = u8g2.getStrWidth(title);
  u8g2.drawStr((u8g2.getDisplayWidth() - titleWidth) / 2, 10, title);

  // Calculate starting position for digits to center them
  int digitWidth = u8g2.getMaxCharWidth();
  int spacing = 4; // Spacing between digits
  int totalWidth = PIN_LENGTH * digitWidth + (PIN_LENGTH - 1) * spacing;
  int startX = (u8g2.getDisplayWidth() - totalWidth) / 2;
  int digitY = 35; // Y position for digits

  for (int i = 0; i < PIN_LENGTH; i++) {
    int currentX = startX + i * (digitWidth + spacing);
    char displayChar;

    if (i < currentDigitIndex) {
      // Digit already confirmed - show actual digit
      displayChar = password[i];
      // displayChar = '*'; // Uncomment for masked entry
    } else if (i == currentDigitIndex) {
      // Digit currently being selected
      displayChar = currentDigitValue + '0'; // Show the value being cycled
    } else {
      // Digit not yet reached
      displayChar = '_'; // Placeholder
    }

    // Draw the digit character, centered within its block
    char tempStr[2] = {displayChar, '\0'};
    int charOffsetX = (digitWidth - u8g2.getStrWidth(tempStr)) / 2;
    u8g2.drawStr(currentX + charOffsetX, digitY, tempStr);

    // Highlight the current selection position with an underline
    if (i == currentDigitIndex) {
      u8g2.drawHLine(currentX, digitY + 2, digitWidth);
    }
  }

  // --- Button hints ---
  u8g2.setFont(u8g2_font_4x6_tr);
  u8g2.drawStr(2, u8g2.getDisplayHeight()-1, "< Cycle");
  u8g2.drawStr(u8g2.getDisplayWidth() - u8g2.getStrWidth("Next/OK >") - 2, u8g2.getDisplayHeight()-1, "Next/OK >");

  u8g2.sendBuffer();
}

// ========================================
// Button Handling Function
// ========================================
void readButtons() {
    unsigned long currentTime = millis();
    // Reset trigger flags at the start of each read cycle
    buttonLeftTriggered = false;
    buttonRightTriggered = false;

    bool currentLeftState = (digitalRead(buttonLeft) == LOW);
    bool currentRightState = (digitalRead(buttonRight) == LOW);

    // Debounce and check for falling edge (press detection)
    if (currentTime - lastDebounceTime > debounceDelay) {
        // Check Left Button state change
        if (currentLeftState != prevButtonLeftState) {
            if (currentLeftState) { // Button changed state and is now pressed
                buttonLeftTriggered = true;
                 // Serial.println("Left Button Pressed"); // Optional debug output
            }
            prevButtonLeftState = currentLeftState; // Update previous state
            lastDebounceTime = currentTime; // Reset debounce timer on any change
        }

        // Check Right Button state change (independent debounce timer reset is okay)
        if (currentRightState != prevButtonRightState) {
             if (currentRightState) { // Button changed state and is now pressed
                buttonRightTriggered = true;
                 // Serial.println("Right Button Pressed"); // Optional debug output
            }
            prevButtonRightState = currentRightState; // Update previous state
            lastDebounceTime = currentTime; // Reset debounce timer on any change
        }
    }
    // Update raw states (useful if you need hold detection later)
    buttonLeftPressed = currentLeftState;
    buttonRightPressed = currentRightState;
}


// ========================================
// Setup
// ========================================
void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 2000); // Wait for serial connection (max 2 sec)
  Serial.println("\n\n--- Yada Wallet Booting ---");

  pinMode(buttonLeft, INPUT_PULLUP);
  pinMode(buttonRight, INPUT_PULLUP);

  u8g2.begin();
  u8g2.setContrast(100); // Adjust contrast if needed (0-255)
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x10_tr);
  u8g2.drawStr(10,30,"Initializing...");
  u8g2.sendBuffer();
  delay(500);


  // Initialize password array with placeholders
  for (int i = 0; i < PIN_LENGTH; i++) {
    password[i] = '_'; // Use placeholder
  }
  password[PIN_LENGTH] = '\0'; // Null terminate

  currentDigitIndex = 0;
  currentDigitValue = 0; // Start cycling from 0
  passwordConfirmed = false;
  currentState = STATE_PASSWORD_ENTRY; // Start with PIN entry

  // Check if mnemonic exists in preferences
  Serial.println("Checking for mnemonic in Preferences...");
  prefs.begin("yada-wallet", true); // Start read-only
  bool mnemonicExists = prefs.isKey("mnemonic") && prefs.getString("mnemonic", "").length() > 0;
  prefs.end();

  if (!mnemonicExists) {
       Serial.println("ERROR: Mnemonic not found in Preferences!");
       errorMessage = "Mnemonic key not found! Please provision device.";
       // Display error and halt - device is unusable without mnemonic
       displayErrorScreen(errorMessage);
       while(1) { delay(1000); } // Halt indefinitely
  } else {
        Serial.println("Mnemonic found. Proceeding to PIN entry.");
        // Show initial PIN screen only if mnemonic exists
        showPasswordEntryScreen();
  }
}

// ========================================
// Main Loop
// ========================================
void loop() {
  readButtons(); // Update button trigger states (buttonLeftTriggered, buttonRightTriggered)

  bool redrawScreen = false; // Flag to indicate if screen needs updating this cycle

  // --- State Machine Logic ---
  switch (currentState) {
    case STATE_PASSWORD_ENTRY:
      if (buttonLeftTriggered) {
        // Left Button: Cycle digit value (0-9)
        currentDigitValue = (currentDigitValue + 1) % 10;
        // Serial.print("PIN Digit "); Serial.print(currentDigitIndex); Serial.print(" cycling to: "); Serial.println(currentDigitValue); // Debug
        redrawScreen = true; // Need to update the display
      } else if (buttonRightTriggered) {
        // Right Button: Confirm digit and move to next / Finish
        password[currentDigitIndex] = currentDigitValue + '0'; // Store the chosen digit
        Serial.print("PIN Digit "); Serial.print(currentDigitIndex); Serial.print(" confirmed as: "); Serial.println(password[currentDigitIndex]); // Log confirmation
        currentDigitIndex++; // Move to the next digit index

        if (currentDigitIndex >= PIN_LENGTH) {
          // PIN Entry Complete
          passwordConfirmed = true;
          currentState = STATE_WALLET_VIEW; // Change state
          displayIndex = 0; // Start at root wallet when entering wallet view
          Serial.println("PIN Confirmed. Entering Wallet View.");
          redrawScreen = true; // Trigger wallet view draw on state change
        } else {
          // Move to next digit entry
          currentDigitValue = 0; // Reset cycle value for the new digit position
          redrawScreen = true; // Need to update the display to show next position
        }
      }

      // If redraw needed for password entry, call the function
      if (redrawScreen && currentState == STATE_PASSWORD_ENTRY) {
          showPasswordEntryScreen();
      }
      break; // End of STATE_PASSWORD_ENTRY

    case STATE_WALLET_VIEW:
      // Handle button presses for wallet view
      if (buttonLeftTriggered) {
        // Left Button: Cycle through wallets (Root -> Child 1 -> ... -> Child N -> Root)
        displayIndex = (displayIndex + 1) % (MAX_CHILD_WALLETS + 1); // +1 because index 0 is root
        Serial.print("Wallet view index changed to: "); Serial.println(displayIndex);
        redrawScreen = true; // Need to redraw the wallet display
      } else if (buttonRightTriggered) {
         // Right Button: Currently no action defined for wallet view
         Serial.println("Right button pressed in wallet view (no action defined).");
         // Could add functionality here later (e.g., go back to PIN, confirm action, etc.)
         // redrawScreen = true; // Set true if action requires redraw
      }

      // Draw/Redraw wallet screen if redrawScreen is true (due to state entry or button press)
      if (redrawScreen) {
          // --- Wallet Generation and Display Logic ---
          prefs.begin("yada-wallet", true); // Read-only access
          String mnemonic = prefs.getString("mnemonic", ""); // Get stored mnemonic

          // Double-check mnemonic presence (should exist from setup check)
          if (mnemonic.length() == 0) {
               errorMessage = "Mnemonic read fail!"; // Should not happen if setup check passed
               displayErrorScreen(errorMessage);
               prefs.end();
               break; // Exit switch, will remain in STATE_ERROR
          }

          // Attempt to generate the HD Private Key using mnemonic and entered password (PIN)
          HDPrivateKey hdPrivateKey(mnemonic, password, &Mainnet);

          // Validate the generated key - checks if mnemonic + password combination is valid
          if (!hdPrivateKey.isValid()) {
               errorMessage = "Invalid PIN or possibly corrupted mnemonic!";
               Serial.println("ERROR: HD Private Key generation failed. Invalid PIN/Mnemonic?");
               displayErrorScreen(errorMessage);
               prefs.end();
               // State changes to STATE_ERROR via displayErrorScreen
               break; // Exit switch, will go to STATE_ERROR handling next loop
          }

          // --- Key generation successful, proceed based on displayIndex ---
          String displayMnemonic = ""; // Mnemonic to *display* (may differ for child)
          String wif = "";             // WIF key for QR code
          String pubAddress = "";      // Public address to display

          if (displayIndex == 0) { // Root Wallet
              wif = hdPrivateKey.wif();
              displayMnemonic = mnemonic; // Show the master mnemonic for the root
              pubAddress = hdPrivateKey.publicKey().address();
              Serial.println("Displaying Root Wallet Details");
          } else { // Child Wallet (index 1 to MAX_CHILD_WALLETS)
              // Derive child key using the specified path structure
              String path = String("m/83696968'/39'/0'/12'/") + String(displayIndex - 1) + "'"; // displayIndex 1 -> path index 0, etc.
              Serial.print("Deriving child key at path: "); Serial.println(path);
              HDPrivateKey childKey = hdPrivateKey.derive(path.c_str());

              // Check if child derivation was successful
              if (!childKey.isValid()) {
                  errorMessage = "Child key derivation failed for index " + String(displayIndex) + "!";
                  Serial.print("ERROR: Failed to derive child key at path: "); Serial.println(path);
                  displayErrorScreen(errorMessage);
                  prefs.end();
                  // State changes to STATE_ERROR via displayErrorScreen
                  break; // Exit switch, go to STATE_ERROR handling next loop
              }

              // --- Generate Child Mnemonic (for display/backup consistency) from Child Private Key ---
              // This derives a *new* 12-word phrase from the child key's entropy using HMAC
              uint8_t childPrivKeyBytes[32];
              childKey.getSecret(childPrivKeyBytes);

              const char hmacKey[] = "bip39-entropy-from-key"; // Standard salt for this process
              uint8_t hmacOutput[64]; // SHA512 output size
              mbedtls_md_context_t ctx;
              const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);

              mbedtls_md_init(&ctx);
              // Basic error checking for mbedtls calls (can be expanded)
              if(mbedtls_md_setup(&ctx, info, 1) != 0) { Serial.println("md_setup fail"); /* handle */ } // 1 for HMAC
              if(mbedtls_md_hmac_starts(&ctx, (const uint8_t*)hmacKey, strlen(hmacKey)) != 0) { Serial.println("hmac_starts fail"); /* handle */ }
              if(mbedtls_md_hmac_update(&ctx, childPrivKeyBytes, 32) != 0) { Serial.println("hmac_update fail"); /* handle */ }
              if(mbedtls_md_hmac_finish(&ctx, hmacOutput) != 0) { Serial.println("hmac_finish fail"); /* handle */ }
              mbedtls_md_free(&ctx);

              // Use the first 16 bytes (128 bits) of HMAC output as entropy for a 12-word mnemonic
              uint8_t childEntropy[16];
              memcpy(childEntropy, hmacOutput, 16);

              // Generate the 12-word mnemonic from this derived entropy
              displayMnemonic = generateMnemonicFromEntropy(childEntropy, sizeof(childEntropy));
              if (displayMnemonic.length() == 0) {
                  Serial.println("Warning: Child mnemonic generation failed.");
                  displayMnemonic = "Generation Error"; // Display error message instead of blank
              }

              // Get WIF and Address from the *derived child key* itself (most important part)
              wif = childKey.wif();
              pubAddress = childKey.publicKey().address();

              // Log the hash of the child's public key (as requested previously)
              String pubKeyStr = childKey.publicKey().toString(); // Get compressed pubkey hex
              if (pubKeyStr.length() > 0) {
                  String childPubKeyHash = sha256Hex((const uint8_t*)pubKeyStr.c_str(), pubKeyStr.length());
                  Serial.println("Child(" + String(displayIndex) + ") PubKey Hash: " + childPubKeyHash);
                  // You could store this hash in Preferences if needed:
                  // prefs.begin("yada-wallet", false); // Need read-write
                  // prefs.putString(("childHash"+String(displayIndex)).c_str(), childPubKeyHash);
                  // prefs.end();
                  // prefs.begin("yada-wallet", true); // Revert to read-only if needed soon
              }
          } // End of child key processing

          // --- Display the Wallet Info (QR, Address, Mnemonic) ---
          displayQRAndWords(wif, pubAddress, displayMnemonic);
          prefs.end(); // Close preferences after reading mnemonic

      } // End if(redrawScreen) for wallet view
      break; // End of STATE_WALLET_VIEW

    case STATE_ERROR:
        // In error state, wait for any button press to acknowledge
        if (buttonLeftTriggered || buttonRightTriggered) {
            Serial.println("Error acknowledged by user. Returning to PIN entry.");
            // Reset state variables to go back cleanly to PIN entry
            currentState = STATE_PASSWORD_ENTRY;
            currentDigitIndex = 0;
            currentDigitValue = 0;
            passwordConfirmed = false;
            // Clear the entered password buffer for security
            for(int i=0; i<PIN_LENGTH; ++i) password[i] = '_';
            password[PIN_LENGTH] = '\0';

            // Explicitly redraw the PIN screen now that we are returning to it
            showPasswordEntryScreen();
            // No need to set redrawScreen = true here, showPasswordEntryScreen was just called
        }
        break; // End of STATE_ERROR

    default:
        // Should not happen, but good practice to have a default
        Serial.print("Error: Unknown state encountered: "); Serial.println(currentState);
        currentState = STATE_PASSWORD_ENTRY; // Try to recover by going to PIN entry
        // Reset relevant variables
        currentDigitIndex = 0;
        currentDigitValue = 0;
        passwordConfirmed = false;
        for(int i=0; i<PIN_LENGTH; ++i) password[i] = '_';
        showPasswordEntryScreen();
        break;

  } // End of switch(currentState)

  // Small delay to yield to other tasks (like WiFi, Bluetooth if active) and prevent excessive CPU usage
  delay(10);
}
