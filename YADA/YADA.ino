#include <Arduino.h>
#include <Bitcoin.h>          // https://github.com/micro-bitcoin/uBitcoin
#include <Networks.h>         // Part of the Bitcoin library
#include <U8g2lib.h>          // https://github.com/olikraus/u8g2
#include <Preferences.h>      // Built-in ESP32 library
#include <QRCodeGenerator.h>  // https://github.com/Tomstark/QRCodeGenerator
#include "bip39_wordlist.h"   // Needs to be included (Make sure this file exists in your project)

#include <mbedtls/sha256.h>
#include <esp_system.h>
#include "esp_heap_caps.h"
#include <stdint.h>        // For uint32_t
#include <arpa/inet.h>     // For ntohl (Network to Host Long for endianness handling)
#include <string.h>        // For memcpy


// --- Hardware Pins ---
const int buttonLeft = 26;  // GPIO 26
const int buttonRight = 25; // GPIO 25

// --- Display Setup ---
U8G2_SSD1306_128X64_NONAME_1_HW_I2C u8g2(U8G2_R0); // Page Buffer mode

// --- Preferences ---
Preferences prefs;
const char* PREFS_NAMESPACE = "yada-wallet";
const char* MNEMONIC_KEY = "mnemonic";
const char* PROVISIONED_KEY = "provisioned";

// --- Button State ---
bool buttonLeftPressed = false;
bool buttonRightPressed = false;
bool buttonLeftTriggered = false;
bool buttonRightTriggered = false;
bool bothButtonsHeld = false; // Flag for simultaneous press
unsigned long lastDebounceTime = 0;
unsigned long debounceDelay = 50;
bool prevButtonLeftState = false;
bool prevButtonRightState = false;

// --- State Variables ---
enum AppState {
    STATE_INITIALIZING,
    STATE_SHOW_GENERATED_MNEMONIC,
    STATE_PASSWORD_ENTRY,
    STATE_WALLET_VIEW,
    STATE_SHOW_SECRET_MNEMONIC,
    STATE_ERROR
};
AppState currentState = STATE_INITIALIZING;
String errorMessage = "";
String generatedMnemonic = "";
String loadedMnemonic = "";

// --- Password Entry State ---
const int PIN_LENGTH = 6;
char password[PIN_LENGTH + 1]; // +1 for null terminator
int currentDigitIndex = 0;
int currentDigitValue = 0;
bool passwordConfirmed = false;
// Removed kdp_as_int as it's no longer directly used in the path

// --- Wallet View State ---
int currentRotationIndex = 0;
const int MAX_ROTATION_INDEX = 1000; // Maximum rotation index to display

// --- Wallet Display State ---
enum WalletDisplayMode {
    MODE_SINGLE_QR
};
WalletDisplayMode currentWalletMode = MODE_SINGLE_QR; // Default to showing single QR
int selectedQRIndex = 0; // 0: Address, 1: H(Pk+1), 2: H(H(Pk+2))

// ========================================
// Crypto & Utility Functions
// ========================================

// --- sha256Hex ---
String sha256Hex(const uint8_t* data, size_t len) {
  uint8_t hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0); // 0 for SHA-256
  mbedtls_sha256_update(&ctx, data, len);
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);
  String hex = "";
  hex.reserve(64); // Preallocate string size
  for (int i = 0; i < 32; i++) {
    if (hash[i] < 0x10) hex += "0"; // Add leading zero if needed
    hex += String(hash[i], HEX);
  }
  return hex;
}

// --- hashPublicKey (Performs SINGLE hash H(PubKey)) ---
String hashPublicKey(const PublicKey& pubKey) {
    String pubKeyHex = pubKey.toString();
    if (pubKeyHex.length() == 0) {
        Serial.println("E: Public Key string empty");
        return "Hashing Error";
    }
    // Public keys are typically 33 bytes (compressed) or 65 bytes (uncompressed)
    // The library usually returns compressed (0x02 or 0x03 prefix)
    // 33 bytes = 66 hex chars
    if (pubKeyHex.length() != 66 && pubKeyHex.length() != 130) {
        Serial.print("W: Unexpected public key hex length: "); Serial.println(pubKeyHex.length());
        // Proceed cautiously, but log a warning.
    }

    size_t len = pubKeyHex.length() / 2;
     if (len == 0) {
         Serial.println("E: Calculated key byte length is zero.");
         return "Hashing Error";
    }
    uint8_t* pubKeyBytes = (uint8_t*)malloc(len);
    if (!pubKeyBytes) {
        Serial.println("E: Failed to allocate memory for pubKeyBytes in hashPublicKey");
        return "Hashing Error";
    }

    // Hex string to byte array conversion
    for (size_t i = 0; i < len; i++) {
        unsigned int byteValue;
         // Check bounds to prevent reading past the end of the hex string
        if ((i * 2 + 1) >= pubKeyHex.length()) { // Check if accessing substring(i*2, i*2+2) is safe
             Serial.println("E: Hex string index out of bounds during conversion.");
             free(pubKeyBytes);
             return "Hashing Error";
        }
        if (sscanf(pubKeyHex.substring(i * 2, i * 2 + 2).c_str(), "%x", &byteValue) != 1) {
            Serial.println("E: Hex conversion error");
            free(pubKeyBytes);
            return "Hashing Error";
        }
        pubKeyBytes[i] = (uint8_t)byteValue;
    }

    String result = sha256Hex(pubKeyBytes, len);
    free(pubKeyBytes);
    return result;
}


// --- sha256Raw (Calculate SHA256 and output raw bytes) ---
bool sha256Raw(const uint8_t* data, size_t len, uint8_t outputHashBuffer[32]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    if(mbedtls_sha256_starts(&ctx, 0) != 0) { // 0 for SHA-256
        mbedtls_sha256_free(&ctx);
        Serial.println("E: mbedtls_sha256_starts failed");
        return false;
    }
    if(mbedtls_sha256_update(&ctx, data, len) != 0) {
        mbedtls_sha256_free(&ctx);
        Serial.println("E: mbedtls_sha256_update failed");
        return false;
    }
    if(mbedtls_sha256_finish(&ctx, outputHashBuffer) != 0) {
        mbedtls_sha256_free(&ctx);
        Serial.println("E: mbedtls_sha256_finish failed");
        return false;
    }
    mbedtls_sha256_free(&ctx);
    return true;
}

// --- bytesToHex (Convert raw bytes to Hex String) ---
String bytesToHex(const uint8_t* bytes, size_t len) {
    String hex = "";
    hex.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        if (bytes[i] < 0x10) hex += "0";
        hex += String(bytes[i], HEX);
    }
    return hex;
}

// --- pinToInt (Removed, no longer needed for direct path component) ---
// Kept the function here in case it's needed elsewhere, but commented out.
/*
bool pinToInt(const char* pinStr, uint32_t& result) {
    char* endptr;
    long val = strtol(pinStr, &endptr, 10);
    if (endptr == pinStr || *endptr != '\0' || val < 0 || val > 0xFFFFFFFF) {
        return false; // Conversion failed or out of range for uint32_t
    }
    result = (uint32_t)val;
    return true;
}
*/

// --- deriveIndexCpp (Calculates derivation index based on PIN and level) ---
// Matches the logic: sha256(PIN + level) -> first 4 bytes -> uint32 -> mask 0x7FFFFFFF
// Returns index < 0x80000000 (non-hardened range limit)
uint32_t deriveIndexCpp(const char* pinStr, int level) {
    String inputString = String(pinStr) + String(level);
    uint8_t hashOutput[32]; // SHA-256 produces 32 bytes

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); // 0 for SHA-256
    mbedtls_sha256_update(&ctx, (const unsigned char*)inputString.c_str(), inputString.length());
    mbedtls_sha256_finish(&ctx, hashOutput);
    mbedtls_sha256_free(&ctx);

    // Extract the first 4 bytes (32 bits) of the hash
    // Use ntohl to ensure consistent byte order interpretation (network order -> host order)
    uint32_t indexRaw;
    memcpy(&indexRaw, hashOutput, sizeof(uint32_t)); // Copy first 4 bytes from hash
    indexRaw = ntohl(indexRaw); // Convert from network byte order (big-endian assumed from hash)

    // Ensure the index is within the non-hardened range (0 to 2^31 - 1)
    // Mask with 0x7FFFFFFF to clear the most significant bit (hardening bit).
    uint32_t index = indexRaw & 0x7FFFFFFF;

    // --- Optional Debugging ---
    // Serial.print("deriveIndexCpp Input: '"); Serial.print(inputString); Serial.println("'");
    // Serial.print("  Hash[0..3]: ");
    // for(int i=0; i<4; i++){ if(hashOutput[i]<0x10) Serial.print("0"); Serial.print(hashOutput[i], HEX); }
    // Serial.println();
    // Serial.print("  Index Raw (BE -> Host): "); Serial.println(indexRaw);
    // Serial.print("  Final Index (masked): "); Serial.println(index);
    // --- End Debugging ---

    return index;
}


// --- generateMnemonicFromEntropy ---
String generateMnemonicFromEntropy(const uint8_t* entropy, size_t length) {
  if (length != 16) { Serial.println("E: Mnemonic gen supports only 16B (12 words)."); return ""; }
  uint8_t cs_len = (length * 8) / 32; // Checksum length in bits (4 bits for 128-bit entropy)
  uint8_t hash[32];
  // Use mbedtls directly for consistency
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, entropy, length);
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);

  uint8_t cs_byte = hash[0];
  uint8_t mask = 0xFF << (8 - cs_len); // Creates a mask like 11110000 for cs_len=4
  uint8_t cs_bits = cs_byte & mask; // Extract the checksum bits

  int total_bits = (length * 8) + cs_len; // 128 + 4 = 132 bits
  int num_words = total_bits / 11;      // 132 / 11 = 12 words

  String mnemonic = "";
  mnemonic.reserve(12 * 10); // Reserve space (avg word len + space)

  uint16_t w_idx = 0;
  int bit_count = 0; // Tracks bits processed for the current word index

  for (int i = 0; i < total_bits; i++) {
    int byte_idx = i / 8;
    int bit_in_byte = 7 - (i % 8); // Bit position within the byte (MSB first)
    uint8_t current_byte;

    if (byte_idx < length) { // Still reading from entropy bytes
        current_byte = entropy[byte_idx];
    } else { // Reading from checksum bits (only first cs_len bits matter)
        int cs_bit_idx = i - (length * 8); // Index within the checksum bits (0 to cs_len-1)
        // We need to shift the cs_bits correctly to align the desired bit
        // Example: cs_bits = 11110000. For cs_bit_idx=0, we need bit 7. For cs_bit_idx=3, we need bit 4.
        int shift_amount = 7 - cs_bit_idx;
        current_byte = cs_bits; // Use the checksum byte
        bit_in_byte = shift_amount; // Directly use the calculated shift for the relevant bit
    }

    uint8_t bit_val = (current_byte >> bit_in_byte) & 1; // Extract the bit value
    w_idx = (w_idx << 1) | bit_val; // Append the bit to the current word index
    bit_count++;

    if (bit_count == 11) { // A full word index has been assembled
        if (w_idx >= 2048) {
            Serial.print("E: Invalid word index generated: "); Serial.println(w_idx);
            return ""; // Error
        }
        mnemonic += String(wordlist[w_idx]);
        if ((i + 1) < total_bits) { // Add space if not the last word
            mnemonic += " ";
        }
        w_idx = 0; // Reset index for the next word
        bit_count = 0; // Reset bit count
    }
  }
  return mnemonic;
}


// ========================================
// Display Functions
// ========================================

void displayErrorScreen(String msg) {
    u8g2.firstPage();
    do {
        u8g2.setFont(u8g2_font_6x10_tr);
        u8g2.drawStr(0, 10, "ERROR:");
        u8g2.drawHLine(0, 12, u8g2.getDisplayWidth());
        u8g2.setFont(u8g2_font_5x7_tr);
        int y = 25;
        int maxChars = u8g2.getDisplayWidth() / u8g2.getMaxCharWidth(); // Approx chars per line
        int pos = 0;
        while (pos < msg.length()) {
            int len = min((int)msg.length() - pos, maxChars);
            // Basic Word wrap logic
            if (pos + len < msg.length()) { // Check if not the end of the string
                int lastSpace = -1;
                // Find the last space within the proposed line length
                for (int i = len - 1; i >= 0; --i) {
                    if (msg.charAt(pos + i) == ' ') {
                        lastSpace = i;
                        break;
                    }
                }
                // If a space is found and breaking there doesn't make the line too short
                if (lastSpace > 0) {
                    len = lastSpace;
                } else if (len == maxChars) {
                    // No space found, force break at maxChars
                }
            }
            u8g2.drawStr(0, y, msg.substring(pos, pos + len).c_str());
            y += u8g2.getMaxCharHeight() + 2; // Move to next line
            pos += len;
            // Skip the space character at the beginning of the next line if we wrapped
            while (pos < msg.length() && msg.charAt(pos) == ' ') {
                pos++;
            }
            if (y > u8g2.getDisplayHeight() - 10) break; // Stop if out of screen space
        }
        u8g2.setFont(u8g2_font_5x7_tr);
        u8g2.drawStr(0, u8g2.getDisplayHeight()-5, "Press any button...");
    } while (u8g2.nextPage());
    currentState = STATE_ERROR; // Set state after drawing
}

void displayGeneratedMnemonicScreen(String mnemonic) {
    u8g2.firstPage();
    do {
        u8g2.setFont(u8g2_font_6x10_tr);
        u8g2.drawStr(0, 10, "BACKUP MNEMONIC!");
        u8g2.drawHLine(0, 12, u8g2.getDisplayWidth());
        u8g2.setFont(u8g2_font_5x7_tr);

        // Split mnemonic into 2 rows (6 words each)
        int y_row1 = 22;
        int y_row2 = y_row1 + u8g2.getMaxCharHeight() + 2;
        String row1_words = "";
        String row2_words = "";
        int wordCount = 0;
        String currentWord = "";
        String tempM = mnemonic + " "; // Add space to catch last word

        for (int i = 0; i < tempM.length(); i++) {
            char c = tempM.charAt(i);
            if (c == ' ') {
                if (currentWord.length() > 0) {
                    wordCount++;
                    if (wordCount <= 6) {
                        row1_words += currentWord + " ";
                    } else if (wordCount <= 12){
                        row2_words += currentWord + " ";
                    }
                    currentWord = "";
                }
            } else {
                currentWord += c;
            }
        }
        row1_words.trim(); // Remove trailing space
        row2_words.trim();

        // Center the rows
        int w1 = u8g2.getStrWidth(row1_words.c_str());
        int w2 = u8g2.getStrWidth(row2_words.c_str());
        u8g2.drawStr(max(0, (u8g2.getDisplayWidth() - w1) / 2), y_row1, row1_words.c_str());
        u8g2.drawStr(max(0, (u8g2.getDisplayWidth() - w2) / 2), y_row2, row2_words.c_str());

        // Confirmation prompt
        u8g2.setFont(u8g2_font_5x7_tr);
        const char* confirm = "Backed up? Press RIGHT >";
        int msgW = u8g2.getStrWidth(confirm);
        u8g2.drawStr(max(0,(u8g2.getDisplayWidth() - msgW)/2), u8g2.getDisplayHeight()-5, confirm);

    } while (u8g2.nextPage());
}

void displaySecretMnemonicScreen(String mnemonic) {
    u8g2.firstPage();
    do {
        u8g2.setFont(u8g2_font_6x10_tr);
        u8g2.drawStr(0, 10, "Root Mnemonic:");
        u8g2.drawHLine(0, 12, u8g2.getDisplayWidth());
        u8g2.setFont(u8g2_font_5x7_tr);

        // Split mnemonic into 4 rows (3 words each)
        int y_start = 18;
        int y_step = u8g2.getMaxCharHeight() + 1;
        String rows[4]; // Array to hold the 4 rows of words
        int wordCount = 0;
        String currentWord = "";
        String tempM = mnemonic + " "; // Add space to catch last word

        for (int i = 0; i < tempM.length(); i++) {
            char c = tempM.charAt(i);
            if (c == ' ') {
                if (currentWord.length() > 0) {
                    int rowIndex = wordCount / 3; // Determine which row (0-3)
                    if (rowIndex < 4) {
                       rows[rowIndex] += currentWord + " ";
                    }
                    wordCount++;
                    currentWord = "";
                }
            } else {
                currentWord += c;
            }
        }

        // Draw the rows
        int x_start = 2; // Slight indent
        for(int i = 0; i < 4; ++i) {
            rows[i].trim(); // Remove trailing space
            u8g2.drawStr(x_start, y_start + i * y_step, rows[i].c_str());
        }

        // Exit prompt
        int line_y = u8g2.getDisplayHeight() - 8;
        u8g2.drawHLine(0, line_y, u8g2.getDisplayWidth());
        u8g2.setFont(u8g2_font_5x7_tr);
        const char* exitPrompt = "Press any button to exit";
        int msgW = u8g2.getStrWidth(exitPrompt);
        u8g2.drawStr(max(0,(u8g2.getDisplayWidth() - msgW)/2), u8g2.getDisplayHeight()-1, exitPrompt);

    } while (u8g2.nextPage());
}

void showPasswordEntryScreen() {
    u8g2.firstPage();
    do {
        // Title
        u8g2.setFont(u8g2_font_6x10_tr);
        const char* title = "Enter Wallet PIN"; // Changed title slightly
        int titleW = u8g2.getStrWidth(title);
        u8g2.drawStr(max(0,(u8g2.getDisplayWidth() - titleW) / 2), 10, title);

        // Digits / Placeholders
        int digitW;
        int spacing = 4; // Space between digits
        int totalW;
        int startX;
        int digitY = 35; // Vertical position of digits

        u8g2.setFont(u8g2_font_7x13B_tr); // Bold font for digits
        digitW = u8g2.getMaxCharWidth();
        totalW = PIN_LENGTH * digitW + (PIN_LENGTH - 1) * spacing;
        startX = max(0,(u8g2.getDisplayWidth() - totalW) / 2);

        for (int i = 0; i < PIN_LENGTH; i++) {
            int currentX = startX + i * (digitW + spacing);
            char displayChar;
            if (i < currentDigitIndex) {
                displayChar = '*'; // Entered digit
            } else if (i == currentDigitIndex) {
                displayChar = currentDigitValue + '0'; // Currently selecting digit
            } else {
                displayChar = '_'; // Placeholder for future digit
            }

            char tempStr[2] = {displayChar, '\0'};
            // Center the character within its allotted space
            int charOffsetX = (digitW - u8g2.getStrWidth(tempStr)) / 2;
            u8g2.drawStr(currentX + charOffsetX, digitY, tempStr);

            // Underline the current digit being selected
            if (i == currentDigitIndex) {
                u8g2.drawHLine(currentX, digitY + 2, digitW); // Line below the current digit
            }
        }

        // Hints
        u8g2.setFont(u8g2_font_4x6_tr);
        u8g2.drawStr(2, u8g2.getDisplayHeight()-1, "< Cycle");
        u8g2.drawStr(u8g2.getDisplayWidth() - u8g2.getStrWidth("Next/OK >") - 2, u8g2.getDisplayHeight()-1, "Next/OK >");

    } while (u8g2.nextPage());
}

// --- Display Single QR Code ---
void displaySingleRotationQR(int rIdx, const String& qrText, const String& label, int qrVersion) {
    if (qrText.length() == 0) {
        Serial.println("E: Empty QR text provided to displaySingleRotationQR");
        displayErrorScreen("QR Gen Error (Empty)");
        return;
    }

    const int eccLevel = ECC_MEDIUM;
    QRCode qr;
    // Allocate buffer dynamically based on version to save stack
    size_t bufferSize = qrcode_getBufferSize(qrVersion);
     // Check for reasonable buffer size to prevent excessive allocation
    if (bufferSize == 0 || bufferSize > 2000) { // Adjust max size limit as needed
         Serial.print("E: Invalid QR buffer size calculated: "); Serial.println(bufferSize);
         displayErrorScreen("QR Buffer Size Error");
         return;
    }
    uint8_t *qrDataBuffer = (uint8_t *)malloc(bufferSize);
    if (!qrDataBuffer) {
         Serial.println("E: Failed to allocate QR buffer!");
         displayErrorScreen("QR Buffer Alloc Fail");
         return;
    }

    // Attempt to initialize the QR code
    if (qrcode_initText(&qr, qrDataBuffer, qrVersion, eccLevel, qrText.c_str()) != 0) {
        Serial.print("E: Failed to initialize QR code (V"); Serial.print(qrVersion);
        Serial.print(") for: "); Serial.println(label);
        Serial.print("E: QR Text Length: "); Serial.println(qrText.length());
        // Try a higher version? For now, display error.
        free(qrDataBuffer); // Free memory before displaying error
        displayErrorScreen("QR Init Fail V" + String(qrVersion));
        return;
    }

    // --- Layout Calculation ---
    int displayWidth = u8g2.getDisplayWidth();   // 128
    int displayHeight = u8g2.getDisplayHeight(); // 64
    int titleHeight = 10; // For "Rotation: X" (Approximate space, depends on font)
    u8g2.setFont(u8g2_font_5x7_tr); // Set font early to get its height for label
    int labelHeight = u8g2.getMaxCharHeight(); // Height of the label font ("Address", etc.)
    u8g2.setFont(u8g2_font_4x6_tr); // Set font early to get its height for hints
    int hintHeight = u8g2.getMaxCharHeight();   // Height of "< Prev | Next >"
    int topGap = 1;      // Gap below title
    int bottomGap = 2;   // Gap between QR and label
    int labelHintGap = 1;// Gap between label and hints

    // Calculate available height for the QR code itself
    int availableHeight = displayHeight - titleHeight - topGap - bottomGap - labelHeight - labelHintGap - hintHeight;

    // Determine the largest pixel size that fits
    int pixelSize = 1;
    if (qr.size > 0 && availableHeight > 0) { // Avoid division by zero or negative height
        pixelSize = availableHeight / qr.size;
        if (pixelSize < 1) pixelSize = 1; // Minimum pixel size is 1
    }
     // Limit max pixel size (e.g., to 2x2 blocks) to keep it scannable
     if (pixelSize > 2) pixelSize = 2;

    int qrDrawSize = qr.size * pixelSize;

    // Check if it also fits horizontally, adjust pixelSize if needed
    int horizontalMargin = 2; // Small margin on left/right
    if (qrDrawSize > displayWidth - (2 * horizontalMargin)) {
        if (qr.size > 0) {
             pixelSize = (displayWidth - (2 * horizontalMargin)) / qr.size;
             if (pixelSize < 1) pixelSize = 1;
             qrDrawSize = qr.size * pixelSize; // Recalculate draw size
        } else {
             qrDrawSize = 0; // Handle zero size case
        }
    }

    // Center the QR code horizontally
    int startX = max(horizontalMargin, (displayWidth - qrDrawSize) / 2);
    // Calculate QR vertical position (top edge)
    u8g2.setFont(u8g2_font_6x10_tr); // Title font
    int titleAscent = u8g2.getAscent(); // Use ascent for baseline positioning
    int startY = titleAscent + topGap; // Position QR below the title baseline + gap
    // Adjust vertical position slightly if there's extra space, relative to the available area
    if (availableHeight > qrDrawSize) {
        startY += (availableHeight - qrDrawSize) / 2;
    }
    // Ensure startY doesn't push QR too low
    startY = max(startY, titleAscent + topGap);


    // Calculate Y positions for other elements (baselines)
    int titleY = titleAscent; // Position title baseline at the top
    u8g2.setFont(u8g2_font_4x6_tr); // Hint font
    int hintsY = displayHeight - 1; // Position hints baseline just above the bottom

    // --- Drawing Loop ---
    u8g2.firstPage();
    do {
        // Title ("Rotation: X")
        u8g2.setFont(u8g2_font_6x10_tr); // Set font for title
        String title = "Rotation: " + String(rIdx);
        int titleW = u8g2.getStrWidth(title.c_str());
        u8g2.drawStr(max(0, (displayWidth - titleW) / 2), titleY, title.c_str()); // Center Title

        // Draw QR Code (scaled)
        for (uint8_t y = 0; y < qr.size; y++) {
            for (uint8_t x = 0; x < qr.size; x++) {
                if (qrcode_getModule(&qr, x, y)) {
                    // Draw a rectangle (box) for each module for scaling
                    // Check bounds before drawing each pixel box
                    if (startX + x * pixelSize < displayWidth && startY + y * pixelSize < displayHeight) {
                       // Check width/height too for pixelSize > 1
                       if (startX + (x + 1) * pixelSize <= displayWidth && startY + (y + 1) * pixelSize <= displayHeight) {
                            u8g2.drawBox(startX + x * pixelSize, startY + y * pixelSize, pixelSize, pixelSize);
                       } else {
                           // If box would exceed bounds, draw single pixel? Or skip? Skipping is safer.
                       }
                    }
                }
            }
        }

        // Draw Label (e.g., "Address", "H(Pk+1)") - CENTERED
        u8g2.setFont(u8g2_font_5x7_tr); // Set font for the label
        int currentLabelAscent = u8g2.getAscent(); // Get ascent for THIS font
        int labelW = u8g2.getStrWidth(label.c_str());
        // Calculate label Y baseline position
        int labelY = startY + qrDrawSize + bottomGap + currentLabelAscent;
        // Ensure label fits vertically before drawing hints
        u8g2.setFont(u8g2_font_4x6_tr);
        int currentHintHeight = u8g2.getMaxCharHeight(); // Height needed for hints
        u8g2.setFont(u8g2_font_5x7_tr); // Switch back to label font for drawing

        if (labelY < (hintsY - currentHintHeight)) { // Check if there's vertical space above hints baseline
            u8g2.drawStr(max(0, (displayWidth - labelW) / 2), labelY, label.c_str()); // Center Label horizontally
        } else {
             // Optionally log warning if label doesn't fit, but don't draw over hints
             // Serial.println("W: Not enough space for QR Label.");
        }


        // Draw Hints ("< Prev QR/Rot", "Next QR/Rot >")
        u8g2.setFont(u8g2_font_4x6_tr); // Set font for hints
        const char* leftHint = "< Prev QR/Rot";
        const char* rightHint = "Next QR/Rot >";
        u8g2.drawStr(2, hintsY, leftHint);
        u8g2.drawStr(displayWidth - u8g2.getStrWidth(rightHint) - 2, hintsY, rightHint);

    } while (u8g2.nextPage());

    free(qrDataBuffer); // Free the allocated buffer

    // Log displayed info to Serial for debugging
    Serial.println("----- Single QR Info Displayed -----");
    Serial.println("Rotation Index: " + String(rIdx));
    Serial.println("Displayed QR: " + label + " (V" + String(qrVersion) + ")");
    // Serial.println("QR Text: " + qrText); // Uncomment for deep debug if needed
    Serial.println("-----------------------------------");
}


// ========================================
// Button Handling Function
// ========================================
void readButtons() {
    unsigned long currentTime = millis();
    buttonLeftTriggered = false;
    buttonRightTriggered = false;
    bothButtonsHeld = false; // Reset flag each time

    // Read the raw state of the buttons (LOW means pressed due to INPUT_PULLUP)
    bool currentLeftState = (digitalRead(buttonLeft) == LOW);
    bool currentRightState = (digitalRead(buttonRight) == LOW);

    // Debounce logic - Trigger on PRESS (transition from HIGH to LOW)
    if (currentTime - lastDebounceTime > debounceDelay) {
        // Check left button state change
        if (currentLeftState != prevButtonLeftState) {
            if (currentLeftState) { // Press detected (transition from HIGH to LOW)
                buttonLeftTriggered = true;
                Serial.println("DBG: Left Triggered"); // Debug
            }
            prevButtonLeftState = currentLeftState; // Update previous state
            lastDebounceTime = currentTime; // Reset timer on state change
        }
        // Check right button state change
        if (currentRightState != prevButtonRightState) {
            if (currentRightState) { // Press detected
                buttonRightTriggered = true;
                Serial.println("DBG: Right Triggered"); // Debug
            }
            prevButtonRightState = currentRightState; // Update previous state
            lastDebounceTime = currentTime; // Reset timer on state change
        }
    }

    // Update the continuous pressed state variables *after* debounce check
    buttonLeftPressed = currentLeftState;
    buttonRightPressed = currentRightState;

    // Check for simultaneous press *after* individual triggers are determined
    // Requires both buttons to be continuously held down
    if (buttonLeftPressed && buttonRightPressed) {
        bothButtonsHeld = true;
         // Optional: Override single triggers if 'both' action is primary
        // buttonLeftTriggered = false;
        // buttonRightTriggered = false;
         // Serial.println("DBG: Both Held"); // Debug - can be noisy
    }
}

// ========================================
// Setup Function
// ========================================
void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 2000); // Wait for Serial connection or timeout
  Serial.println("\n\n--- Yada Hardware Wallet ---");
  Serial.print("Setup: Initial Free Heap: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));

  // Configure Button Pins
  pinMode(buttonLeft, INPUT_PULLUP);
  pinMode(buttonRight, INPUT_PULLUP);
  Serial.println("Setup: Button pins configured.");

  // Initialize Display
  if (!u8g2.begin()) {
      Serial.println("!!! E: U8G2 Initialization Failed !!!");
      // Optionally halt or try alternative I2C pins/address
      while(1); // Halt execution
  } else {
      Serial.println("Setup: U8G2 Initialized.");
      u8g2.setContrast(100); // Adjust contrast if needed (0-255)
      u8g2.firstPage();
      do {
        u8g2.setFont(u8g2_font_6x10_tr);
        u8g2.drawStr(10,30,"Initializing...");
      } while (u8g2.nextPage());
      Serial.println("Setup: 'Initializing...' sent to display.");
  }


  // Initialize Password State
  memset(password, '_', PIN_LENGTH); // Fill with placeholder
  password[PIN_LENGTH] = '\0';       // Null-terminate
  currentDigitIndex = 0;
  currentDigitValue = 0;
  passwordConfirmed = false;
  Serial.println("Setup: Password state initialized.");

  // Preferences Initialization Check
  if (!prefs.begin(PREFS_NAMESPACE, false)) { // Try read/write first
       Serial.println("W: Setup: Failed to init Prefs (RW). Trying ReadOnly...");
       if (!prefs.begin(PREFS_NAMESPACE, true)) {
           Serial.println("!!! E: Setup: Failed to init Prefs (RO) as well. Storage issue? !!!");
           // Display error? Halt? For now, proceed assuming no stored data.
       } else {
           Serial.println("Setup: Prefs opened ReadOnly.");
           prefs.end(); // Close immediately if only checking read access
       }
  } else {
       Serial.println("Setup: Prefs Initialized OK (RW).");
       prefs.end(); // Close after check
  }

  // Check Provisioning Status (Read-Only) - Already done above implicitly, but good practice
  bool provisioned = false;
  if (prefs.begin(PREFS_NAMESPACE, true)) { // true = readOnly
      provisioned = prefs.getBool(PROVISIONED_KEY, false);
      prefs.end();
      Serial.print("Setup: Provisioned flag read = "); Serial.println(provisioned);
  } else {
      Serial.println("W: Setup: Failed to open Prefs (RO) again. Assuming not provisioned.");
      // This case might indicate a more serious storage problem.
  }

  // Set Initial Application State
  currentState = STATE_PASSWORD_ENTRY; // Always start by asking for PIN
  Serial.println("Setup: Set initial state -> STATE_PASSWORD_ENTRY.");

  Serial.print("Setup: Free Heap Before Exit: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
  Serial.println("Setup function finished.");
}

// ========================================
// Main Loop
// ========================================
void loop() {
  static bool firstLoop = true;
  bool redrawScreen = false; // Flag to request redraw for states that don't draw every loop

  if (firstLoop) {
      redrawScreen = true; // Force redraw on the very first loop iteration
      firstLoop = false;
      Serial.println("Loop: First iteration, forcing redraw.");
  }

  readButtons(); // Read button states and handle debounce/triggers

  switch (currentState) {

    case STATE_INITIALIZING:
        // This state should ideally not be re-entered after setup.
        Serial.println("W: Re-entered INITIALIZING state unexpectedly.");
        errorMessage = "Init Error Loop"; // More specific error
        displayErrorScreen(errorMessage); // Will change state to STATE_ERROR
        break;

    case STATE_SHOW_GENERATED_MNEMONIC:
        // This screen redraws itself every loop
        displayGeneratedMnemonicScreen(generatedMnemonic);

        if (buttonRightTriggered) { // User confirms backup
            Serial.println("L: User confirmed mnemonic backup.");
            Serial.println("L: Saving mnemonic & provisioned flag...");

            bool mnemonicSaved = false;
            bool flagSaved = false;

            // Open Prefs in Read/Write mode
            if (prefs.begin(PREFS_NAMESPACE, false)) { // false = read/write
                // Attempt to save mnemonic
                if (prefs.putString(MNEMONIC_KEY, generatedMnemonic.c_str())) {
                     Serial.println("L: Mnemonic saved successfully.");
                     mnemonicSaved = true;
                } else {
                     Serial.println("!!! E: Failed to store mnemonic string in Preferences !!!");
                     // Consider setting errorMessage here if needed
                }

                // Attempt to save provisioned flag only if mnemonic saved
                if(mnemonicSaved) {
                    if(prefs.putBool(PROVISIONED_KEY, true)) {
                         Serial.println("L: Provisioned flag saved successfully.");
                         flagSaved = true;
                    } else {
                         Serial.println("!!! E: Failed to store provisioned flag in Preferences !!!");
                    }
                }
                prefs.end(); // Close Preferences

                // Check if both saves were successful
                if (mnemonicSaved && flagSaved) {
                     loadedMnemonic = generatedMnemonic; // Copy to the active mnemonic variable
                     generatedMnemonic = ""; // Clear the temporary generated mnemonic
                     Serial.println("L: Copied generated mnemonic to loadedMnemonic.");

                     // Transition to Wallet View
                     currentState = STATE_WALLET_VIEW;
                     currentRotationIndex = 0; // Start at index 0
                     selectedQRIndex = 0; // Start showing Address QR
                     currentWalletMode = MODE_SINGLE_QR; // Set wallet display mode
                     Serial.println("L: Save OK. Set state STATE_WALLET_VIEW.");
                     redrawScreen = true; // Force redraw of wallet view on next loop iteration
                } else { // Save failed
                    errorMessage = "Failed to save keys!";
                    displayErrorScreen(errorMessage); // Show error (state becomes ERROR)
                    // User stays on mnemonic screen until button press, then goes to ERROR handling
                }
            } else { // Failed to open Prefs for writing
                Serial.println("!!! E: Failed to open Preferences for writing !!!");
                errorMessage = "Storage Write Error!";
                displayErrorScreen(errorMessage); // Show error (state becomes ERROR)
            }
        }
        break; // End STATE_SHOW_GENERATED_MNEMONIC

    case STATE_PASSWORD_ENTRY:
        // Password entry screen needs to be drawn every loop to show the cycling digit
        showPasswordEntryScreen();

        // Handle button presses for PIN entry
        if (buttonLeftTriggered) { // Cycle digit
            currentDigitValue = (currentDigitValue + 1) % 10; // Cycle 0-9
            // No need to set redrawScreen = true, showPasswordEntryScreen() handles it
             Serial.print("L: Cycle Digit -> "); Serial.println(currentDigitValue); // Debug
        }
        else if (buttonRightTriggered) { // Confirm digit / Move next / Confirm PIN
            password[currentDigitIndex] = currentDigitValue + '0'; // Store selected digit
            Serial.print("L: PIN Digit "); Serial.print(currentDigitIndex); Serial.print(" set to: "); Serial.println(password[currentDigitIndex]);
            currentDigitIndex++;

            if (currentDigitIndex >= PIN_LENGTH) { // Full PIN entered
                password[PIN_LENGTH] = '\0'; // Null-terminate the PIN string
                Serial.print("L: Full PIN Entered: "); Serial.println("******"); // Avoid logging actual PIN

                // PIN entered, mark as confirmed for derivation use
                passwordConfirmed = true;
                Serial.println("L: PIN Confirmed logically.");
                Serial.println("L: Attempting to load existing mnemonic...");
                Serial.print("L: Heap Before Load/Gen: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));

                bool loadAttempted = false;
                bool loadSuccess = false;
                bool isProvisioned = false;

                // Try loading from Prefs (Read Only)
                if (prefs.begin(PREFS_NAMESPACE, true)) { // true = readOnly
                    loadAttempted = true; Serial.println("L: Prefs opened (RO).");
                    isProvisioned = prefs.getBool(PROVISIONED_KEY, false);
                    Serial.print("L: Provisioned flag read = "); Serial.println(isProvisioned);

                    if (isProvisioned && prefs.isKey(MNEMONIC_KEY)) {
                        loadedMnemonic = prefs.getString(MNEMONIC_KEY, "");
                        if (loadedMnemonic.length() > 10) { // Basic validity check
                            loadSuccess = true; Serial.println("L: Existing Mnemonic loaded successfully.");
                        } else {
                            Serial.println("W: Provisioned flag set, but mnemonic empty/short in storage!");
                            loadedMnemonic = ""; // Ensure it's empty if load failed
                        }
                    } else if (isProvisioned) {
                        Serial.println("W: Provisioned flag set, but mnemonic key is missing in storage!");
                    } else {
                        Serial.println("L: Device is not provisioned (flag missing or false). Will generate new keys.");
                    }
                    prefs.end(); Serial.println("L: Prefs closed.");
                } else {
                    Serial.println("!!! E: Failed to open Preferences (RO) for loading mnemonic !!!");
                    // Treat as not provisioned if prefs can't be read
                    isProvisioned = false;
                    loadSuccess = false;
                }

                // Decide next state based on load success
                if (loadSuccess) { // Go directly to wallet view
                    currentState = STATE_WALLET_VIEW;
                    currentRotationIndex = 0; // Start at rotation 0
                    selectedQRIndex = 0;      // Start showing Address QR
                    currentWalletMode = MODE_SINGLE_QR; // Set wallet mode
                    Serial.println("L: Set state STATE_WALLET_VIEW (from loaded mnemonic).");
                    redrawScreen = true; // Force wallet redraw ONCE on state change
                } else { // Need to generate new keys (first boot or load failed)
                    Serial.println("L: Load failed or first boot. Generating new keys...");
                    uint8_t entropy[16]; // 128 bits for 12 words
                    esp_fill_random(entropy, sizeof(entropy)); // Use ESP32 Hardware RNG
                    Serial.print("L: Generated Entropy: "); for(int i=0; i<sizeof(entropy); i++) { if(entropy[i]<0x10) Serial.print("0"); Serial.print(entropy[i], HEX); } Serial.println();

                    generatedMnemonic = generateMnemonicFromEntropy(entropy, sizeof(entropy));

                    if (generatedMnemonic.length() > 0) {
                        Serial.println("L: Mnemonic generated successfully (post-PIN entry).");
                        currentState = STATE_SHOW_GENERATED_MNEMONIC; // Go to backup screen
                        Serial.println("L: Set state STATE_SHOW_GENERATED_MNEMONIC.");
                        redrawScreen = true; // Force mnemonic screen redraw ONCE
                    } else { // Mnemonic generation failed
                        errorMessage = "Key Generation Failed!"; Serial.println("!!! E: Failed post-PIN mnemonic generation !!!");
                        displayErrorScreen(errorMessage);
                        // Reset PIN state after error acknowledged.
                        passwordConfirmed = false; currentDigitIndex = 0; currentDigitValue = 0; memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0'; loadedMnemonic = ""; generatedMnemonic = "";
                    }
                }
                Serial.print("L: Heap After Load/Gen: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));

            } else { // Not the last digit yet, move to the next digit
                currentDigitValue = 0; // Reset the selector for the *next* digit position
                Serial.println("L: Advance to next digit"); // Debug
                // No need to set redrawScreen = true, screen updates next loop.
            }
        } // End buttonRightTriggered
        break; // End STATE_PASSWORD_ENTRY

    case STATE_WALLET_VIEW: { // Scope for variables local to this case
        bool walletNeedsRedraw = redrawScreen; // Check if redraw was forced by state change

        // Check for dual press first (Show Mnemonic)
        if (bothButtonsHeld) {
             // Add a small delay or check mechanism to ensure it wasn't just a quick simultaneous press
             unsigned long holdStartTime = millis();
             while(digitalRead(buttonLeft) == LOW && digitalRead(buttonRight) == LOW) {
                 if (millis() - holdStartTime > 500) { // Require hold for 500ms
                     Serial.println("L: Both buttons held > 500ms, showing secret mnemonic.");
                     currentState = STATE_SHOW_SECRET_MNEMONIC;
                     redrawScreen = true; // Request redraw of the secret screen
                     goto end_wallet_view_case; // Use goto to exit cleanly after setting state
                 }
                 delay(10); // Small delay while checking hold
             }
             // If loop finishes without reaching threshold, it was likely a quick press, ignore 'both'
             Serial.println("DBG: Both buttons quick press, ignoring.");
        }


        // Handle single button presses for QR/Rotation cycling (only if not both held)
        if (!bothButtonsHeld && buttonLeftTriggered) {
            selectedQRIndex--; // Go to previous QR item (Address -> H(H+2) -> H(+1) -> Address...)
            if (selectedQRIndex < 0) { // Was showing Address (index 0), wrap around QR and go to PREVIOUS rotation
                selectedQRIndex = 2; // Wrap around to show H(H(Pk+2))
                // Decrement rotation index with wrap-around
                if (currentRotationIndex > 0) {
                    currentRotationIndex--;
                } else {
                    currentRotationIndex = MAX_ROTATION_INDEX; // Wrap around from 0 to max
                }
                Serial.print("L: Wallet View: Prev Rot -> "); Serial.println(currentRotationIndex);
            }
            Serial.print("L: Wallet View: Selected QR Index -> "); Serial.println(selectedQRIndex);
            walletNeedsRedraw = true; // Need to recalculate and redraw the new view
        }
        else if (!bothButtonsHeld && buttonRightTriggered) {
            selectedQRIndex++; // Go to next QR item (Address -> H(+1) -> H(H+2) -> Address...)
            if (selectedQRIndex > 2) { // Was showing H(H(Pk+2)) (index 2), wrap around QR and go to NEXT rotation
                selectedQRIndex = 0; // Wrap around to show Address
                // Increment rotation index with wrap-around
                currentRotationIndex = (currentRotationIndex + 1) % (MAX_ROTATION_INDEX + 1);
                Serial.print("L: Wallet View: Next Rot -> "); Serial.println(currentRotationIndex);
            }
             Serial.print("L: Wallet View: Selected QR Index -> "); Serial.println(selectedQRIndex);
            walletNeedsRedraw = true; // Need to recalculate and redraw the new view
        }

        // Perform calculations and display selected QR code IF needed
        if (walletNeedsRedraw) {
             Serial.print("L: Redrawing Wallet R"); Serial.print(currentRotationIndex);
             Serial.print(" QR Index "); Serial.println(selectedQRIndex);
             Serial.print("L: Heap Wallet Draw Start: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));

             // --- Pre-computation Checks ---
             if (loadedMnemonic.length() == 0) { errorMessage = "Mnemonic Missing!"; Serial.println("E: loadedMnemonic empty in Wallet View!"); displayErrorScreen(errorMessage); break; }
             if (!passwordConfirmed) { errorMessage = "PIN Not Confirmed!"; Serial.println("E: Entered Wallet View without PIN confirmed!"); displayErrorScreen(errorMessage); break; }
             password[PIN_LENGTH] = '\0'; // Ensure PIN is null-terminated

             // --- Derive Master Key (using empty "" passphrase, PIN used for path derivation) ---
             HDPrivateKey hdMasterKey(loadedMnemonic, "", &Mainnet); // Use empty string "" as BIP39 passphrase
             if (!hdMasterKey.isValid()) { errorMessage = "Master Key Deriv Fail"; Serial.println("E: Master Key Initialization Failed (Mnemonic/Library issue?)."); displayErrorScreen(errorMessage); break; }
             Serial.println("L: Master Key derived successfully.");

             // --- Calculate the 4-Level Password-Dependent Path ---
             String passwordBasePath = "m";
             for (int level = 0; level < 4; ++level) {
                 uint32_t index = deriveIndexCpp(password, level); // Use the confirmed PIN string
                 passwordBasePath += "/" + String(index) + "'"; // Append hardened index
             }
             Serial.print("L: Derived Password Base Path: "); Serial.println(passwordBasePath);

             // --- Derive the Node Based on the Password Path ---
             HDPrivateKey passwordNode = hdMasterKey.derive(passwordBasePath.c_str());
             if (!passwordNode.isValid()) {
                 errorMessage = "Password Node Deriv Fail";
                 Serial.print("E: Failed to derive password-based node using path: "); Serial.println(passwordBasePath);
                 displayErrorScreen(errorMessage);
                 break; // Exit wallet view state -> Error state
             }
             Serial.println("L: Password Node derived successfully.");
             Serial.print("L: Heap After Password Node: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));


             // --- Define Derivation Paths RELATIVE to the passwordNode ---
             // Using standard external chain (0) and address index = rotationIndex
             // These are NON-HARDENED relative paths.
             String path_current_rel = "0/" + String(currentRotationIndex);
             String path_prerotated_rel = "0/" + String(currentRotationIndex + 1);
             String path_twice_prerotated_rel = "0/" + String(currentRotationIndex + 2);

             // --- Declare variables for ALL potential display data ---
             String current_address = "";
             String prerotated_pubkey_hash = "";      // H(Pk(i+1))
             String twice_prerotated_pubkey_hash = ""; // H(H(Pk(i+2)))

             // --- Perform ALL Calculations (Deriving from passwordNode) ---
             bool calculation_ok = true; // Flag to track if all calculations succeed
             String calculation_error_msg = ""; // Store specific error

             { // Scope for derived keys to limit their lifetime and free memory sooner
                 HDPrivateKey key_current = passwordNode.derive(path_current_rel.c_str());
                 HDPrivateKey key_prerotated = passwordNode.derive(path_prerotated_rel.c_str());
                 HDPrivateKey key_twice_prerotated = passwordNode.derive(path_twice_prerotated_rel.c_str());

                 // Check if derivations were successful
                 if (!key_current.isValid()) {
                      calculation_error_msg = "Rel Key Deriv Fail R" + String(currentRotationIndex);
                      Serial.println("E: " + calculation_error_msg + " Path: " + path_current_rel); calculation_ok = false;
                 }
                 if (calculation_ok && !key_prerotated.isValid()) {
                      calculation_error_msg = "Rel Key Deriv Fail R" + String(currentRotationIndex+1);
                      Serial.println("E: " + calculation_error_msg + " Path: " + path_prerotated_rel); calculation_ok = false;
                 }
                  if (calculation_ok && !key_twice_prerotated.isValid()) {
                      calculation_error_msg = "Rel Key Deriv Fail R" + String(currentRotationIndex+2);
                      Serial.println("E: " + calculation_error_msg + " Path: " + path_twice_prerotated_rel); calculation_ok = false;
                 }


                 // 1. Calculate Current Address: Pk(i) -> Address
                 if (calculation_ok) {
                    PublicKey pk_current = key_current.publicKey();
                    if (!pk_current.isValid()) {
                        calculation_error_msg = "Invalid Pk(i)"; Serial.println("E: "+ calculation_error_msg); calculation_ok = false;
                    } else {
                        current_address = pk_current.address(&Mainnet); // Specify network for address format
                        if (current_address.length() == 0) {
                            calculation_error_msg = "Addr Gen Fail R" + String(currentRotationIndex);
                            Serial.println("E: Address generation from Pk(i) failed."); calculation_ok = false;
                        }
                    }
                 }

                 // 2. Calculate Prerotated Hash: H(Pk(i+1))
                 if (calculation_ok) {
                    PublicKey pk_prerotated = key_prerotated.publicKey();
                     if (!pk_prerotated.isValid()) {
                        calculation_error_msg = "Invalid Pk(i+1)"; Serial.println("E: "+ calculation_error_msg); calculation_ok = false;
                    } else {
                        prerotated_pubkey_hash = hashPublicKey(pk_prerotated); // Uses single hash helper
                        if (prerotated_pubkey_hash.startsWith("Hashing Error")) {
                            calculation_error_msg = "Error Hashing Pk(i+1)";
                            Serial.println("E: " + calculation_error_msg); calculation_ok = false;
                        } else if (prerotated_pubkey_hash.length() != 64) { // SHA-256 hash must be 64 hex chars
                            calculation_error_msg = "Invalid H(Pk+1) Len";
                            Serial.print("E: " + calculation_error_msg + " Got: "); Serial.println(prerotated_pubkey_hash); calculation_ok = false;
                        }
                    }
                 }

                 // 3. Calculate Twice Prerotated Hash: H(H(Pk(i+2)))
                 if (calculation_ok) {
                     PublicKey pk_twice = key_twice_prerotated.publicKey();
                     if (!pk_twice.isValid()) {
                        calculation_error_msg = "Invalid Pk(i+2)"; Serial.println("E: "+ calculation_error_msg); calculation_ok = false;
                     } else {
                         String pk_twice_hex = pk_twice.toString(); // Get hex representation of Pk(i+2)

                         if (pk_twice_hex.length() > 0 && pk_twice_hex.length() % 2 == 0) {
                             size_t pk_len = pk_twice_hex.length() / 2;
                             // Allocate buffer for Pk(i+2) bytes dynamically
                             uint8_t* pk_bytes = (uint8_t*)malloc(pk_len);
                             if (!pk_bytes) {
                                 calculation_error_msg = "Mem Alloc H(H) Pk Fail"; Serial.println("E: "+ calculation_error_msg); calculation_ok = false;
                             } else {
                                 // Convert hex string Pk(i+2) to raw bytes
                                 bool conversion_ok = true;
                                 for (size_t i = 0; i < pk_len; i++) {
                                     unsigned int byteValue;
                                     if ((i * 2 + 1) >= pk_twice_hex.length()) { // Bounds check
                                         Serial.println("E: Hex string index out of bounds for Pk(i+2) bytes");
                                         calculation_error_msg = "Hex Idx Err H(H)"; conversion_ok = false; break;
                                     }
                                     if (sscanf(pk_twice_hex.substring(i * 2, i * 2 + 2).c_str(), "%x", &byteValue) != 1) {
                                         Serial.println("E: Hex conversion error for Pk(i+2) bytes");
                                         calculation_error_msg = "Hex Conv Err H(H)"; conversion_ok = false; break;
                                     }
                                     pk_bytes[i] = (uint8_t)byteValue;
                                 }

                                 if (conversion_ok) {
                                     uint8_t first_hash[32];
                                     // Calculate the first hash: H(Pk(i+2)) -> raw bytes
                                     if (sha256Raw(pk_bytes, pk_len, first_hash)) {
                                         uint8_t second_hash[32];
                                         // Calculate the second hash: H(first_hash) -> raw bytes
                                         if (sha256Raw(first_hash, 32, second_hash)) {
                                             // Convert the final raw hash H(H(Pk(i+2))) to hex string
                                             twice_prerotated_pubkey_hash = bytesToHex(second_hash, 32);
                                             if (twice_prerotated_pubkey_hash.length() != 64) { // Validate length
                                                calculation_error_msg = "Invalid H(H) Len";
                                                Serial.print("E: " + calculation_error_msg + " Got: "); Serial.println(twice_prerotated_pubkey_hash); calculation_ok = false;
                                             }
                                         } else { Serial.println("E: Second SHA256 failed for H(H(Pk(i+2)))"); calculation_error_msg = "Hashing Error (H2)"; calculation_ok = false; }
                                     } else { Serial.println("E: First SHA256 failed for H(H(Pk(i+2)))"); calculation_error_msg = "Hashing Error (H1)"; calculation_ok = false; }
                                 } else {
                                      calculation_ok = false; // Error already set during hex conversion
                                 }
                                 free(pk_bytes); // Free the allocated Pk(i+2) buffer
                             } // end else !pk_bytes (mem alloc ok)
                         } else { // Invalid hex string length for Pk(i+2)
                              calculation_error_msg = "Invalid Pk(i+2) Hex Len"; Serial.println("E: "+ calculation_error_msg + " Len=" + pk_twice_hex.length()); calculation_ok = false;
                         }
                     } // end else pk_twice valid
                 } // end H(H()) calculation block

             } // Derived keys (key_current, key_prerotated, key_twice_prerotated) go out of scope here

             // --- Display Selected QR Code ---
             if (calculation_ok) {
                 // Call the display function based on which QR is currently selected
                 switch (selectedQRIndex) {
                     case 0: // Display Address QR
                         // Determine QR version based on address length? Bitcoin addresses are usually short enough for V3-V5
                         // Let's try V4 as a general guess, might need adjustment based on actual address length/format
                         displaySingleRotationQR(currentRotationIndex, current_address, "Address", 4);
                         break;
                     case 1: // Display H(Pk+1) QR (64 hex chars = 32 bytes -> QR V5 is reasonable)
                         displaySingleRotationQR(currentRotationIndex, prerotated_pubkey_hash, "H(Pk+1)", 5);
                         break;
                     case 2: // Display H(H(Pk+2)) QR (64 hex chars = 32 bytes -> QR V5 is reasonable)
                         displaySingleRotationQR(currentRotationIndex, twice_prerotated_pubkey_hash, "H(H(Pk+2))", 5);
                         break;
                     default: // Should not happen
                         Serial.print("E: Invalid selectedQRIndex: "); Serial.println(selectedQRIndex);
                         displayErrorScreen("Internal QR Index Err");
                         break;
                 }
             } else {
                 // Calculation failed, display the specific error message
                 displayErrorScreen(calculation_error_msg.length() > 0 ? calculation_error_msg : "Calculation Error");
                 // The displayErrorScreen function changes state to STATE_ERROR
             }

             Serial.print("L: Heap Wallet Draw End: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
        } // End if(walletNeedsRedraw)

        // Reset the redraw flag AFTER potential drawing is done for this loop iteration
        if (redrawScreen) redrawScreen = false;

        // Label for goto statement
        end_wallet_view_case:;

        break; // End STATE_WALLET_VIEW
      } // End scope for STATE_WALLET_VIEW case

    case STATE_SHOW_SECRET_MNEMONIC:
        displaySecretMnemonicScreen(loadedMnemonic); // Draws itself every loop

        // Exit on ANY single button press (left OR right triggered), but NOT if both are held down still
        if ((buttonLeftTriggered || buttonRightTriggered) && !bothButtonsHeld) {
            Serial.println("L: Exiting secret mnemonic display.");
            currentState = STATE_WALLET_VIEW; // Go back to wallet view
            // When returning, ensure redraw happens and resets to default QR view for the current rotation
            selectedQRIndex = 0; // Reset to address QR
            currentWalletMode = MODE_SINGLE_QR;
            redrawScreen = true; // Request redraw of the wallet view screen on next loop
        }
        break; // End STATE_SHOW_SECRET_MNEMONIC

    case STATE_ERROR:
        // displayErrorScreen handles drawing and sets the state.
        // Wait here for any button press to acknowledge the error.
        if (buttonLeftTriggered || buttonRightTriggered) {
            Serial.println("L: Error acknowledged by user.");
            // Reset state to allow re-entry of PIN (most common recovery path)
            currentState = STATE_PASSWORD_ENTRY;
            currentDigitIndex = 0;
            currentDigitValue = 0;
            passwordConfirmed = false; // Crucial: Reset password confirmation
            memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0';
            errorMessage = ""; // Clear error message
            redrawScreen = true; // Force redraw of password entry screen on next loop
            Serial.println("L: Reset state to STATE_PASSWORD_ENTRY.");
        }
        break; // End STATE_ERROR

    default:
        // Catch any unexpected state
        Serial.print("!!! E: Reached unknown application state: "); Serial.println(currentState);
        errorMessage = "Internal State Error";
        displayErrorScreen(errorMessage); // This will change state to STATE_ERROR
        break; // End default case

  } // End of switch(currentState)

  delay(20); // Slightly increased delay for stability, adjust if needed
} // End of loop()
