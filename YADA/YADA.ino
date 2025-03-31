#include <Arduino.h>
#include <Bitcoin.h>          
#include <Networks.h>         
#include <U8g2lib.h>          
#include <Preferences.h>      
#include <QRCodeGenerator.h>  
#include "bip39_wordlist.h"   // Needs to be included 

#include <mbedtls/sha256.h>
#include <esp_system.h>
#include "esp_heap_caps.h"

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
uint32_t kdp_as_int = 0; // KDP (Key Derivation Path) component from PIN

// --- Wallet View State ---
int currentRotationIndex = 0;
const int MAX_ROTATION_INDEX = 1000; // Maximum rotation index to display

// ========================================
// Crypto & Utility Functions (Original + H(H()) Helpers)
// ========================================

// --- ORIGINAL sha256Hex (from user code) ---
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

// --- ORIGINAL hashPublicKey (Performs SINGLE hash H(PubKey) ) ---
String hashPublicKey(const PublicKey& pubKey) {
    String pubKeyHex = pubKey.toString();
    if (pubKeyHex.length() == 0) {
        Serial.println("E: Public Key string empty");
        return "Hashing Error";
    }
    // Use dynamic allocation for safety, especially if keys could be large
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

    for (size_t i = 0; i < len; i++) {
        unsigned int byteValue;
        // Basic check to prevent reading past the end of the string
        if (i * 2 + 2 > pubKeyHex.length()) {
             Serial.println("E: Hex string too short during conversion.");
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

    // Perform the SINGLE hash and convert to hex string
    String result = sha256Hex(pubKeyBytes, len);
    free(pubKeyBytes); // Free the allocated memory
    return result;
}

// --- NEW HELPER: Calculate SHA256 and output raw bytes ---
// Needed for the H(H()) calculation. outputHashBuffer MUST be pre-allocated 32 bytes.
bool sha256Raw(const uint8_t* data, size_t len, uint8_t outputHashBuffer[32]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    // Consider adding checks for mbedtls return codes in production
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, data, len);
    mbedtls_sha256_finish(&ctx, outputHashBuffer);
    mbedtls_sha256_free(&ctx);
    return true; // Assume success for simplicity
}

// --- NEW HELPER: Convert raw bytes to Hex String ---
// Needed for the H(H()) calculation.
String bytesToHex(const uint8_t* bytes, size_t len) {
    String hex = "";
    hex.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        if (bytes[i] < 0x10) hex += "0";
        hex += String(bytes[i], HEX);
    }
    return hex;
}


// --- ORIGINAL pinToInt ---
bool pinToInt(const char* pinStr, uint32_t& result) {
    char* endptr; long val = strtol(pinStr, &endptr, 10); if (endptr == pinStr || *endptr != '\0' || val < 0 || val > 0xFFFFFFFF) { return false; } result = (uint32_t)val; return true;
}

// --- ORIGINAL generateMnemonicFromEntropy (from user code) ---
String generateMnemonicFromEntropy(const uint8_t* entropy, size_t length) {
  if (length != 16) { Serial.println("E: Mnemonic gen supports only 16B."); return ""; } uint8_t cs_len = (length * 8) / 32; uint8_t hash[32]; mbedtls_sha256(entropy, length, hash, 0); uint8_t cs_byte = hash[0]; uint8_t mask = 0xFF << (8 - cs_len); uint8_t cs_bits = cs_byte & mask; int total_bits = (length * 8) + cs_len; int num_words = total_bits / 11; String mnemonic = ""; mnemonic.reserve(12 * 9); uint16_t w_idx = 0; for (int i = 0; i < num_words; i++) { w_idx = 0; for (int j = 0; j < 11; j++) { int bit_idx = i * 11 + j; int byte_idx = bit_idx / 8; int bit_in_byte = 7 - (bit_idx % 8); uint8_t current_byte; if (byte_idx < length) { current_byte = entropy[byte_idx]; } else { current_byte = cs_bits; bit_in_byte = 7 - (bit_idx - (length * 8)); } uint8_t bit_val = (current_byte >> bit_in_byte) & 1; w_idx = (w_idx << 1) | bit_val; } if (w_idx >= 2048) { Serial.print("E: Invalid word index: "); Serial.println(w_idx); return ""; } mnemonic += String(wordlist[w_idx]); if (i < num_words - 1) { mnemonic += " "; } } return mnemonic;
}

// ========================================
// Display Functions 
// ========================================
void displayErrorScreen(String msg) {
    u8g2.firstPage(); do { u8g2.setFont(u8g2_font_6x10_tr); u8g2.drawStr(0, 10, "ERROR:"); u8g2.drawHLine(0, 12, u8g2.getDisplayWidth()); u8g2.setFont(u8g2_font_5x7_tr); int y = 25; int maxChars = u8g2.getDisplayWidth() / u8g2.getMaxCharWidth(); int pos = 0; while (pos < msg.length()) { int len = min((int)msg.length() - pos, maxChars); if (pos + len < msg.length()) { int lastSpace = -1; for (int i = len - 1; i >= 0; --i) { if (msg.charAt(pos + i) == ' ') { lastSpace = i; break; } } if (lastSpace > 0 && len - lastSpace < 10) { len = lastSpace; } } u8g2.drawStr(0, y, msg.substring(pos, pos + len).c_str()); y += u8g2.getMaxCharHeight() + 2; pos += len; if (pos < msg.length() && msg.charAt(pos) == ' ') pos++; if (y > u8g2.getDisplayHeight() - 10) break; } u8g2.setFont(u8g2_font_5x7_tr); u8g2.drawStr(0, u8g2.getDisplayHeight()-5, "Press any button..."); } while (u8g2.nextPage()); currentState = STATE_ERROR;
}
void displayGeneratedMnemonicScreen(String mnemonic) {
    u8g2.firstPage(); do { u8g2.setFont(u8g2_font_6x10_tr); u8g2.drawStr(0, 10, "BACKUP MNEMONIC!"); u8g2.drawHLine(0, 12, u8g2.getDisplayWidth()); u8g2.setFont(u8g2_font_5x7_tr); int y_row1 = 22; int y_row2 = y_row1 + u8g2.getMaxCharHeight() + 2; String row1_words = ""; String row2_words = ""; int wordCount = 0; String currentWord = ""; String tempM = mnemonic + " "; for (int i = 0; i < tempM.length(); i++) { char c = tempM.charAt(i); if (c == ' ') { if (currentWord.length() > 0) { wordCount++; if (wordCount <= 6) { row1_words += currentWord + " "; } else if (wordCount <= 12){ row2_words += currentWord + " "; } currentWord = ""; } } else { currentWord += c; } } row1_words.trim(); row2_words.trim(); int w1 = u8g2.getStrWidth(row1_words.c_str()); int w2 = u8g2.getStrWidth(row2_words.c_str()); u8g2.drawStr((u8g2.getDisplayWidth() - w1) / 2, y_row1, row1_words.c_str()); u8g2.drawStr((u8g2.getDisplayWidth() - w2) / 2, y_row2, row2_words.c_str()); u8g2.setFont(u8g2_font_5x7_tr); const char* confirm = "Backed up? Press RIGHT >"; int msgW = u8g2.getStrWidth(confirm); u8g2.drawStr((u8g2.getDisplayWidth() - msgW)/2, u8g2.getDisplayHeight()-5, confirm); } while (u8g2.nextPage());
}
void displaySecretMnemonicScreen(String mnemonic) {
    u8g2.firstPage(); do { u8g2.setFont(u8g2_font_6x10_tr); u8g2.drawStr(0, 10, "Root Mnemonic:"); u8g2.drawHLine(0, 12, u8g2.getDisplayWidth()); u8g2.setFont(u8g2_font_5x7_tr); int y_start = 18; int y_step = u8g2.getMaxCharHeight() + 1; String rows[4]; int wordCount = 0; String currentWord = ""; String tempM = mnemonic + " "; for (int i = 0; i < tempM.length(); i++) { char c = tempM.charAt(i); if (c == ' ') { if (currentWord.length() > 0) { int rowIndex = wordCount / 3; if (rowIndex < 4) { rows[rowIndex] += currentWord + " "; } wordCount++; currentWord = ""; } } else { currentWord += c; } } int x_start = 2; for(int i = 0; i < 4; ++i) { rows[i].trim(); u8g2.drawStr(x_start, y_start + i * y_step, rows[i].c_str()); } int line_y = u8g2.getDisplayHeight() - 8; u8g2.drawHLine(0, line_y, u8g2.getDisplayWidth()); u8g2.setFont(u8g2_font_5x7_tr); const char* exitPrompt = "Press any button to exit"; int msgW = u8g2.getStrWidth(exitPrompt); u8g2.drawStr((u8g2.getDisplayWidth() - msgW)/2, u8g2.getDisplayHeight()-1, exitPrompt); } while (u8g2.nextPage());
}

// *** Using Current Working displayRotationInfo (3 QRs, V3/V5, Increased Gap) ***
void displayRotationInfo(int rIdx, const String& addr, const String& preHash, const String& twicePreHash) {

    // Basic checks for empty strings
    if (addr.length() == 0 || preHash.length() == 0 || twicePreHash.length() == 0) {
        Serial.println("E: Empty string provided to displayRotationInfo");
        // Avoid crashing, maybe display an error or return
        displayErrorScreen("QR Gen Error"); // Show error on screen
        return;
    }

    // --- Define QR Code versions and ECC levels ---
    const int qrVersionAddr = 3; // Version 3 for Address
    const int qrVersionHash = 5; // Version 5 for Hashes (usually fits 64 hex chars)
    const int eccLevel = ECC_MEDIUM;

    // --- Allocate Buffers and Initialize QR Codes ---
    QRCode qrAddr;
    uint8_t qrDataAddr[qrcode_getBufferSize(qrVersionAddr)];
    // Check buffer size roughly - qrcode_initText might handle internally but good practice
    if (addr.length() >= sizeof(qrDataAddr)) { Serial.println("W: Addr might be too long for QR V3"); }
    qrcode_initText(&qrAddr, qrDataAddr, qrVersionAddr, eccLevel, addr.c_str());

    QRCode qrHash1;
    uint8_t qrDataHash1[qrcode_getBufferSize(qrVersionHash)];
    if (preHash.length() >= sizeof(qrDataHash1)) { Serial.println("W: H+1 might be too long for QR V5"); }
    qrcode_initText(&qrHash1, qrDataHash1, qrVersionHash, eccLevel, preHash.c_str());

    QRCode qrHash2;
    uint8_t qrDataHash2[qrcode_getBufferSize(qrVersionHash)];
    if (twicePreHash.length() >= sizeof(qrDataHash2)) { Serial.println("W: H+2 might be too long for QR V5"); }
    qrcode_initText(&qrHash2, qrDataHash2, qrVersionHash, eccLevel, twicePreHash.c_str());

    // --- Calculate Layout ---
    int pixelSize = 1;
    int qrSizeAddr = qrAddr.size * pixelSize;  // V3 -> 29x29
    int qrSizeHash1 = qrHash1.size * pixelSize; // V5 -> 37x37
    int qrSizeHash2 = qrHash2.size * pixelSize; // V5 -> 37x37
    int displayWidth = u8g2.getDisplayWidth();
    int displayHeight = u8g2.getDisplayHeight();
    int gutter = 3; // Reduced from 4
    int totalQrWidth = qrSizeAddr + gutter + qrSizeHash1 + gutter + qrSizeHash2;
    int startX = max(0, (displayWidth - totalQrWidth) / 2); // Center horizontally
    int oxAddr = startX;
    int oxHash1 = startX + qrSizeAddr + gutter;
    int oxHash2 = startX + qrSizeAddr + gutter + qrSizeHash1 + gutter;
    int titleHeight = 12; // Approximate title height
    int oy = titleHeight + 2; // Y offset for top of QRs
    int maxQrHeight = max(qrSizeAddr, max(qrSizeHash1, qrSizeHash2));
    int qrBottom = oy + maxQrHeight;
    int labelGap = 4; // Space below QRs
    int labelY = qrBottom + labelGap;
    int hintFontHeight = 6; // Approx height
    int labelFontHeight = 6; // Approx height
    int hintsY = displayHeight - 1; // Bottom line for hints

    // --- Drawing Loop ---
    u8g2.firstPage();
    do {
        // Title
        u8g2.setFont(u8g2_font_6x10_tr);
        String title = "Rotation: " + String(rIdx);
        int titleW = u8g2.getStrWidth(title.c_str());
        u8g2.drawStr(max(0, (displayWidth - titleW) / 2), 10, title.c_str()); // Center

        // Draw QR Codes (with basic bounds check)
        for (uint8_t y = 0; y < qrAddr.size; y++) { for (uint8_t x = 0; x < qrAddr.size; x++) { if (qrcode_getModule(&qrAddr, x, y)) { if (oxAddr + x * pixelSize < displayWidth && oy + y * pixelSize < displayHeight) { u8g2.drawPixel(oxAddr + x * pixelSize, oy + y * pixelSize); } } } }
        for (uint8_t y = 0; y < qrHash1.size; y++) { for (uint8_t x = 0; x < qrHash1.size; x++) { if (qrcode_getModule(&qrHash1, x, y)) { if (oxHash1 + x * pixelSize < displayWidth && oy + y * pixelSize < displayHeight) { u8g2.drawPixel(oxHash1 + x * pixelSize, oy + y * pixelSize); } } } }
        for (uint8_t y = 0; y < qrHash2.size; y++) { for (uint8_t x = 0; x < qrHash2.size; x++) { if (qrcode_getModule(&qrHash2, x, y)) { if (oxHash2 + x * pixelSize < displayWidth && oy + y * pixelSize < displayHeight) { u8g2.drawPixel(oxHash2 + x * pixelSize, oy + y * pixelSize); } } } }

        // Draw Labels if space allows
        if (labelY < (hintsY - hintFontHeight - labelFontHeight)) {
            u8g2.setFont(u8g2_font_4x6_tr);
            const char* lblAddr = "Addr"; const char* lblH1 = "H+1"; const char* lblH2 = "H+2";
            int lblAddrW = u8g2.getStrWidth(lblAddr); int lblH1W = u8g2.getStrWidth(lblH1); int lblH2W = u8g2.getStrWidth(lblH2);
            u8g2.drawStr(max(0, oxAddr + (qrSizeAddr - lblAddrW)/2), labelY + labelFontHeight - 1, lblAddr);
            u8g2.drawStr(max(0, oxHash1 + (qrSizeHash1 - lblH1W)/2), labelY + labelFontHeight - 1, lblH1);
            u8g2.drawStr(max(0, oxHash2 + (qrSizeHash2 - lblH2W)/2), labelY + labelFontHeight - 1, lblH2);
        } else {
            // Optional: Log if labels don't fit, don't display error on screen for this
            // Serial.println("W: Not enough vertical space for QR labels.");
        }

        // Draw Hints
        u8g2.setFont(u8g2_font_4x6_tr);
        u8g2.drawStr(2, hintsY, "< Prev Rot");
        const char* nextHint = "Next Rot >";
        u8g2.drawStr(displayWidth - u8g2.getStrWidth(nextHint) - 2, hintsY, nextHint);
    } while (u8g2.nextPage());

    // Log displayed info to Serial for debugging
    Serial.println("----- Rotation Info Displayed -----");
    Serial.println("Rotation Index: " + String(rIdx));
    Serial.println("QR 1 (Addr - V" + String(qrVersionAddr) + "): " + addr);
    Serial.println("QR 2 (H+1 - V" + String(qrVersionHash) + "): " + preHash); // H(Pk(i+1))
    Serial.println("QR 3 (H+2 - V" + String(qrVersionHash) + "): " + twicePreHash); // H(H(Pk(i+2)))
    Serial.println("-----------------------------------");
}

// Using current working showPasswordEntryScreen 
void showPasswordEntryScreen() {
    u8g2.firstPage(); do { u8g2.setFont(u8g2_font_6x10_tr); const char* title = "Enter KDP PIN"; int titleW = u8g2.getStrWidth(title); u8g2.drawStr((u8g2.getDisplayWidth() - titleW) / 2, 10, title); int digitW = u8g2.getMaxCharWidth(); int spacing = 4; int totalW = PIN_LENGTH * digitW + (PIN_LENGTH - 1) * spacing; int startX = (u8g2.getDisplayWidth() - totalW) / 2; int digitY = 35; u8g2.setFont(u8g2_font_7x13B_tr); digitW = u8g2.getMaxCharWidth(); totalW = PIN_LENGTH * digitW + (PIN_LENGTH - 1) * spacing; startX = (u8g2.getDisplayWidth() - totalW) / 2; for (int i = 0; i < PIN_LENGTH; i++) { int currentX = startX + i * (digitW + spacing); char displayChar; if (i < currentDigitIndex) { displayChar = '*'; } else if (i == currentDigitIndex) { displayChar = currentDigitValue + '0'; } else { displayChar = '_'; } char tempStr[2] = {displayChar, '\0'}; int charOffsetX = (digitW - u8g2.getStrWidth(tempStr)) / 2; u8g2.drawStr(currentX + charOffsetX, digitY, tempStr); if (i == currentDigitIndex) { u8g2.drawHLine(currentX, digitY + 2, digitW); } } u8g2.setFont(u8g2_font_4x6_tr); u8g2.drawStr(2, u8g2.getDisplayHeight()-1, "< Cycle"); u8g2.drawStr(u8g2.getDisplayWidth() - u8g2.getStrWidth("Next/OK >") - 2, u8g2.getDisplayHeight()-1, "Next/OK >"); } while (u8g2.nextPage());
}

// ========================================
// Button Handling Function
// ========================================
void readButtons() {
    unsigned long currentTime = millis();
    buttonLeftTriggered = false;
    buttonRightTriggered = false;
    bothButtonsHeld = false; // Reset flag each time
    bool currentLeftState = (digitalRead(buttonLeft) == LOW);
    bool currentRightState = (digitalRead(buttonRight) == LOW);

    if (currentTime - lastDebounceTime > debounceDelay) {
        if (currentLeftState != prevButtonLeftState) {
            if (currentLeftState) { // Press detected
                buttonLeftTriggered = true;
            }
            prevButtonLeftState = currentLeftState;
            lastDebounceTime = currentTime; // Reset timer on change
        }
        if (currentRightState != prevButtonRightState) {
            if (currentRightState) { // Press detected
                buttonRightTriggered = true;
            }
            prevButtonRightState = currentRightState;
            lastDebounceTime = currentTime; // Reset timer on change
        }
    }

    buttonLeftPressed = currentLeftState; // Update current hold state
    buttonRightPressed = currentRightState; // Update current hold state

    // Check for simultaneous press
    if (buttonLeftPressed && buttonRightPressed) {
        bothButtonsHeld = true;
        // If 'both' should override single triggers entirely, uncomment below
        // buttonLeftTriggered = false;
        // buttonRightTriggered = false;
    }
}

// ========================================
// Setup Function 
// ========================================
void setup() {
  Serial.begin(115200); while (!Serial && millis() < 2000); Serial.println("\n\n--- Yada Hardware Wallet ---"); Serial.print("Setup: Initial Free Heap: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT)); pinMode(buttonLeft, INPUT_PULLUP); pinMode(buttonRight, INPUT_PULLUP); Serial.println("Setup: Button pins configured."); u8g2.begin(); Serial.println("Setup: U8G2 Initialized."); u8g2.setContrast(100); u8g2.firstPage(); do { u8g2.setFont(u8g2_font_6x10_tr); u8g2.drawStr(10,30,"Initializing..."); } while (u8g2.nextPage()); Serial.println("Setup: 'Initializing...' sent to display."); memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0'; currentDigitIndex = 0; currentDigitValue = 0; passwordConfirmed = false; kdp_as_int = 0; Serial.println("Setup: Password state initialized."); bool provisioned = false; if (prefs.begin(PREFS_NAMESPACE, true)) { provisioned = prefs.getBool(PROVISIONED_KEY, false); prefs.end(); Serial.print("Setup: Provisioned flag read = "); Serial.println(provisioned); } else { Serial.println("W: Setup: Failed to open Prefs (RO). Assuming not provisioned."); } currentState = STATE_PASSWORD_ENTRY; Serial.println("Setup: Set initial state -> STATE_PASSWORD_ENTRY."); Serial.print("Setup: Free Heap Before Exit: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT)); Serial.println("Setup function finished.");
}

// ========================================
// Main Loop (Minimal changes for H(H()) integration)
// ========================================
void loop() {
  static bool firstLoop = true; bool redrawScreen = false;
  if (firstLoop) { redrawScreen = true; firstLoop = false; Serial.println("Loop: First iteration, forcing redraw."); }
  readButtons(); // Use the original button reading logic

  switch (currentState) {

    case STATE_INITIALIZING:
        // Should ideally only happen once at boot, handle unexpected entry
        Serial.println("W: Re-entered INITIALIZING state."); errorMessage = "Init Error"; displayErrorScreen(errorMessage); break;

    case STATE_SHOW_GENERATED_MNEMONIC:
        displayGeneratedMnemonicScreen(generatedMnemonic); // Screen updates itself
        if (buttonRightTriggered) {
            Serial.println("L: User confirmed backup."); Serial.println("L: Saving mnemonic & flag...");
            bool mnemonicSaved = false; bool flagSaved = false;
            // Open Prefs in Read/Write mode
            if (prefs.begin(PREFS_NAMESPACE, false)) {
                if (prefs.putString(MNEMONIC_KEY, generatedMnemonic.c_str())) {
                     Serial.println("L: Mnemonic saved ok."); mnemonicSaved = true;
                } else { Serial.println("!!! E: Failed to store mnemonic !!!"); }
                // Only save flag if mnemonic saved
                if(mnemonicSaved) {
                    if(prefs.putBool(PROVISIONED_KEY, true)) {
                         Serial.println("L: Provisioned flag saved ok."); flagSaved = true;
                    } else { Serial.println("!!! E: Failed to store provisioned flag !!!"); }
                }
                prefs.end(); // Close Prefs

                if (mnemonicSaved && flagSaved) {
                     loadedMnemonic = generatedMnemonic;
                     generatedMnemonic = ""; // Clear temp mnemonic
                     Serial.println("L: Copied generated mnemonic to loadedMnemonic.");
                     currentState = STATE_WALLET_VIEW;
                     currentRotationIndex = 0; // Start at index 0
                     Serial.println("L: Save OK. Set state STATE_WALLET_VIEW.");
                     redrawScreen = true; // Force redraw of wallet view
                } else { // Save failed
                    errorMessage = "Failed to save keys!";
                    displayErrorScreen(errorMessage); // Show error, stay on mnemonic screen
                }
            } else { // Failed to open Prefs
                Serial.println("!!! E: Failed to open Prefs for writing !!!");
                errorMessage = "Storage Write Error!";
                displayErrorScreen(errorMessage); // Show error, stay on mnemonic screen
            }
        }
        break; // End STATE_SHOW_GENERATED_MNEMONIC

    case STATE_PASSWORD_ENTRY:
      // Redraw screen only if flag is set (e.g., digit cycled)
      if(redrawScreen) {
          showPasswordEntryScreen();
          // Don't reset redrawScreen here, showPasswordEntryScreen draws every loop implicitly
      }

      // Handle button presses for PIN entry
      if (buttonLeftTriggered) {
          currentDigitValue = (currentDigitValue + 1) % 10; // Cycle 0-9
          redrawScreen = true; // Need to redraw the updated digit
      }
      else if (buttonRightTriggered) { // Confirm digit / PIN
        password[currentDigitIndex] = currentDigitValue + '0'; // Store digit
        Serial.print("L: PIN Digit "); Serial.print(currentDigitIndex); Serial.println(" set.");
        currentDigitIndex++;

        if (currentDigitIndex >= PIN_LENGTH) { // Full PIN entered
          password[PIN_LENGTH] = '\0'; // Null-terminate
          Serial.print("L: Full PIN Entered: "); /*Serial.println(password);*/ Serial.println("******"); // Don't log actual PIN

          if (!pinToInt(password, kdp_as_int)) { // Validate PIN format
              errorMessage = "Invalid PIN format."; Serial.println("E: PIN conversion failed.");
              displayErrorScreen(errorMessage);
              // Reset PIN state on error
              currentDigitIndex = 0; currentDigitValue = 0; memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0'; kdp_as_int = 0; passwordConfirmed = false;
              // Stay in Password Entry (Error screen will change state to ERROR)
          } else { // PIN format OK
              passwordConfirmed = true;
              Serial.println("L: PIN Confirmed."); Serial.print("L: KDP int: "); Serial.println(kdp_as_int);
              Serial.println("L: Attempting to load existing mnemonic..."); Serial.print("L: Heap Before Load/Gen: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));

              bool loadAttempted = false; bool loadSuccess = false;
              // Try loading from Prefs (Read Only)
              if (prefs.begin(PREFS_NAMESPACE, true)) {
                  loadAttempted = true; Serial.println("L: Prefs opened (RO).");
                  bool provisionedFlag = prefs.getBool(PROVISIONED_KEY, false);
                  Serial.print("L: Provisioned flag read = "); Serial.println(provisionedFlag);

                  if (provisionedFlag && prefs.isKey(MNEMONIC_KEY)) {
                      loadedMnemonic = prefs.getString(MNEMONIC_KEY, "");
                      if (loadedMnemonic.length() > 10) { // Basic check
                         loadSuccess = true; Serial.println("L: Existing Mnemonic loaded ok.");
                      } else { Serial.println("W: Provisioned flag set, but mnemonic empty/short!"); loadedMnemonic = ""; }
                  } else if (provisionedFlag) { Serial.println("W: Provisioned flag set, but mnemonic key missing!");
                  } else { Serial.println("L: Not provisioned (flag missing/false). Should generate."); }
                  prefs.end(); Serial.println("L: Prefs closed.");
              } else { Serial.println("!!! E: Failed to open Prefs (RO) for load !!!"); /* Consider error handling */ }

              // Decide next step based on load success
              if (loadSuccess) { // Go to wallet view
                  currentState = STATE_WALLET_VIEW;
                  currentRotationIndex = 0; // Start at rotation 0
                  Serial.println("L: Set state STATE_WALLET_VIEW (from loaded).");
                  redrawScreen = true; // Force wallet redraw
              } else { // Generate new keys
                  Serial.println("L: Load failed or first boot. Generating keys...");
                  uint8_t entropy[16]; // 128 bits
                  esp_fill_random(entropy, sizeof(entropy)); // Use HW RNG
                  Serial.print("L: Entropy for Gen: "); for(int i=0; i<sizeof(entropy); i++) { if(entropy[i]<0x10) Serial.print("0"); Serial.print(entropy[i], HEX); } Serial.println();

                  generatedMnemonic = generateMnemonicFromEntropy(entropy, sizeof(entropy));

                  if (generatedMnemonic.length() > 0) {
                      Serial.println("L: Mnemonic generated ok (post-PIN).");
                      currentState = STATE_SHOW_GENERATED_MNEMONIC; // Go to backup screen
                      Serial.println("L: Set state STATE_SHOW_GENERATED_MNEMONIC.");
                      redrawScreen = true; // Force mnemonic screen redraw
                  } else { // Generation failed
                      errorMessage = "Key Generation Failed!"; Serial.println("!!! E: Failed post-PIN mnemonic generation !!!");
                      displayErrorScreen(errorMessage);
                      // Reset state?
                      passwordConfirmed = false; currentDigitIndex = 0; currentDigitValue = 0; memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0'; kdp_as_int = 0; loadedMnemonic = ""; generatedMnemonic = "";
                  }
              }
              Serial.print("L: Heap After Load/Gen: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
          }
        } else { // Not the last digit yet
          currentDigitValue = 0; // Reset value for the *next* digit
          redrawScreen = true; // Need redraw to show progress (* _ _...)
        }
      }
      break; // End STATE_PASSWORD_ENTRY

    case STATE_WALLET_VIEW: {
        bool walletNeedsRedraw = redrawScreen; // Check if forced redraw

        // Check for dual press first
        if (bothButtonsHeld) {
            Serial.println("L: Both buttons detected, showing secret mnemonic.");
            currentState = STATE_SHOW_SECRET_MNEMONIC;
            redrawScreen = true; // Request redraw of the secret screen
            break; // Exit this case
        }

        // Check single button presses if dual press didn't occur
        if (buttonLeftTriggered) {
            if (currentRotationIndex > 0) { currentRotationIndex--; }
            else { currentRotationIndex = MAX_ROTATION_INDEX; } // Wrap around
            Serial.print("L: Wallet View: Prev Rot -> "); Serial.println(currentRotationIndex);
            walletNeedsRedraw = true; // Need to recalculate and redraw
        } else if (buttonRightTriggered) {
            currentRotationIndex = (currentRotationIndex + 1) % (MAX_ROTATION_INDEX + 1); // Wrap around
            Serial.print("L: Wallet View: Next Rot -> "); Serial.println(currentRotationIndex);
            walletNeedsRedraw = true; // Need to recalculate and redraw
        }

        // Perform calculations and display QR codes IF needed
        if (walletNeedsRedraw) {
             Serial.print("L: Redrawing Wallet R"); Serial.println(currentRotationIndex); Serial.print("L: Heap Wallet Draw Start: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));

             // --- Pre-computation Checks ---
             if (loadedMnemonic.length() == 0) { errorMessage = "Mnemonic Missing!"; Serial.println("E: loadedMnemonic empty!"); displayErrorScreen(errorMessage); break; }
             if (!passwordConfirmed) { errorMessage = "PIN Not Confirmed!"; Serial.println("E: Entered Wallet View without PIN!"); displayErrorScreen(errorMessage); break; }
             password[PIN_LENGTH] = '\0'; // Ensure null-terminated

             // --- Derive Master Key ---
             HDPrivateKey hdMasterKey(loadedMnemonic, password, &Mainnet); // Assuming Mainnet params
             if (!hdMasterKey.isValid()) { errorMessage = "Invalid PIN/Mnemonic!"; Serial.println("E: Master Key Init Fail."); displayErrorScreen(errorMessage); break; }

             // --- Define Derivation Paths ---
             String basePath = "m/83696968'/39'/" + String(kdp_as_int) + "'";
             String path_current = basePath + "/" + String(currentRotationIndex) + "'";
             String path_prerotated = basePath + "/" + String(currentRotationIndex + 1) + "'";
             String path_twice_prerotated = basePath + "/" + String(currentRotationIndex + 2) + "'";

             // --- Declare variables for display data ---
             String current_address = "";
             String prerotated_pubkey_hash = "";      // H(Pk(i+1))
             String twice_prerotated_pubkey_hash = ""; // H(H(Pk(i+2)))

             { // Scope for derived keys to release memory earlier
                 HDPrivateKey key_current = hdMasterKey.derive(path_current.c_str());
                 HDPrivateKey key_prerotated = hdMasterKey.derive(path_prerotated.c_str());
                 HDPrivateKey key_twice_prerotated = hdMasterKey.derive(path_twice_prerotated.c_str());

                 if (!key_current.isValid() || !key_prerotated.isValid() || !key_twice_prerotated.isValid()) {
                     errorMessage = "Key derivation fail R" + String(currentRotationIndex); Serial.println("E: Key derive fail."); displayErrorScreen(errorMessage); break;
                 }

                 // --- Calculate Display Data ---
                 // 1. Current Address Pk(i) -> Address
                 current_address = key_current.publicKey().address();
                 if (current_address.length() == 0) {
                     errorMessage = "Addr Gen Fail R" + String(currentRotationIndex); Serial.println("E: Address gen fail."); displayErrorScreen(errorMessage); break;
                 }

                 // 2. Prerotated Hash: H(Pk(i+1)) - Use original single hash function
                 prerotated_pubkey_hash = hashPublicKey(key_prerotated.publicKey());
                 if (prerotated_pubkey_hash.startsWith("Hashing Error")) {
                     errorMessage = "Error Hashing Pk(i+1)"; Serial.println("E: " + errorMessage); displayErrorScreen(errorMessage); break;
                 }

                 // 3. Twice Prerotated Hash: H(H(Pk(i+2))) - **NEW LOGIC**
                 PublicKey pk_twice = key_twice_prerotated.publicKey();
                 String pk_twice_hex = pk_twice.toString();

                 if (pk_twice_hex.length() > 0 && pk_twice_hex.length() % 2 == 0) {
                     size_t pk_len = pk_twice_hex.length() / 2;
                     uint8_t* pk_bytes = (uint8_t*)malloc(pk_len); // Allocate buffer
                     if (!pk_bytes) {
                          errorMessage = "Mem Alloc H(H) Fail"; Serial.println("E: "+ errorMessage); displayErrorScreen(errorMessage); break;
                     }
                     bool conversion_ok = true;
                     // Convert hex string Pk(i+2) to bytes
                     for (size_t i = 0; i < pk_len; i++) {
                         unsigned int byteValue;
                         if (sscanf(pk_twice_hex.substring(i * 2, i * 2 + 2).c_str(), "%x", &byteValue) != 1) {
                             Serial.println("E: Hex conversion error for Pk(i+2) H(H)");
                             errorMessage = "Hex Conv Err H(H)"; conversion_ok = false; break;
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
                                 // Convert the final raw hash to hex string
                                 twice_prerotated_pubkey_hash = bytesToHex(second_hash, 32);
                             } else { Serial.println("E: Second SHA256 failed for H(H(Pk(i+2)))"); errorMessage = "Hashing Error (H2)"; }
                         } else { Serial.println("E: First SHA256 failed for H(H(Pk(i+2)))"); errorMessage = "Hashing Error (H1)"; }
                     }
                     free(pk_bytes); // Free allocated memory

                     // If H(H()) calculation failed, set error and break
                     if (twice_prerotated_pubkey_hash.length() == 0) {
                          if (errorMessage.length() == 0) errorMessage = "H(H) Calc Failed"; // Ensure error message exists
                          Serial.println("E: Failed to calculate H(H(Pk(i+2)))");
                          displayErrorScreen(errorMessage);
                          break; // Exit the wallet view processing
                     }
                 } else { // Invalid hex string for Pk(i+2)
                      errorMessage = "Invalid Pk(i+2) Hex"; Serial.println("E: "+ errorMessage); displayErrorScreen(errorMessage); break;
                 }
                 // --- End of H(H(Pk(i+2))) calculation ---

             } // Derived keys go out of scope

             // --- Display QR Codes ---
             // Ensure all data was successfully calculated before calling display
             if (current_address.length() > 0 && prerotated_pubkey_hash.length() > 0 && !prerotated_pubkey_hash.startsWith("Hashing Error") && twice_prerotated_pubkey_hash.length() > 0)
             {
                 displayRotationInfo(currentRotationIndex, current_address, prerotated_pubkey_hash, twice_prerotated_pubkey_hash);
             } else {
                 // If we got here, an error should have been displayed already
                 Serial.println("E: Data missing before display call, error should have been shown.");
                 if(currentState != STATE_ERROR) { // Defensive check
                    displayErrorScreen(errorMessage.length() > 0 ? errorMessage : "Display Data Error");
                 }
             }

             Serial.print("L: Heap Wallet Draw End: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
             redrawScreen = false; // Reset the flag as redraw is complete
        } // End if(walletNeedsRedraw)
        break; // End STATE_WALLET_VIEW
      } // End scope for STATE_WALLET_VIEW

    case STATE_SHOW_SECRET_MNEMONIC:
        displaySecretMnemonicScreen(loadedMnemonic); // Screen updates itself
        // Exit on ANY single button press (left OR right triggered), but NOT if both are held
        if ((buttonLeftTriggered || buttonRightTriggered) && !bothButtonsHeld) {
            Serial.println("L: Exiting secret mnemonic display.");
            currentState = STATE_WALLET_VIEW; // Go back to wallet view
            redrawScreen = true; // Request redraw of the wallet view screen
        }
        break; // End STATE_SHOW_SECRET_MNEMONIC

    case STATE_ERROR:
        // displayErrorScreen handles drawing. Wait for button press.
        if (buttonLeftTriggered || buttonRightTriggered) {
            Serial.println("L: Error acknowledged.");
            // Reset state to allow re-entry of PIN
            currentState = STATE_PASSWORD_ENTRY;
            currentDigitIndex = 0; currentDigitValue = 0; passwordConfirmed = false;
            memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0';
            kdp_as_int = 0;
            errorMessage = ""; // Clear error message
            redrawScreen = true; // Force redraw of password entry screen
            Serial.println("L: Set state STATE_PASSWORD_ENTRY.");
        }
        break; // End STATE_ERROR

    default:
        Serial.print("!!! E: Unknown state: "); Serial.println(currentState);
        errorMessage = "Internal State Error";
        displayErrorScreen(errorMessage); // This will change state to STATE_ERROR
        break; // End default case

  } // End of switch

  // --- Centralized Redraw Handling ---
  // This might be slightly redundant now, but keeps the original structure
  // Password Entry redraw is handled by its own redrawScreen flag checks
  if (redrawScreen && currentState == STATE_PASSWORD_ENTRY) {
        // Serial.println("Loop: Redrawing Password Entry Screen (centralized)."); // Debug
        showPasswordEntryScreen(); // Redraw if needed
        redrawScreen = false; // Reset flag here as it's handled now
  }
  // Wallet view handles its redraw internally via its own redraw flag
  else if (redrawScreen && currentState == STATE_WALLET_VIEW) {
        // Serial.println("Loop: Wallet view redraw flag cleared (handled internally)."); // Debug
        redrawScreen = false;
  }
  // Mnemonic screens redraw every loop anyway
  else if (redrawScreen && currentState == STATE_SHOW_GENERATED_MNEMONIC) {
        // Serial.println("Loop: Generated Mnemonic redraw flag cleared (handled internally)."); // Debug
        redrawScreen = false;
  } else if (redrawScreen && currentState == STATE_SHOW_SECRET_MNEMONIC) {
        // Serial.println("Loop: Secret Mnemonic redraw flag cleared (handled internally)."); // Debug
        redrawScreen = false;
  }

  delay(10); 
} // End of loop()
