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

// --- Button State (From Older Code) ---
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
// Crypto & Utility Functions (Unchanged)
// ========================================
String sha256Hex(const uint8_t* data, size_t len) {
  uint8_t hash[32]; mbedtls_sha256_context ctx; mbedtls_sha256_init(&ctx); mbedtls_sha256_starts(&ctx, 0); mbedtls_sha256_update(&ctx, data, len); mbedtls_sha256_finish(&ctx, hash); mbedtls_sha256_free(&ctx); String hex = ""; hex.reserve(64); for (int i = 0; i < 32; i++) { if (hash[i] < 0x10) hex += "0"; hex += String(hash[i], HEX); } return hex;
}
String hashPublicKey(const PublicKey& pubKey) {
    String pubKeyHex = pubKey.toString(); if (pubKeyHex.length() == 0) { Serial.println("E: Public Key string empty"); return "Hashing Error"; } size_t len = pubKeyHex.length() / 2; uint8_t pubKeyBytes[len]; for (size_t i = 0; i < len; i++) { unsigned int byteValue; if (sscanf(pubKeyHex.substring(i * 2, i * 2 + 2).c_str(), "%x", &byteValue) != 1) { Serial.println("E: Hex conversion error"); return "Hashing Error"; } pubKeyBytes[i] = (uint8_t)byteValue; } return sha256Hex(pubKeyBytes, len);
}
bool pinToInt(const char* pinStr, uint32_t& result) {
    char* endptr; long val = strtol(pinStr, &endptr, 10); if (endptr == pinStr || *endptr != '\0' || val < 0 || val > 0xFFFFFFFF) { return false; } result = (uint32_t)val; return true;
}
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

    // --- Define QR Code versions and ECC levels ---
    const int qrVersionAddr = 3; // Version 3 for Address
    const int qrVersionHash = 5; // Version 5 for Hashes
    const int eccLevel = ECC_MEDIUM;

    // --- Allocate Buffers and Initialize QR Codes ---
    QRCode qrAddr;
    uint8_t qrDataAddr[qrcode_getBufferSize(qrVersionAddr)];
    qrcode_initText(&qrAddr, qrDataAddr, qrVersionAddr, eccLevel, addr.c_str());

    QRCode qrHash1;
    uint8_t qrDataHash1[qrcode_getBufferSize(qrVersionHash)];
    qrcode_initText(&qrHash1, qrDataHash1, qrVersionHash, eccLevel, preHash.c_str());

    QRCode qrHash2;
    uint8_t qrDataHash2[qrcode_getBufferSize(qrVersionHash)];
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
    int startX = max(0, (displayWidth - totalQrWidth) / 2);
    int oxAddr = startX;
    int oxHash1 = startX + qrSizeAddr + gutter;
    int oxHash2 = startX + qrSizeAddr + gutter + qrSizeHash1 + gutter;
    int titleHeight = 12;
    int oy = titleHeight + 2;
    int maxQrHeight = max(qrSizeAddr, max(qrSizeHash1, qrSizeHash2));
    int qrBottom = oy + maxQrHeight;
    int labelGap = 4;
    int labelY = qrBottom + labelGap;
    int hintFontHeight = 6;
    int labelFontHeight = 6;
    int hintsY = displayHeight - 1;

    // --- Drawing Loop ---
    u8g2.firstPage();
    do {
        u8g2.setFont(u8g2_font_6x10_tr);
        String title = "Rotation: " + String(rIdx);
        int titleW = u8g2.getStrWidth(title.c_str());
        u8g2.drawStr(max(0, (displayWidth - titleW) / 2), 10, title.c_str());
        for (uint8_t y = 0; y < qrAddr.size; y++) { for (uint8_t x = 0; x < qrAddr.size; x++) { if (qrcode_getModule(&qrAddr, x, y)) { if (oxAddr + x * pixelSize < displayWidth) { u8g2.drawPixel(oxAddr + x * pixelSize, oy + y * pixelSize); } } } }
        for (uint8_t y = 0; y < qrHash1.size; y++) { for (uint8_t x = 0; x < qrHash1.size; x++) { if (qrcode_getModule(&qrHash1, x, y)) { if (oxHash1 + x * pixelSize < displayWidth) { u8g2.drawPixel(oxHash1 + x * pixelSize, oy + y * pixelSize); } } } }
        for (uint8_t y = 0; y < qrHash2.size; y++) { for (uint8_t x = 0; x < qrHash2.size; x++) { if (qrcode_getModule(&qrHash2, x, y)) { if (oxHash2 + x * pixelSize < displayWidth) { u8g2.drawPixel(oxHash2 + x * pixelSize, oy + y * pixelSize); } } } }
        if (labelY < (hintsY - hintFontHeight - labelFontHeight)) {
            u8g2.setFont(u8g2_font_4x6_tr);
            const char* lblAddr = "Addr"; const char* lblH1 = "H+1"; const char* lblH2 = "H+2";
            int lblAddrW = u8g2.getStrWidth(lblAddr); int lblH1W = u8g2.getStrWidth(lblH1); int lblH2W = u8g2.getStrWidth(lblH2);
            u8g2.drawStr(max(0, oxAddr + (qrSizeAddr - lblAddrW)/2), labelY + labelFontHeight - 1, lblAddr);
            u8g2.drawStr(max(0, oxHash1 + (qrSizeHash1 - lblH1W)/2), labelY + labelFontHeight - 1, lblH1);
            u8g2.drawStr(max(0, oxHash2 + (qrSizeHash2 - lblH2W)/2), labelY + labelFontHeight - 1, lblH2);
        } else { Serial.println("W: Not enough vertical space for QR labels."); }
        u8g2.setFont(u8g2_font_4x6_tr);
        u8g2.drawStr(2, hintsY, "< Prev Rot");
        const char* nextHint = "Next Rot >";
        u8g2.drawStr(displayWidth - u8g2.getStrWidth(nextHint) - 2, hintsY, nextHint);
    } while (u8g2.nextPage());

    Serial.println("----- Rotation Info (3 QRs) -----");
    Serial.println("Rotation Index: " + String(rIdx));
    Serial.println("QR 1 (Addr - V3): " + addr);
    Serial.println("QR 2 (H+1 - V5): " + preHash);
    Serial.println("QR 3 (H+2 - V5): " + twicePreHash);
    Serial.println("!! Displaying 3 separate QR codes. Scan individually. !!");
}

// Using current working showPasswordEntryScreen
void showPasswordEntryScreen() {
    u8g2.firstPage(); do { u8g2.setFont(u8g2_font_6x10_tr); const char* title = "Enter KDP PIN"; int titleW = u8g2.getStrWidth(title); u8g2.drawStr((u8g2.getDisplayWidth() - titleW) / 2, 10, title); int digitW = u8g2.getMaxCharWidth(); int spacing = 4; int totalW = PIN_LENGTH * digitW + (PIN_LENGTH - 1) * spacing; int startX = (u8g2.getDisplayWidth() - totalW) / 2; int digitY = 35; u8g2.setFont(u8g2_font_7x13B_tr); digitW = u8g2.getMaxCharWidth(); totalW = PIN_LENGTH * digitW + (PIN_LENGTH - 1) * spacing; startX = (u8g2.getDisplayWidth() - totalW) / 2; for (int i = 0; i < PIN_LENGTH; i++) { int currentX = startX + i * (digitW + spacing); char displayChar; if (i < currentDigitIndex) { displayChar = '*'; } else if (i == currentDigitIndex) { displayChar = currentDigitValue + '0'; } else { displayChar = '_'; } char tempStr[2] = {displayChar, '\0'}; int charOffsetX = (digitW - u8g2.getStrWidth(tempStr)) / 2; u8g2.drawStr(currentX + charOffsetX, digitY, tempStr); if (i == currentDigitIndex) { u8g2.drawHLine(currentX, digitY + 2, digitW); } } u8g2.setFont(u8g2_font_4x6_tr); u8g2.drawStr(2, u8g2.getDisplayHeight()-1, "< Cycle"); u8g2.drawStr(u8g2.getDisplayWidth() - u8g2.getStrWidth("Next/OK >") - 2, u8g2.getDisplayHeight()-1, "Next/OK >"); } while (u8g2.nextPage());
}

// ========================================
// Button Handling Function (From Older Code)
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

    // This was the separate check in the older code's loop, now integrated here
    if (buttonLeftPressed && buttonRightPressed) {
        bothButtonsHeld = true;
        // If we want 'both' to override single triggers entirely, uncomment below
        // buttonLeftTriggered = false;
        // buttonRightTriggered = false;
    }
}

// ========================================
// Setup Function (Using Current Working Version)
// ========================================
void setup() {
  Serial.begin(115200); while (!Serial && millis() < 2000); Serial.println("\n\n--- Yada Hardware Wallet ---"); Serial.print("Setup: Initial Free Heap: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT)); pinMode(buttonLeft, INPUT_PULLUP); pinMode(buttonRight, INPUT_PULLUP); Serial.println("Setup: Button pins configured."); u8g2.begin(); Serial.println("Setup: U8G2 Initialized."); u8g2.setContrast(100); u8g2.firstPage(); do { u8g2.setFont(u8g2_font_6x10_tr); u8g2.drawStr(10,30,"Initializing..."); } while (u8g2.nextPage()); Serial.println("Setup: 'Initializing...' sent to display."); memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0'; currentDigitIndex = 0; currentDigitValue = 0; passwordConfirmed = false; kdp_as_int = 0; Serial.println("Setup: Password state initialized."); bool provisioned = false; if (prefs.begin(PREFS_NAMESPACE, true)) { provisioned = prefs.getBool(PROVISIONED_KEY, false); prefs.end(); Serial.print("Setup: Provisioned flag read = "); Serial.println(provisioned); } else { Serial.println("W: Setup: Failed to open Prefs (RO). Assuming not provisioned."); } currentState = STATE_PASSWORD_ENTRY; Serial.println("Setup: Set initial state -> STATE_PASSWORD_ENTRY."); Serial.print("Setup: Free Heap Before Exit: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT)); Serial.println("Setup function finished.");
}

// ========================================
// Main Loop (Using Older Code's State Logic Structure)
// ========================================
void loop() {
  static bool firstLoop = true; bool redrawScreen = false;
  if (firstLoop) { redrawScreen = true; firstLoop = false; Serial.println("Loop: First iteration, forcing redraw."); }
  readButtons(); // Use the older readButtons function logic

  switch (currentState) {

    case STATE_INITIALIZING:
        Serial.println("W: Re-entered INITIALIZING state."); errorMessage = "Init Error"; displayErrorScreen(errorMessage); break;

    case STATE_SHOW_GENERATED_MNEMONIC:
        displayGeneratedMnemonicScreen(generatedMnemonic);
        if (buttonRightTriggered) {
            Serial.println("L: User confirmed backup."); Serial.println("L: Saving mnemonic & flag...");
            bool mnemonicSaved = false; bool flagSaved = false;
            if (prefs.begin(PREFS_NAMESPACE, false)) { if (prefs.putString(MNEMONIC_KEY, generatedMnemonic.c_str())) { Serial.println("L: Mnemonic saved ok."); mnemonicSaved = true; } else { Serial.println("!!! E: Failed to store mnemonic !!!"); } if(mnemonicSaved) { if(prefs.putBool(PROVISIONED_KEY, true)) { Serial.println("L: Provisioned flag saved ok."); flagSaved = true; } else { Serial.println("!!! E: Failed to store provisioned flag !!!"); } } prefs.end();
                if (mnemonicSaved && flagSaved) { loadedMnemonic = generatedMnemonic; generatedMnemonic = ""; Serial.println("L: Copied generated mnemonic to loadedMnemonic."); currentState = STATE_WALLET_VIEW; currentRotationIndex = 0; Serial.println("L: Save OK. Set state STATE_WALLET_VIEW."); redrawScreen = true; }
                else { errorMessage = "Failed to save keys!"; displayErrorScreen(errorMessage); }
            } else { Serial.println("!!! E: Failed to open Prefs for writing !!!"); errorMessage = "Storage Write Error!"; displayErrorScreen(errorMessage); }
        }
        break;

    case STATE_PASSWORD_ENTRY:
      // Redraw only if needed (digit cycle)
      if(redrawScreen) {
          showPasswordEntryScreen();
      }
      if (buttonLeftTriggered) { currentDigitValue = (currentDigitValue + 1) % 10; redrawScreen = true; }
      else if (buttonRightTriggered) {
        password[currentDigitIndex] = currentDigitValue + '0'; Serial.print("L: PIN Digit "); Serial.print(currentDigitIndex); Serial.println(" ok."); currentDigitIndex++;
        if (currentDigitIndex >= PIN_LENGTH) {
          password[PIN_LENGTH] = '\0'; Serial.println("L: Full PIN Entered.");
          if (!pinToInt(password, kdp_as_int)) { errorMessage = "Invalid PIN format."; Serial.println("E: PIN conversion failed."); displayErrorScreen(errorMessage); currentDigitIndex = 0; currentDigitValue = 0; memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0'; kdp_as_int = 0; } // Reset state on error
          else {
              passwordConfirmed = true; Serial.println("L: PIN Confirmed."); Serial.println("L: Attempting to load existing mnemonic..."); Serial.print("L: Heap Before Load/Gen: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
              bool loadAttempted = false; bool loadSuccess = false;
              if (prefs.begin(PREFS_NAMESPACE, true)) { loadAttempted = true; Serial.println("L: Prefs opened (RO)."); bool provisionedFlag = prefs.getBool(PROVISIONED_KEY, false); Serial.print("L: Provisioned flag read = "); Serial.println(provisionedFlag); if (provisionedFlag && prefs.isKey(MNEMONIC_KEY)) { loadedMnemonic = prefs.getString(MNEMONIC_KEY, ""); if (loadedMnemonic.length() > 10) { loadSuccess = true; Serial.println("L: Existing Mnemonic loaded ok."); } else { Serial.println("W: Provisioned flag set, but mnemonic empty/short!"); loadedMnemonic = ""; } } else if (provisionedFlag) { Serial.println("W: Provisioned flag set, but mnemonic key missing!"); } else { Serial.println("L: Not provisioned (flag missing/false). Should generate."); } prefs.end(); Serial.println("L: Prefs closed."); }
              else { Serial.println("!!! E: Failed to open Prefs (RO) for load !!!"); }
              if (loadSuccess) { currentState = STATE_WALLET_VIEW; currentRotationIndex = 0; Serial.print("L: KDP int: "); Serial.println(kdp_as_int); Serial.println("L: Set state STATE_WALLET_VIEW (from loaded)."); redrawScreen = true; }
              else { Serial.println("L: Load failed or first boot. Generating keys..."); uint8_t entropy[16]; esp_fill_random(entropy, sizeof(entropy)); Serial.print("L: Entropy for Gen: "); for(int i=0; i<sizeof(entropy); i++) { if(entropy[i]<0x10) Serial.print("0"); Serial.print(entropy[i], HEX); } Serial.println(); generatedMnemonic = generateMnemonicFromEntropy(entropy, sizeof(entropy)); if (generatedMnemonic.length() > 0) { Serial.println("L: Mnemonic generated ok (post-PIN)."); currentState = STATE_SHOW_GENERATED_MNEMONIC; Serial.println("L: Set state STATE_SHOW_GENERATED_MNEMONIC."); redrawScreen = true; } else { errorMessage = "Key Generation Failed!"; Serial.println("!!! E: Failed post-PIN mnemonic generation !!!"); displayErrorScreen(errorMessage); passwordConfirmed = false; currentDigitIndex = 0; currentDigitValue = 0; memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0'; kdp_as_int = 0; loadedMnemonic = ""; generatedMnemonic = ""; } }
              Serial.print("L: Heap After Load/Gen: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
          }
        } else { currentDigitValue = 0; redrawScreen = true; }
      }
      break;

    // *** Using Older Code's State Logic Structure ***
    case STATE_WALLET_VIEW: {
        // Use walletNeedsRedraw from older logic's trigger approach
        bool walletNeedsRedraw = redrawScreen; // Redraw if forced by state change

        // Check dual press first (using older logic's check order)
        if (bothButtonsHeld) {
            Serial.println("L: Both buttons detected, showing secret mnemonic.");
            currentState = STATE_SHOW_SECRET_MNEMONIC;
            redrawScreen = true; // Request redraw of secret screen
            break; // Exit case to prevent single button logic below
        }
        // Now check single button triggers
        if (buttonLeftTriggered) {
            if (currentRotationIndex > 0) { currentRotationIndex--; }
            else { currentRotationIndex = MAX_ROTATION_INDEX; } // Wrap around
            Serial.print("L: Rot idx: "); Serial.println(currentRotationIndex);
            walletNeedsRedraw = true;
        } else if (buttonRightTriggered) {
            currentRotationIndex = (currentRotationIndex + 1) % (MAX_ROTATION_INDEX + 1); // Wrap around
            Serial.print("L: Rot idx: "); Serial.println(currentRotationIndex);
            walletNeedsRedraw = true;
        }

        // Perform calculations and draw if needed
        if (walletNeedsRedraw) {
             Serial.print("L: Redraw Wallet R"); Serial.println(currentRotationIndex); Serial.print("L: Heap Wallet Draw Start: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
             if (loadedMnemonic.length() == 0) { errorMessage = "Mnemonic Missing!"; Serial.println("E: loadedMnemonic empty!"); displayErrorScreen(errorMessage); break; }
             password[PIN_LENGTH] = '\0'; // Ensure null-terminated
             HDPrivateKey hdMasterKey(loadedMnemonic, password, &Mainnet); if (!hdMasterKey.isValid()) { errorMessage = "Invalid PIN/Mnemonic!"; Serial.println("E: Master Key Init Fail."); displayErrorScreen(errorMessage); break; }

             String basePath = "m/83696968'/39'/" + String(kdp_as_int) + "'";
             String path_current = basePath + "/" + String(currentRotationIndex) + "'";
             String path_prerotated = basePath + "/" + String(currentRotationIndex + 1) + "'";
             String path_twice_prerotated = basePath + "/" + String(currentRotationIndex + 2) + "'";
             { // Scope for derived keys
                 HDPrivateKey key_current = hdMasterKey.derive(path_current.c_str());
                 HDPrivateKey key_prerotated = hdMasterKey.derive(path_prerotated.c_str());
                 HDPrivateKey key_twice_prerotated = hdMasterKey.derive(path_twice_prerotated.c_str());
                 if (!key_current.isValid() || !key_prerotated.isValid() || !key_twice_prerotated.isValid()) { errorMessage = "Key derivation fail R" + String(currentRotationIndex); Serial.println("E: Key derive fail."); displayErrorScreen(errorMessage); break; }

                 // Get the data components
                 String current_address = key_current.publicKey().address();
                 String prerotated_pubkey_hash = hashPublicKey(key_prerotated.publicKey());
                 String twice_prerotated_pubkey_hash = hashPublicKey(key_twice_prerotated.publicKey());

                 // *** MERGE: Call the 3-QR display function with correct args ***
                 // NOTE: The 'current_wif' variable from older code is not used here
                 displayRotationInfo(currentRotationIndex, current_address, prerotated_pubkey_hash, twice_prerotated_pubkey_hash);

             } // Derived keys go out of scope
             Serial.print("L: Heap Wallet Draw End: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
        }
        break; // End STATE_WALLET_VIEW
      }

    // *** Using Older Code's State Logic Structure ***
    case STATE_SHOW_SECRET_MNEMONIC:
        displaySecretMnemonicScreen(loadedMnemonic);
        // Exit on ANY single button press (left OR right triggered, but not bothHeld)
        if (buttonLeftTriggered || buttonRightTriggered) {
            Serial.println("L: Exiting secret mnemonic display.");
            currentState = STATE_WALLET_VIEW; // Go back to wallet view
            redrawScreen = true; // Request redraw of the wallet view screen
        }
        break;

    case STATE_ERROR:
        if (buttonLeftTriggered || buttonRightTriggered) { Serial.println("L: Error acknowledged."); currentState = STATE_PASSWORD_ENTRY; currentDigitIndex = 0; currentDigitValue = 0; passwordConfirmed = false; memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0'; kdp_as_int = 0; redrawScreen = true; Serial.println("L: Set state STATE_PASSWORD_ENTRY."); }
        break;

    default:
        Serial.print("!!! E: Unknown state: "); Serial.println(currentState); errorMessage = "Internal State Error"; displayErrorScreen(errorMessage); break;

  } // End of switch

  // --- Centralized Redraw Handling (From Older Code) ---
  if (redrawScreen && currentState == STATE_PASSWORD_ENTRY) { Serial.println("Loop: Redrawing Password Entry Screen (centralized)."); showPasswordEntryScreen(); redrawScreen = false; }
  else if (redrawScreen && currentState == STATE_WALLET_VIEW) { redrawScreen = false; } // Wallet view handles its redraw on entry or button press
  else if (redrawScreen && currentState == STATE_SHOW_GENERATED_MNEMONIC) { redrawScreen = false; } // Display fn draws every loop
  else if (redrawScreen && currentState == STATE_SHOW_SECRET_MNEMONIC) { redrawScreen = false; } // Display fn draws every loop

  delay(10); // Keep original delay
} // End of loop()
