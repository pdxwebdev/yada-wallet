#include <Arduino.h>
#include <Bitcoin.h>          // https://github.com/micro-bitcoin/uBitcoin
#include <Networks.h>         // Part of the Bitcoin library
#include <Preferences.h>      // Built-in ESP32 library
#include <QRCodeGenerator.h>  // https://github.com/Tomstark/QRCodeGenerator
#include "bip39_wordlist.h"   // Needs to be included (Make sure this file exists in your project)
#include <BigNumber.h> // https://github.com/nickgammon/BigNumber download and load the zip file as a library

#include <mbedtls/sha256.h>
#include <esp_system.h>
#include "esp_heap_caps.h"
#include <stdint.h>        // For uint32_t
#include <arpa/inet.h>     // For ntohl (Network to Host Long for endianness handling)
#include <string.h>        // For memcpy

// --- TFT & Touch Libraries ---
#include <SPI.h>
#include <TFT_eSPI.h>         // Use TFT_eSPI library
#include <XPT2046_Touchscreen.h> // Touch screen library

// --- Pin Definitions ---
#ifndef TFT_BL
  #define TFT_BL 21
#endif
#ifndef TFT_BACKLIGHT_ON
  #define TFT_BACKLIGHT_ON HIGH
#endif
#define TOUCH_CS   33
#define TOUCH_IRQ  36
#define TOUCH_SCK  25
#define TOUCH_MISO 39
#define TOUCH_MOSI 32

// --- Display & Touch Setup ---
TFT_eSPI tft = TFT_eSPI();
SPIClass touchSPI(VSPI);
XPT2046_Touchscreen ts(TOUCH_CS, TOUCH_IRQ);

// --- On-Screen Buttons ---
#define MAX_BUTTONS 5
TFT_eSPI_Button buttons[MAX_BUTTONS];
#define BUTTON_H 50 // Increased Height
#define BUTTON_W 100
#define SECRET_BUTTON_SIZE 35
#define BUTTON_SPACING_X 10
#define BUTTON_SPACING_Y 10

// Define button IDs (Based on HORIZONTAL layout + Secret)
#define BTN_LEFT   0 // Cycle/Back/Prev/OK (Bottom Left drawn -> Touch X=65, Y=205)
#define BTN_RIGHT  1 // Next/Confirm (Bottom Right drawn -> Touch X=35, Y=45) // Note: touch mapping for this is TOP-LEFT in main loop
#define BTN_SECRET 2 // Show Secret Mnemonic (Top Right Drawn -> Touch X=300, Y=20)
#define BTN_OK     0
#define BTN_BACK   0
#define BTN_CYCLE  0
#define BTN_NEXT   1
#define BTN_CONFIRM 1

// --- Preferences ---
Preferences prefs;
const char* PREFS_NAMESPACE = "yada-wallet";
const char* MNEMONIC_KEY = "mnemonic";
const char* PROVISIONED_KEY = "provisioned";

// --- Button State ---
bool buttonLeftTriggered = false;
bool buttonRightTriggered = false;
bool buttonSecretTriggered = false;
unsigned long touchHoldStartTime = 0;
bool touchIsBeingHeld = false;

// --- State Variables ---
enum AppState { STATE_INITIALIZING, STATE_SHOW_GENERATED_MNEMONIC, STATE_PASSWORD_ENTRY, STATE_WALLET_VIEW, STATE_SHOW_SECRET_MNEMONIC, STATE_ERROR };
AppState currentState = STATE_INITIALIZING;
String errorMessage = "";
String generatedMnemonic = "";
String loadedMnemonic = "";
HDPrivateKey hdWalletKey; // Stores m/0'/index0'/index1'/index2'/index3' (PR Change)
String baseWalletPath;    // Stores m/0'/index0'/index1'/index2'/index3' (PR Change)


// --- Password Entry State ---
const uint32_t MODULO_2_31 = 2147483647; // 2^31
const int PIN_LENGTH = 6;
char password[PIN_LENGTH + 1];
int currentDigitIndex = 0;
int currentDigitValue = 0;
bool passwordConfirmed = false;

// --- Wallet View State ---
int currentRotationIndex = 0;
const int MAX_ROTATION_INDEX = 1000; // Max address index m/0/MAX_ROTATION_INDEX

// ========================================
// Crypto & Utility Functions
// ========================================
String sha256Hex(const uint8_t* data, size_t len) { uint8_t h[32]; mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c,0); mbedtls_sha256_update(&c,data,len); mbedtls_sha256_finish(&c,h); mbedtls_sha256_free(&c); String s=""; s.reserve(64); for(int i=0;i<32;i++){if(h[i]<0x10)s+="0"; s+=String(h[i],HEX);} return s; }
String hashPublicKey(const PublicKey& pk) { String h=pk.toString(); if(h.length()==0) return "Hashing Error"; if(h.length()!=66&&h.length()!=130) Serial.printf("W: Bad Pk len: %d\n",h.length()); size_t l=h.length()/2; if(l==0) return "Hashing Error"; uint8_t* b=(uint8_t*)malloc(l); if(!b) return "Hashing Error"; for(size_t i=0;i<l;i++){unsigned int v; if((i*2+1)>=h.length()||sscanf(h.substring(i*2,i*2+2).c_str(),"%x",&v)!=1){free(b);return"Hashing Error";}b[i]=(uint8_t)v;} String r=sha256Hex(b,l); free(b); return r; }
bool sha256Raw(const uint8_t* d, size_t l, uint8_t o[32]){mbedtls_sha256_context c;mbedtls_sha256_init(&c);if(mbedtls_sha256_starts(&c,0)!=0){mbedtls_sha256_free(&c);return false;}if(mbedtls_sha256_update(&c,d,l)!=0){mbedtls_sha256_free(&c);return false;}if(mbedtls_sha256_finish(&c,o)!=0){mbedtls_sha256_free(&c);return false;}mbedtls_sha256_free(&c);return true;}
String bytesToHex(const uint8_t* b, size_t l){String s="";s.reserve(l*2);for(size_t i=0;i<l;i++){if(b[i]<0x10)s+="0";s+=String(b[i],HEX);}return s;}

// Function to convert a single hex character to its decimal value
int hexCharToDec(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return -1; // Invalid character
}

// Function to convert a hexadecimal string to a BigNumber
BigNumber hexToBigNumber(const char* hex) {
    BigNumber result = 0;
    for (const char* p = hex; *p != '\0'; ++p) {
        int digit = hexCharToDec(*p);
        if (digit < 0) {
            // Handle invalid character (optional, assume valid for SHA256)
            continue;
        }
        result *= 16;
        result += digit;
    }
    return result;
}

// Derive index using BigNumber to handle 256-bit arithmetic
uint32_t deriveIndex(String factor, int level) {
    // Initialize BigNumber library
    BigNumber::begin();

    // Construct input string (e.g., "0000000")
    String combined = factor + String(level);
    
    // Compute SHA-256 hash
    unsigned char hash[32];
    mbedtls_sha256((const unsigned char*)combined.c_str(), combined.length(), hash, 0);

    // Convert hash to hex string
    char hex[65]; // 64 characters + null terminator
    for (int i = 0; i < 32; i++) {
        sprintf(&hex[i * 2], "%02x", hash[i]);
    }

    Serial.print("SHA256 hash: ");
    Serial.println(hex);

    // Convert hex to BigNumber
    BigNumber bigNumber = hexToBigNumber(hex);
    // Debug: Print the index
    Serial.print("bigNumber: ");
    Serial.println(bigNumber);
    
    // Compute modulo 2^31 - 1
    BigNumber modulo(MODULO_2_31);
    BigNumber remainder = bigNumber % modulo;

    // Debug: Print the index
    Serial.print("deriveIndex index: ");
    Serial.println(remainder);
    
    // Clean up BigNumber library
    BigNumber::finish();
    
    return remainder;
}

// Derive hardened key using uBitcoin
HDPrivateKey deriveHardened(HDPrivateKey root, uint32_t index) {
    // Construct hardened path (e.g., "0'")
    String path = String(index) + "'";
    
    // Derive hardened key
    HDPrivateKey key = root.derive(path.c_str());
    
    // Validate key
    bool isValid = key.isValid();
    if (!isValid) {
        String errorMessage = "hdWallet Key Invalid (" + path + ")";
        Serial.println(errorMessage); // Replace with displayErrorScreen
        passwordConfirmed = false;
        currentDigitIndex = 0;
        currentDigitValue = 0;
        memset(password, '_', PIN_LENGTH);
        password[PIN_LENGTH] = '\0';
    }
    
    Serial.print("L: root derived: ");
    Serial.println(path);
    
    return key;
}

// Derive secure path (returns HDPrivateKey)
HDPrivateKey deriveSecurePath(HDPrivateKey root, String secondFactor) {
    HDPrivateKey currentNode = root;
    for (int level = 0; level < 4; level++) {
        uint32_t index = deriveIndex(secondFactor, level);
        currentNode = deriveHardened(currentNode, index);
    }
    return currentNode;
}

String generateMnemonicFromEntropy(const uint8_t* e, size_t len){if(len!=16)return""; uint8_t cs_len=(len*8)/32; uint8_t h[32]; mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c,0); mbedtls_sha256_update(&c,e,len); mbedtls_sha256_finish(&c,h); mbedtls_sha256_free(&c); uint8_t cs_byte=h[0]; uint8_t mask=0xFF<<(8-cs_len); uint8_t cs_bits=cs_byte&mask; int total_bits=(len*8)+cs_len; int num_words=total_bits/11; String m=""; m.reserve(120); uint16_t w_idx=0; int bit_count=0; for(int i=0;i<total_bits;i++){int byte_idx=i/8; int bit_in_byte=7-(i%8); uint8_t curr_byte; if(byte_idx<len){curr_byte=e[byte_idx];}else{int cs_bit_idx=i-(len*8); int shift=7-cs_bit_idx; curr_byte=cs_bits; bit_in_byte=shift;} uint8_t bit_val=(curr_byte>>bit_in_byte)&1; w_idx=(w_idx<<1)|bit_val; bit_count++; if(bit_count==11){if(w_idx>=2048)return""; m+=String(wordlist[w_idx]); if((i+1)<total_bits)m+=" "; w_idx=0; bit_count=0;}} return m;}

// ========================================
// Display Functions (using TFT_eSPI - FINAL Button Definitions)
// ========================================
void drawButtons(int numButtons) { for(int i=0;i<numButtons;i++) buttons[i].drawButton(); }

void displayErrorScreen(String msg) {
    tft.fillScreen(TFT_RED); tft.setTextColor(TFT_WHITE,TFT_RED); tft.setTextDatum(MC_DATUM);
    tft.setTextSize(2); tft.drawString("ERROR", tft.width()/2, 30);
    tft.drawFastHLine(10,50,tft.width()-20,TFT_WHITE); tft.setTextDatum(TL_DATUM);
    tft.setTextSize(1); tft.setCursor(10,65); int maxC=(tft.width()-20)/6; String cL="";
    for(int i=0;i<msg.length();i++){cL+=msg[i]; if((msg[i]==' '&&cL.length()>=maxC)||cL.length()>maxC+10){int wP=-1; if(msg[i]!=' '){for(int j=cL.length()-1;j>=0;j--) if(cL[j]==' '){wP=j;break;}} if(wP!=-1){tft.println(cL.substring(0,wP)); cL=cL.substring(wP+1);} else{tft.println(cL); cL="";} tft.setCursor(10,tft.getCursorY()); if(tft.getCursorY()>tft.height()-BUTTON_H-30){tft.print("...");break;}}} if(cL.length()>0)tft.println(cL);
    buttons[BTN_OK].initButton(&tft, 65, 205, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_DARKGREY, TFT_BLACK, "OK", 2); // Triggered by Bottom-Left Touch
    drawButtons(1); currentState=STATE_ERROR;
}

void displayGeneratedMnemonicScreen(String m) {
    tft.fillScreen(TFT_BLACK); tft.setTextColor(TFT_YELLOW,TFT_BLACK); tft.setTextDatum(MC_DATUM);
    tft.setTextSize(2); tft.drawString("BACKUP MNEMONIC!",tft.width()/2, 20);
    tft.drawFastHLine(10,35,tft.width()-20,TFT_YELLOW); tft.setTextColor(TFT_WHITE,TFT_BLACK);
    tft.setTextDatum(TL_DATUM); tft.setTextSize(1); tft.setTextFont(2);
    int wc=0; String cw=""; String tM=m+" "; int xS=15, yS=55, cW=tft.width()/3-5, lH=tft.fontHeight(2)+3; int xP=xS, yP=yS;
    for(int i=0;i<tM.length();i++){char c=tM.charAt(i); if(c==' '){if(cw.length()>0){wc++; String wn=String(wc)+"."; tft.setTextColor(TFT_CYAN); tft.drawString(wn,xP,yP); tft.setTextColor(TFT_WHITE); tft.drawString(cw,xP+tft.textWidth("XX."),yP); cw=""; yP+=lH; if(wc%4==0){xP+=cW; yP=yS;} if(wc>=12)break;}} else cw+=c;}
    int confirmButtonCenterX = 255; // Bottom Right X (drawing coordinates)
    int confirmButtonCenterY = 205; // Bottom Right Y (drawing coordinates)
    buttons[BTN_CONFIRM].initButton(&tft, confirmButtonCenterX, confirmButtonCenterY, BUTTON_W+40, BUTTON_H, TFT_WHITE, TFT_GREEN, TFT_BLACK, "Backed Up", 2);
    buttons[BTN_CONFIRM].drawButton();
}


void displaySecretMnemonicScreen(String m) {
    tft.fillScreen(TFT_BLACK); tft.setTextColor(TFT_ORANGE,TFT_BLACK); tft.setTextDatum(MC_DATUM);
    tft.setTextSize(2); tft.drawString("Root Mnemonic",tft.width()/2, 20);
    tft.drawFastHLine(10,35,tft.width()-20,TFT_ORANGE); tft.setTextColor(TFT_WHITE,TFT_BLACK);
    tft.setTextDatum(TL_DATUM); tft.setTextSize(1); tft.setTextFont(2);
    int wc=0; String cw=""; String tM=m+" "; int xS=15, yS=55, cW=tft.width()/3-5, lH=tft.fontHeight(2)+3; int xP=xS, yP=yS;
    for(int i=0;i<tM.length();i++){char c=tM.charAt(i); if(c==' '){if(cw.length()>0){wc++; String wn=String(wc)+"."; tft.setTextColor(TFT_CYAN); tft.drawString(wn,xP,yP); tft.setTextColor(TFT_WHITE); tft.drawString(cw,xP+tft.textWidth("XX."),yP); cw=""; yP+=lH; if(wc%4==0){xP+=cW; yP=yS;} if(wc>=12)break;}} else cw+=c;}
    buttons[BTN_BACK].initButton(&tft, 65, 205, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Back", 2); // Triggered by Bottom-Left Touch
    drawButtons(1);
}

void showPasswordEntryScreen() {
    tft.fillScreen(TFT_DARKCYAN); tft.setTextColor(TFT_WHITE, TFT_DARKCYAN);
    tft.setTextDatum(MC_DATUM); tft.setTextSize(2);
    tft.drawString("Enter Wallet PIN", tft.width()/2, 30);
    int digitBoxSize = 25; int spacing = 8;
    int totalW = PIN_LENGTH * digitBoxSize + (PIN_LENGTH - 1) * spacing;
    int startX = (tft.width()-totalW)/2; int digitY = 80;
    tft.setTextSize(2); tft.setTextDatum(MC_DATUM);
    for (int i = 0; i < PIN_LENGTH; i++) {
        int currentX = startX + i * (digitBoxSize + spacing);
        uint16_t boxColor = (i == currentDigitIndex) ? TFT_YELLOW : TFT_WHITE;
        tft.drawRect(currentX, digitY, digitBoxSize, digitBoxSize, boxColor);
        char displayChar;
        if (i < currentDigitIndex) { displayChar = '*'; }
        else if (i == currentDigitIndex) { displayChar = currentDigitValue + '0'; }
        else { displayChar = '_'; }
        char tempStr[2] = {displayChar, '\0'};
        tft.drawString(tempStr, currentX + digitBoxSize / 2, digitY + digitBoxSize / 2 + 2);
    }
    char nextLabel[5] = "Next"; if (currentDigitIndex == PIN_LENGTH - 1) { strcpy(nextLabel, "OK"); }

    int leftButtonCenterX = 65;     // Bottom Left X (drawing coordinates)
    int leftButtonCenterY = 205;    // Bottom Left Y (drawing coordinates)
    int rightButtonCenterX = 255;   // Bottom Right X (drawing coordinates)
    int rightButtonCenterY = 205;   // Bottom Right Y (drawing coordinates)

    buttons[BTN_CYCLE].initButton(&tft, leftButtonCenterX, leftButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Cycle", 2);
    buttons[BTN_NEXT].initButton(&tft, rightButtonCenterX, rightButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_GREEN, TFT_BLACK, nextLabel, 2);
    drawButtons(2);
}

// --- Display Single QR Code (Combined Data + Maximized Size + FINAL Buttons + Secret Button) ---
void displaySingleRotationQR(int rIdx, const String& combinedQRData, const String& label, int qrVersion) {
    if(combinedQRData.length() == 0){ displayErrorScreen("QR Gen Error (Empty)"); return; }
    const int eccLevel = ECC_LOW;
    QRCode qr;
    size_t bufferSize = qrcode_getBufferSize(qrVersion);
    if (bufferSize == 0 || bufferSize > 3500) { // uBitcoin QR Code Buffer Size limit might be different, check library for actual limits if issues persist
        Serial.printf("E: QR Buffer Size Error V%d, Size: %u\n", qrVersion, bufferSize);
        displayErrorScreen("QR Buffer Size Error V" + String(qrVersion));
        return;
    }
    uint8_t *qrDataBuffer = (uint8_t *)malloc(bufferSize);
    if (!qrDataBuffer) { displayErrorScreen("QR Buffer Alloc Fail"); return; }

    if (qrcode_initText(&qr, qrDataBuffer, qrVersion, eccLevel, combinedQRData.c_str()) != 0) {
        Serial.printf("E: QR Init Fail V%d L=%d %s\n",qrVersion, combinedQRData.length(), label.c_str());
        int nextVersion = qrVersion + 1;
        if(nextVersion <= 13) { // Max typical QR for this display size/complexity
            Serial.println("Trying V"+String(nextVersion));
            free(qrDataBuffer);
            displaySingleRotationQR(rIdx, combinedQRData, label, nextVersion); // Recursive call with higher version
            return;
        } else {
            free(qrDataBuffer);
            displayErrorScreen("QR Init Failed V" + String(qrVersion));
            return;
        }
    }

    tft.fillScreen(TFT_WHITE);
    tft.setTextColor(TFT_BLACK, TFT_WHITE);

    int topMargin = 2;
    int titleHeight = 18;
    int bottomMargin = 2;
    int buttonAreaHeight = BUTTON_H + BUTTON_SPACING_Y;
    int sideMargin = 4;

    int availableHeight = tft.height() - topMargin - titleHeight - bottomMargin - buttonAreaHeight;
    int availableWidth = tft.width() - 2 * sideMargin;

    int pixelSize = 1;
    if (qr.size > 0) {
        int pixelSizeW = availableWidth / qr.size;
        int pixelSizeH = availableHeight / qr.size;
        pixelSize = min(pixelSizeW, pixelSizeH);
        if (pixelSize < 1) pixelSize = 1;
        pixelSize = min(pixelSize, 3); // Cap pixel size to prevent overly large QR
    }

    int qrDrawSize = qr.size * pixelSize;
    int startX = sideMargin + (availableWidth - qrDrawSize) / 2;
    int startY = topMargin + titleHeight + (availableHeight - qrDrawSize) / 2;

    tft.setTextDatum(TC_DATUM);
    tft.setTextSize(1);
    String tit = label + ": " + String(rIdx); // Changed label order
    tft.drawString(tit, tft.width()/2, topMargin, 2);

    for (uint8_t y = 0; y < qr.size; y++) {
        for (uint8_t x = 0; x < qr.size; x++) {
            if (qrcode_getModule(&qr, x, y)) {
                if (pixelSize == 1) tft.drawPixel(startX + x, startY + y, TFT_BLACK);
                else tft.fillRect(startX + x * pixelSize, startY + y * pixelSize, pixelSize, pixelSize, TFT_BLACK);
            }
        }
    }

    int leftButtonCenterX = 65;     // Bottom Left X (drawing coordinates)
    int leftButtonCenterY = 205;    // Bottom Left Y (drawing coordinates)
    int rightButtonCenterX = 255;   // Bottom Right X (drawing coordinates)
    int rightButtonCenterY = 205;   // Bottom Right Y (drawing coordinates)
    int secretButtonCenterX = tft.width() - (SECRET_BUTTON_SIZE / 2) - 5; // Top Right X
    int secretButtonCenterY = (SECRET_BUTTON_SIZE / 2) + 5;               // Top Right Y

    buttons[BTN_LEFT].initButton(&tft, leftButtonCenterX, leftButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "< Prev", 2);
    buttons[BTN_RIGHT].initButton(&tft, rightButtonCenterX, rightButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Next >", 2);
    buttons[BTN_SECRET].initButton(&tft, secretButtonCenterX, secretButtonCenterY, SECRET_BUTTON_SIZE, SECRET_BUTTON_SIZE, TFT_WHITE, TFT_ORANGE, TFT_BLACK, "...", 1);
    drawButtons(3);
    free(qrDataBuffer);
 }


// ========================================
// Touch Button Handling Function
// ========================================
void readButtons() {
    uint16_t t_x = 0, t_y = 0;
    static bool wasLeftPressedState = false;
    static bool wasRightPressedState = false;
    static bool wasSecretPressedState = false;

    buttonLeftTriggered = false;
    buttonRightTriggered = false;
    buttonSecretTriggered = false;

    bool pressed = ts.tirqTouched() && ts.touched();
    bool currentLeftContainsManual = false;
    bool currentRightContainsManual = false;
    bool currentSecretContainsManual = false;

    if (pressed) {
        TS_Point p = ts.getPoint();
        // Rotation 3, Inverted X, Inverted Y from observed values
        t_x = map(p.y, 338, 3739, tft.width(), 0);
        t_y = map(p.x, 414, 3857, tft.height(), 0);

        if (!touchIsBeingHeld) {
            touchIsBeingHeld = true; touchHoldStartTime = millis();
        }

        // --- MANUAL BOUNDS CHECK based on observed touch coordinates for Rot 3 ---
        // These are the *actual touch coordinates* after mapping
        // Bottom-Left Area (BTN_LEFT: Cycle/Prev/Back/OK)
        int leftBtnL = 15; int leftBtnR = 115; int leftBtnT = 180; int leftBtnB = 230;
        if (t_x >= leftBtnL && t_x <= leftBtnR && t_y >= leftBtnT && t_y <= leftBtnB) {
             currentLeftContainsManual = true;
        }

        // Top-Left Area (BTN_RIGHT: Next/Confirm) - THIS IS AN IMPORTANT MAPPING.
        // The button is *drawn* bottom-right on some screens, but this touch area corresponds to it.
        int rightBtnL = -15; int rightBtnR = 85; int rightBtnT = 20; int rightBtnB = 70;
         if (t_x >= rightBtnL && t_x <= rightBtnR && t_y >= rightBtnT && t_y <= rightBtnB) {
             currentRightContainsManual = true;
        }

        // Top-Right Area (BTN_SECRET)
        int secretBtnL = 282; int secretBtnR = 318; int secretBtnT = 2; int secretBtnB = 38;
        if (t_x >= secretBtnL && t_x <= secretBtnR && t_y >= secretBtnT && t_y <= secretBtnB) {
            currentSecretContainsManual = true;
        }
    } else { // Not pressed (Touch Released)
        if (touchIsBeingHeld) {
             touchIsBeingHeld = false;
             if (wasLeftPressedState && !currentLeftContainsManual) { buttonLeftTriggered = true; }
             if (wasRightPressedState && !currentRightContainsManual) { buttonRightTriggered = true; }
             if (wasSecretPressedState && !currentSecretContainsManual) { buttonSecretTriggered = true; }
        }
    }
    wasLeftPressedState = currentLeftContainsManual;
    wasRightPressedState = currentRightContainsManual;
    wasSecretPressedState = currentSecretContainsManual;
}


// ========================================
// Setup Function
// ========================================
void setup() {
  Serial.begin(115200); while (!Serial && millis() < 2000);
  Serial.println("\n\n--- Yada HW (TFT+Touch - PR #1 Applied) ---");
  Serial.print("Setup: Init Heap: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));

  pinMode(TOUCH_IRQ, INPUT);

  tft.init();
  tft.setRotation(3); // USING ROTATION 3
  tft.fillScreen(TFT_BLACK);
  Serial.println("Setup: TFT OK (Rotation 3).");

  Serial.println("Setup: Init Touch SPI (VSPI)...");
  touchSPI.begin(TOUCH_SCK, TOUCH_MISO, TOUCH_MOSI, TOUCH_CS);
  ts.begin(touchSPI);
  ts.setRotation(tft.getRotation()); // Match touch rotation to TFT
  Serial.println("Setup: Touch OK (Rotation 3).");

  pinMode(TFT_BL, OUTPUT); digitalWrite(TFT_BL, TFT_BACKLIGHT_ON); Serial.println("Setup: BL OK.");
  tft.setTextColor(TFT_WHITE, TFT_BLACK); tft.setTextDatum(MC_DATUM); tft.drawString("Initializing...", tft.width() / 2, tft.height() / 2, 4);
  Serial.println("Setup: Init Msg OK."); delay(1000);

  memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0';
  currentDigitIndex = 0; currentDigitValue = 0; passwordConfirmed = false;
  Serial.println("Setup: Pwd State OK.");

  if (!prefs.begin(PREFS_NAMESPACE, false)) {
    Serial.println("W: Prefs RW Fail. Trying RO...");
    if (!prefs.begin(PREFS_NAMESPACE, true)) {
      Serial.println("E: Prefs RO Fail!");
      tft.fillScreen(TFT_RED); tft.setTextColor(TFT_WHITE);
      tft.drawString("Storage Error!", tft.width()/2, tft.height()/2, 2);
      while(1);
    } else {
      Serial.println("Setup: Prefs RO OK (initial RO fail).");
      prefs.end(); // End RO mode if it was only for checking
    }
  } else {
    Serial.println("Setup: Prefs RW OK.");
    prefs.end(); // End RW mode after check
  }

  bool prv = false;
  if (prefs.begin(PREFS_NAMESPACE, true)) { // Re-open as RO for reading provisioned status
    prv = prefs.getBool(PROVISIONED_KEY, false);
    prefs.end();
    Serial.print("Setup: Provisioned = "); Serial.println(prv);
  } else {
    Serial.println("W: Prefs RO Fail for provisioned check.");
  }

  currentState = STATE_PASSWORD_ENTRY;
  Serial.println("Setup: Init state -> PWD.");
  Serial.print("Setup: Exit Heap: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
  Serial.println("Setup OK.");
}


// ========================================
// Main Loop
// ========================================
void loop() {
  static bool firstLoop = true;
  static AppState lastState = STATE_INITIALIZING;
  bool redrawScreen = false;

  if (currentState != lastState) {
    redrawScreen = true;
    lastState = currentState;
    buttonLeftTriggered = false;
    buttonRightTriggered = false;
    buttonSecretTriggered = false;
    touchIsBeingHeld = false;
  }
  if (firstLoop) {
    redrawScreen = true;
    firstLoop = false;
  }

  readButtons();

  switch (currentState) {
    case STATE_INITIALIZING:
      Serial.println("W: Init Loop reached. Should not happen.");
      errorMessage="Init Loop Error";
      displayErrorScreen(errorMessage);
      break;

    case STATE_SHOW_GENERATED_MNEMONIC:
      if(redrawScreen) displayGeneratedMnemonicScreen(generatedMnemonic);
      if(buttonRightTriggered){
        Serial.println("L: Mnem Confirm.");
        bool sM=false,sF=false;
        if(prefs.begin(PREFS_NAMESPACE,false)){
          if(prefs.putString(MNEMONIC_KEY,generatedMnemonic.c_str())){sM=true;}
          if(sM && prefs.putBool(PROVISIONED_KEY,true)){sF=true;}
          prefs.end();
        } else {
          errorMessage="Store Write Err!"; displayErrorScreen(errorMessage); break;
        }
        if(sM && sF){
          loadedMnemonic=generatedMnemonic;
          generatedMnemonic="";
          // After saving a newly generated mnemonic, we need to derive hdWalletKey and baseWalletPath
          // This logic is similar to the 'ldOK' case in STATE_PASSWORD_ENTRY
          // but uses the just-saved loadedMnemonic and current password.
          // This assumes the password was confirmed *before* showing generated mnemonic,
          // which isn't the current flow.
          // The PR implies hdWalletKey is set up *after* PIN confirmation when ldOK is true.
          // For newly generated mnemonic, this setup happens when user re-enters PIN.
          // For now, simply transition to wallet view, PIN will be re-confirmed and keys derived.
          // OR, better, transition back to password entry to force re-entry and key derivation.
          // The PR's logic in password entry handles derivation for ldOK=true (now that it's saved).
          // So, let's go back to password entry to ensure consistency.

          // currentState=STATE_WALLET_VIEW; // Old logic
          // currentRotationIndex=0;
          // Serial.println("L: Saved OK -> Wallet View");

          // New logic: Go back to password entry, which will now load the mnemonic and derive keys.
          Serial.println("L: Saved OK -> Re-enter PIN for Wallet View");
          currentState = STATE_PASSWORD_ENTRY;
          // Reset PIN entry state as if starting fresh for this new mnemonic
          currentDigitIndex = 0;
          currentDigitValue = 0;
          passwordConfirmed = false;
          memset(password, '_', PIN_LENGTH);
          password[PIN_LENGTH] = '\0';

        } else {
          errorMessage="Key Save Fail!"; displayErrorScreen(errorMessage);
        }
      }
      break;

    case STATE_PASSWORD_ENTRY:
        if (redrawScreen) { showPasswordEntryScreen(); }

        if (buttonLeftTriggered) {
            currentDigitValue = (currentDigitValue + 1) % 10;
            showPasswordEntryScreen();
        }
        else if (buttonRightTriggered) {
            password[currentDigitIndex] = currentDigitValue + '0';
            currentDigitIndex++;
            currentDigitValue = 0;

            if (currentDigitIndex >= PIN_LENGTH) {
                password[PIN_LENGTH] = '\0'; // Ensure null termination
                Serial.print("L: Full PIN Entered: ");
                Serial.print(password);
                Serial.print(" (bytes: ");
                for (int i = 0; i <= PIN_LENGTH; i++) { // Log including null terminator
                    Serial.print((uint8_t)password[i], HEX);
                    Serial.print(" ");
                }
                Serial.println(")");
                passwordConfirmed = true;
                Serial.println("L: Checking provision status...");

                bool ldOK = false, isPrv = false;
                if (prefs.begin(PREFS_NAMESPACE, true)) {
                    isPrv = prefs.getBool(PROVISIONED_KEY, false);
                    if (isPrv && prefs.isKey(MNEMONIC_KEY)) {
                        loadedMnemonic = prefs.getString(MNEMONIC_KEY, "");
                        if (loadedMnemonic.length() > 10) ldOK = true;
                    }
                    prefs.end();
                }
                Serial.printf("L: Loaded Mnemonic OK = %d, Provisioned = %d\n", ldOK, isPrv);

                if (ldOK) {
                    HDPrivateKey hdMasterKey(loadedMnemonic, "", &Mainnet);
                    if (!hdMasterKey.isValid()) {
                        errorMessage = "MasterKey Invalid";
                        displayErrorScreen(errorMessage);
                        passwordConfirmed = false; currentDigitIndex = 0; currentDigitValue = 0;
                        memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0';
                        break; // Break from switch, effectively re-showing PIN screen after error
                    }

                    // Derive the first level key (m/0')
                    HDPrivateKey tempKey = hdMasterKey.derive("0'");
                    if (!tempKey.isValid()) {
                        errorMessage = "Initial Key 0' Invalid";
                        displayErrorScreen(errorMessage);
                        passwordConfirmed = false; currentDigitIndex = 0; currentDigitValue = 0;
                        memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0';
                        break;
                    }

                    // Derive the secure path using the password as secondFactor
                    hdWalletKey = deriveSecurePath(tempKey, String(password));
                    if (!hdWalletKey.isValid()) {
                        errorMessage = "Derived Wallet Key Invalid";
                        displayErrorScreen(errorMessage);
                        passwordConfirmed = false; currentDigitIndex = 0; currentDigitValue = 0;
                        memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0';
                        break;
                    }

                    // Construct the baseWalletPath as a string (e.g., "0'/index0'/index1'/index2'/index3'")
                    baseWalletPath = "";
                    for (int level = 0; level < 4; level++) {
                        uint32_t index = deriveIndex(String(password), level);
                        baseWalletPath += "/" + String(index) + "'";
                    }

                    currentState = STATE_WALLET_VIEW;
                    currentRotationIndex = 0;
                    Serial.println("L: -> Wallet View");
                } else { // Not ldOK (e.g. not provisioned or mnemonic load failed)
                    Serial.println("L: Not provisioned or mnem load failed. Generating new keys...");
                    uint8_t ent[16];
                    esp_fill_random(ent, 16);
                    generatedMnemonic = generateMnemonicFromEntropy(ent, 16);
                    if (generatedMnemonic.length() > 0) {
                        currentState = STATE_SHOW_GENERATED_MNEMONIC;
                        Serial.println("L: -> Show Generated Mnemonic");
                    } else {
                        errorMessage = "Key Gen Fail!";
                        displayErrorScreen(errorMessage);
                        passwordConfirmed = false; currentDigitIndex = 0; currentDigitValue = 0;
                        memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0';
                    }
                }
            } else { // currentDigitIndex < PIN_LENGTH
                showPasswordEntryScreen();
            }
        }
        break;

    case STATE_WALLET_VIEW: {
        bool walletNeedsRedraw = redrawScreen;

        if(buttonSecretTriggered) {
             Serial.println("L: Wallet: Secret Button -> Show Secret Mnemonic");
             currentState = STATE_SHOW_SECRET_MNEMONIC;
             goto end_wallet_view_logic; // Using goto as in PR
        }
        else if(buttonLeftTriggered) {
             currentRotationIndex=(currentRotationIndex==0)?MAX_ROTATION_INDEX:currentRotationIndex-1;
             Serial.printf("L: Wallet: Prev Rotation -> %d\n", currentRotationIndex);
             walletNeedsRedraw = true;
        }
        else if(buttonRightTriggered) {
             currentRotationIndex=(currentRotationIndex+1)%(MAX_ROTATION_INDEX+1);
             Serial.printf("L: Wallet: Next Rotation -> %d\n", currentRotationIndex);
             walletNeedsRedraw = true;
        }

        if (walletNeedsRedraw) {
             Serial.printf("L: Redrawing Wallet R%d (WIF format)\n", currentRotationIndex);
             if(loadedMnemonic.length()==0){errorMessage="Mnem Missing!"; displayErrorScreen(errorMessage); break;}
             if(!passwordConfirmed){errorMessage="PIN Not Confirmed"; displayErrorScreen(errorMessage); break;}
             if (!hdWalletKey.isValid()) { // Check the base wallet key derived during PIN entry
                errorMessage = "hdWallet Key Invalid";
                displayErrorScreen(errorMessage);
                break;

             }
             // password[PIN_LENGTH]='\0'; // Already null-terminated

            Serial.print("PIN used for rotation: ");
            Serial.print(password);
            Serial.print(" (bytes: ");
            for (int i = 0; i <= PIN_LENGTH; i++) {
                Serial.print((uint8_t)password[i], HEX);
                Serial.print(" ");
            }
            Serial.println(")");


            HDPrivateKey parentKey = hdWalletKey; // Start with m/0'/pin_lvl0'/.../pin_lvl3'

            // Apply currentRotationIndex rotations
            for (int r = 0; r < currentRotationIndex; r++) {
                String rotationPathSegment = "";
                for (int l = 0; l < 4; l++) {
                    uint32_t index = deriveIndex(password, l);
                    rotationPathSegment += (l > 0 ? "/" : "") + String(index) + "'";
                }
                parentKey = parentKey.derive(rotationPathSegment.c_str());
                if (!parentKey.isValid()) {
                    errorMessage = "Parent Key Invalid (Rotation " + String(r) + ", PathSeg: " + rotationPathSegment + ")";
                    displayErrorScreen(errorMessage);
                    goto end_wallet_view_logic;
                }
            }

            HDPrivateKey currentKey = parentKey; // Key for addr_n, wif_n
            if (!currentKey.isValid()) { // Should be caught above, but as a safeguard
                errorMessage = "Current Key Invalid";
                displayErrorScreen(errorMessage);
                goto end_wallet_view_logic;
            }

            // Pre-rotated key (for addr_n_plus_1)
            String preRotatedPathSegment = "";
            for (int l = 0; l < 4; l++) {
                uint32_t index = deriveIndex(password, l);
                preRotatedPathSegment += (l > 0 ? "/" : "") + String(index) + "'";
            }
            HDPrivateKey preRotatedKey = currentKey.derive(preRotatedPathSegment.c_str());
            if (!preRotatedKey.isValid()) {
                errorMessage = "Pre-Rotated Key Invalid (PathSeg: " + preRotatedPathSegment + ")";
                displayErrorScreen(errorMessage);
                goto end_wallet_view_logic;
            }

            // Twice-pre-rotated key (for addr_n_plus_2)
            String twicePreRotatedPathSegment = "";
            for (int l = 0; l < 4; l++) {
                uint32_t index = deriveIndex(password, l);
                twicePreRotatedPathSegment += (l > 0 ? "/" : "") + String(index) + "'";
            }
            HDPrivateKey twicePreRotatedKey = preRotatedKey.derive(twicePreRotatedPathSegment.c_str());
            if (!twicePreRotatedKey.isValid()) {
                errorMessage = "Twice-Pre-Rotated Key Invalid (PathSeg: " + twicePreRotatedPathSegment + ")";
                displayErrorScreen(errorMessage);
                goto end_wallet_view_logic;
            }

            String addr_n = currentKey.publicKey().address(&Mainnet);
            String wif_n = currentKey.wif();
            String addr_n_plus_1 = preRotatedKey.publicKey().address(&Mainnet);
            String addr_n_plus_2 = twicePreRotatedKey.publicKey().address(&Mainnet); // PR Change: Now an address

            bool derivation_ok = true;
            String error_msg_detail = "";

            if (addr_n.length() == 0) { error_msg_detail = "Addr_n Gen Fail"; derivation_ok = false; }
            if (derivation_ok && wif_n.length() == 0) { error_msg_detail = "WIF_n Gen Fail"; derivation_ok = false; }
            if (derivation_ok && addr_n_plus_1.length() == 0) { error_msg_detail = "Addr_n+1 Gen Fail"; derivation_ok = false; }
            if (derivation_ok && addr_n_plus_2.length() == 0) { error_msg_detail = "Addr_n+2 Gen Fail"; derivation_ok = false; }

            if (derivation_ok) {
                String combinedQRData = addr_n + "|" + wif_n + "|" + addr_n_plus_1 + "|" + addr_n_plus_2;
                Serial.println("QR Data: " + combinedQRData);
                Serial.println("QR Data Length: " + String(combinedQRData.length()));
                int estimatedQrVersion = 11; // This can be adjusted or made dynamic
                displaySingleRotationQR(currentRotationIndex, combinedQRData, "Rotation", estimatedQrVersion);
            } else {
                displayErrorScreen(error_msg_detail.length() > 0 ? error_msg_detail : "Derivation Error");
            }
        }
        end_wallet_view_logic:; // Label for goto statements
        break;
      }

    case STATE_SHOW_SECRET_MNEMONIC:
      if(redrawScreen) displaySecretMnemonicScreen(loadedMnemonic);
      if(buttonLeftTriggered){
        Serial.println("L: Exit Secret Mnemonic screen.");
        currentState=STATE_WALLET_VIEW;
      }
      break;

    case STATE_ERROR:
      if(buttonLeftTriggered){
        Serial.println("L: Error Acknowledged.");
        // Go back to password entry, resetting PIN state
        currentState=STATE_PASSWORD_ENTRY;
        currentDigitIndex=0; currentDigitValue=0; passwordConfirmed=false;
        memset(password,'_',PIN_LENGTH); password[PIN_LENGTH]='\0';
        // hdWalletKey might be invalid, password entry will try to re-derive it.
      }
      break;

    default:
      Serial.printf("E: Unknown State %d\n", currentState);
      errorMessage="Unknown State Error";
      displayErrorScreen(errorMessage);
      // Default to password entry as a recovery mechanism
      currentState=STATE_PASSWORD_ENTRY;
      currentDigitIndex=0; currentDigitValue=0; passwordConfirmed=false;
      memset(password,'_',PIN_LENGTH); password[PIN_LENGTH]='\0';
      break;
  }
}