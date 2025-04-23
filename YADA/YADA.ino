#include <Arduino.h>
#include <Bitcoin.h>          // https://github.com/micro-bitcoin/uBitcoin
#include <Networks.h>         // Part of the Bitcoin library
#include <Preferences.h>      // Built-in ESP32 library
#include <QRCodeGenerator.h>  // https://github.com/Tomstark/QRCodeGenerator
#include "bip39_wordlist.h"   // Needs to be included (Make sure this file exists in your project)

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
#define BTN_RIGHT  1 // Next/Confirm (Bottom Right drawn -> Touch X=35, Y=45)
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

// --- Password Entry State ---
const int PIN_LENGTH = 6;
char password[PIN_LENGTH + 1];
int currentDigitIndex = 0;
int currentDigitValue = 0;
bool passwordConfirmed = false;

// --- Wallet View State ---
int currentRotationIndex = 0;
const int MAX_ROTATION_INDEX = 1000;
// enum WalletDisplayMode { MODE_SINGLE_QR }; // No longer needed
// WalletDisplayMode currentWalletMode = MODE_SINGLE_QR; // No longer needed
// int selectedQRIndex = 0; // No longer needed for display type

// ========================================
// Crypto & Utility Functions (UNCHANGED)
// ========================================
String sha256Hex(const uint8_t* data, size_t len) { uint8_t h[32]; mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c,0); mbedtls_sha256_update(&c,data,len); mbedtls_sha256_finish(&c,h); mbedtls_sha256_free(&c); String s=""; s.reserve(64); for(int i=0;i<32;i++){if(h[i]<0x10)s+="0"; s+=String(h[i],HEX);} return s; }
String hashPublicKey(const PublicKey& pk) { String h=pk.toString(); if(h.length()==0) return "Hashing Error"; if(h.length()!=66&&h.length()!=130) Serial.printf("W: Bad Pk len: %d\n",h.length()); size_t l=h.length()/2; if(l==0) return "Hashing Error"; uint8_t* b=(uint8_t*)malloc(l); if(!b) return "Hashing Error"; for(size_t i=0;i<l;i++){unsigned int v; if((i*2+1)>=h.length()||sscanf(h.substring(i*2,i*2+2).c_str(),"%x",&v)!=1){free(b);return"Hashing Error";}b[i]=(uint8_t)v;} String r=sha256Hex(b,l); free(b); return r; }
bool sha256Raw(const uint8_t* d, size_t l, uint8_t o[32]){mbedtls_sha256_context c;mbedtls_sha256_init(&c);if(mbedtls_sha256_starts(&c,0)!=0){mbedtls_sha256_free(&c);return false;}if(mbedtls_sha256_update(&c,d,l)!=0){mbedtls_sha256_free(&c);return false;}if(mbedtls_sha256_finish(&c,o)!=0){mbedtls_sha256_free(&c);return false;}mbedtls_sha256_free(&c);return true;}
String bytesToHex(const uint8_t* b, size_t l){String s="";s.reserve(l*2);for(size_t i=0;i<l;i++){if(b[i]<0x10)s+="0";s+=String(b[i],HEX);}return s;}
uint32_t deriveIndexCpp(const char* p, int l){String i=String(p)+String(l); uint8_t h[32]; mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c,0); mbedtls_sha256_update(&c,(const unsigned char*)i.c_str(),i.length()); mbedtls_sha256_finish(&c,h); mbedtls_sha256_free(&c); uint32_t r; memcpy(&r,h,4); r=ntohl(r); return r&0x7FFFFFFF;}
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
    int confirmButtonCenterX = 255; // Bottom Right X
    int confirmButtonCenterY = 205; // Bottom Right Y
    buttons[BTN_RIGHT].initButton(&tft, confirmButtonCenterX, confirmButtonCenterY, BUTTON_W+40, BUTTON_H, TFT_WHITE, TFT_GREEN, TFT_BLACK, "Backed Up", 2);
    buttons[BTN_RIGHT].drawButton(); // Explicitly draw only this button
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

    // --- Button Initialization - FINAL - Buttons Drawn Horizontally ---
    int leftButtonCenterX = 65;
    int leftButtonCenterY = 205;
    int rightButtonCenterX = 255; // DRAWN here (bottom right)
    int rightButtonCenterY = 205;

    buttons[BTN_LEFT].initButton(&tft, leftButtonCenterX, leftButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Cycle", 2);
    buttons[BTN_RIGHT].initButton(&tft, rightButtonCenterX, rightButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_GREEN, TFT_BLACK, nextLabel, 2);
    drawButtons(2);
}

// --- Display Single QR Code (Combined Data + Maximized Size + FINAL Buttons + Secret Button) ---
void displaySingleRotationQR(int rIdx, const String& combinedQRData, const String& label, int qrVersion) {
    if(combinedQRData.length() == 0){ displayErrorScreen("QR Gen Error (Empty)"); return; }
    const int eccLevel = ECC_LOW; // Try LOW ECC for potentially larger modules
    QRCode qr;
    size_t bufferSize = qrcode_getBufferSize(qrVersion);
    if (bufferSize == 0 || bufferSize > 3500) {
        displayErrorScreen("QR Buffer Size Error V" + String(qrVersion));
        return;
    }
    uint8_t *qrDataBuffer = (uint8_t *)malloc(bufferSize);
    if (!qrDataBuffer) { displayErrorScreen("QR Buffer Alloc Fail"); return; }

    if (qrcode_initText(&qr, qrDataBuffer, qrVersion, eccLevel, combinedQRData.c_str()) != 0) {
        Serial.printf("E: QR Init Fail V%d L=%d %s\n",qrVersion, combinedQRData.length(), label.c_str());
        int nextVersion = qrVersion + 1;
        if(nextVersion <= 13) { // Allow retry up to higher version
            Serial.println("Trying V"+String(nextVersion));
            free(qrDataBuffer);
            displaySingleRotationQR(rIdx, combinedQRData, label, nextVersion);
            return;
        } else {
            free(qrDataBuffer);
            displayErrorScreen("QR Init Failed V" + String(qrVersion));
            return;
        }
    }

    // --- Layout Calculation - Revised to Maximize QR Size ---
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
        pixelSize = min(pixelSize, 3); // Set a reasonable max pixel size (e.g., 3x3)
        // Serial.printf("L: QR Display - Size:%dx%d, Avail W:%d H:%d -> PixelSize:%d\n", qr.size, qr.size, availableWidth, availableHeight, pixelSize); // Optional Log
    }

    int qrDrawSize = qr.size * pixelSize;
    int startX = sideMargin + (availableWidth - qrDrawSize) / 2;
    int startY = topMargin + titleHeight + (availableHeight - qrDrawSize) / 2;

    // --- Drawing ---
    tft.setTextDatum(TC_DATUM);
    tft.setTextSize(1); // Smaller Title Font
    String tit="Rotation: "+String(rIdx) + " (" + label + ")";
    tft.drawString(tit, tft.width()/2, topMargin, 2); // Font 2

    // Draw QR Code
    for (uint8_t y = 0; y < qr.size; y++) {
        for (uint8_t x = 0; x < qr.size; x++) {
            if (qrcode_getModule(&qr, x, y)) {
                if (pixelSize == 1) tft.drawPixel(startX + x, startY + y, TFT_BLACK);
                else tft.fillRect(startX + x * pixelSize, startY + y * pixelSize, pixelSize, pixelSize, TFT_BLACK);
            }
        }
    }

    // --- Button Positions - FINAL Horizontal + Secret Button ---
    int leftButtonCenterX = 65;
    int leftButtonCenterY = 205;
    int rightButtonCenterX = 255; // DRAWN here
    int rightButtonCenterY = 205;
    int secretButtonCenterX = tft.width() - (SECRET_BUTTON_SIZE / 2) - 5;
    int secretButtonCenterY = (SECRET_BUTTON_SIZE / 2) + 5;

    buttons[BTN_LEFT].initButton(&tft, leftButtonCenterX, leftButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "< Prev", 2);
    buttons[BTN_RIGHT].initButton(&tft, rightButtonCenterX, rightButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Next >", 2);
    buttons[BTN_SECRET].initButton(&tft, secretButtonCenterX, secretButtonCenterY, SECRET_BUTTON_SIZE, SECRET_BUTTON_SIZE, TFT_WHITE, TFT_ORANGE, TFT_BLACK, "...", 1);
    drawButtons(3);
    free(qrDataBuffer);
 }


// ========================================
// Touch Button Handling Function (FINAL MAPPING + MANUAL BOUNDS CHECK - Cleaned)
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
        // --- Final Mapping (Rot 3, Inv X, Inv Y) ---
        t_x = map(p.y, 338, 3739, tft.width(), 0);   // Raw Y -> Screen X (Inverted)
        t_y = map(p.x, 414, 3857, tft.height(), 0); // Raw X -> Screen Y (Inverted)
        // --- End Mapping ---

        if (!touchIsBeingHeld) {
            touchIsBeingHeld = true; touchHoldStartTime = millis();
        }

        // --- MANUAL BOUNDS CHECK based on observed touch coordinates ---
        int leftBtnL = 15; int leftBtnR = 115; int leftBtnT = 180; int leftBtnB = 230;
        if (t_x >= leftBtnL && t_x <= leftBtnR && t_y >= leftBtnT && t_y <= leftBtnB) {
             currentLeftContainsManual = true;
        } else { currentLeftContainsManual = false; }

        int rightBtnL = -15; int rightBtnR = 85; int rightBtnT = 20; int rightBtnB = 70; // Top Left Area
         if (t_x >= rightBtnL && t_x <= rightBtnR && t_y >= rightBtnT && t_y <= rightBtnB) {
             currentRightContainsManual = true;
        } else { currentRightContainsManual = false; }

        int secretBtnL = 282; int secretBtnR = 318; int secretBtnT = 2; int secretBtnB = 38; // Top Right Area
        if (t_x >= secretBtnL && t_x <= secretBtnR && t_y >= secretBtnT && t_y <= secretBtnB) {
            currentSecretContainsManual = true;
        } else { currentSecretContainsManual = false; }
        // --- END MANUAL BOUNDS CHECK ---

    } else { // Not pressed (Touch Released)
        if (touchIsBeingHeld) {
             touchIsBeingHeld = false;
             // --- SIMPLIFIED RELEASE CHECK ---
             if (wasLeftPressedState && !currentLeftContainsManual) { buttonLeftTriggered = true; }
             if (wasRightPressedState && !currentRightContainsManual) { buttonRightTriggered = true; }
             if (wasSecretPressedState && !currentSecretContainsManual) { buttonSecretTriggered = true; }
             // --- END SIMPLIFIED RELEASE CHECK ---
        }
    }
    // Update previous state for next loop iteration
    wasLeftPressedState = currentLeftContainsManual;
    wasRightPressedState = currentRightContainsManual;
    wasSecretPressedState = currentSecretContainsManual;
}


// ========================================
// Setup Function (WITH ROTATION 3)
// ========================================
void setup() {
  Serial.begin(115200); while (!Serial && millis() < 2000);
  Serial.println("\n\n--- Yada HW (TFT+Touch v2 - FINAL CLEANED) ---"); // Modified Title
  Serial.print("Setup: Init Heap: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));

  pinMode(TOUCH_IRQ, INPUT);

  tft.init();
  // --- USING ROTATION 3 ---
  tft.setRotation(3);
  tft.fillScreen(TFT_BLACK);
  Serial.println("Setup: TFT OK (Rotation 3).");

  Serial.println("Setup: Init Touch SPI (VSPI)...");
  touchSPI.begin(TOUCH_SCK, TOUCH_MISO, TOUCH_MOSI, TOUCH_CS);
  ts.begin(touchSPI);
  ts.setRotation(tft.getRotation()); // Match touch rotation (now 3)
  Serial.println("Setup: Touch OK (Rotation 3).");

  pinMode(TFT_BL, OUTPUT); digitalWrite(TFT_BL, TFT_BACKLIGHT_ON); Serial.println("Setup: BL OK.");
  tft.setTextColor(TFT_WHITE, TFT_BLACK); tft.setTextDatum(MC_DATUM); tft.drawString("Initializing...", tft.width() / 2, tft.height() / 2, 4);
  Serial.println("Setup: Init Msg OK."); delay(1000);
  memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0'; currentDigitIndex = 0; currentDigitValue = 0; passwordConfirmed = false; Serial.println("Setup: Pwd State OK.");
  if (!prefs.begin(PREFS_NAMESPACE, false)) { Serial.println("W: Prefs RW Fail. RO..."); if (!prefs.begin(PREFS_NAMESPACE, true)) { Serial.println("E: Prefs RO Fail!"); tft.fillScreen(TFT_RED); tft.setTextColor(TFT_WHITE); tft.drawString("Storage Error!", tft.width()/2, tft.height()/2, 2); while(1); } else { Serial.println("Setup: Prefs RO OK."); prefs.end(); } } else { Serial.println("Setup: Prefs RW OK."); prefs.end(); }
  bool prv = false; if (prefs.begin(PREFS_NAMESPACE, true)) { prv = prefs.getBool(PROVISIONED_KEY, false); prefs.end(); Serial.print("Setup: Provisioned = "); Serial.println(prv); } else { Serial.println("W: Prefs RO Fail 2."); }
  currentState = STATE_PASSWORD_ENTRY; Serial.println("Setup: Init state -> PWD."); Serial.print("Setup: Exit Heap: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT)); Serial.println("Setup OK.");
}


// ========================================
// Main Loop (Cleaned up + Secret Button + Combined QR + Reordered Wallet View)
// ========================================
void loop() {
  static bool firstLoop = true; static AppState lastState = STATE_INITIALIZING; bool redrawScreen = false;
  if (currentState != lastState) { redrawScreen = true; lastState = currentState; buttonLeftTriggered = false; buttonRightTriggered = false; buttonSecretTriggered = false; touchIsBeingHeld = false; }
  if (firstLoop) { redrawScreen = true; firstLoop = false; }

  readButtons(); // Uses final mapping and MANUAL bound checks

  switch (currentState) {
    case STATE_INITIALIZING: Serial.println("W: Init Loop."); errorMessage="Init Loop Error"; displayErrorScreen(errorMessage); break;
    case STATE_SHOW_GENERATED_MNEMONIC: if(redrawScreen) displayGeneratedMnemonicScreen(generatedMnemonic); if(buttonRightTriggered){ Serial.println("L: Mnem Confirm."); bool sM=false,sF=false; if(prefs.begin(PREFS_NAMESPACE,false)){if(prefs.putString(MNEMONIC_KEY,generatedMnemonic.c_str())){sM=true;}if(sM&&prefs.putBool(PROVISIONED_KEY,true)){sF=true;}prefs.end();}else{errorMessage="Store Write Err!";displayErrorScreen(errorMessage);break;} if(sM&&sF){loadedMnemonic=generatedMnemonic;generatedMnemonic="";currentState=STATE_WALLET_VIEW;currentRotationIndex=0; Serial.println("L: Saved OK -> Wallet");}else{errorMessage="Key Save Fail!";displayErrorScreen(errorMessage);}} break;
    case STATE_PASSWORD_ENTRY:
        if (redrawScreen) { showPasswordEntryScreen(); }
        if (buttonLeftTriggered) { // Triggered by touch in Bottom-Left Area
            currentDigitValue = (currentDigitValue + 1) % 10;
            showPasswordEntryScreen();
            // Serial.printf("L: Cycle -> %d\n",currentDigitValue); // Optional Log
        } else if (buttonRightTriggered) { // Triggered by touch in Top-Left Area
            password[currentDigitIndex] = currentDigitValue + '0'; //Serial.printf("L: PIN[%d] set.\n", currentDigitIndex); // Optional Log
            currentDigitIndex++;
            if (currentDigitIndex >= PIN_LENGTH) { // Full PIN logic
                password[PIN_LENGTH] = '\0'; Serial.println("L: Full PIN Entered."); passwordConfirmed = true; Serial.println("L: Check Store...");
                bool ldOK=false, isPrv=false; if(prefs.begin(PREFS_NAMESPACE, true)){ isPrv=prefs.getBool(PROVISIONED_KEY,false); if(isPrv && prefs.isKey(MNEMONIC_KEY)){loadedMnemonic=prefs.getString(MNEMONIC_KEY,""); if(loadedMnemonic.length()>10) ldOK=true;} prefs.end(); } Serial.printf("L: Loaded Mnemonic OK = %d\n", ldOK); if(ldOK){ currentState=STATE_WALLET_VIEW; currentRotationIndex=0; Serial.println("L: -> Wallet View");} else { Serial.println("L: Gen Keys..."); uint8_t ent[16]; esp_fill_random(ent,16); generatedMnemonic=generateMnemonicFromEntropy(ent,16); if(generatedMnemonic.length()>0){ currentState=STATE_SHOW_GENERATED_MNEMONIC; Serial.println("L: -> Show Generated Mnem"); } else { errorMessage="Key Gen Fail!"; displayErrorScreen(errorMessage); passwordConfirmed=false; currentDigitIndex=0; currentDigitValue=0; memset(password,'_',PIN_LENGTH); password[PIN_LENGTH]='\0';}}
            } else { // Next digit logic
                currentDigitValue = 0;
                showPasswordEntryScreen();
                // Serial.println("L: Advanced to next digit."); // Optional Log
            }
        } break; // End PWD Entry

    // Wallet View case with Reordered Logic + Combined QR
    case STATE_WALLET_VIEW: {
        bool walletNeedsRedraw = redrawScreen;

        // --- Handle Button Actions FIRST ---
        if(buttonSecretTriggered) { // Triggered by touch in Top-Right Area
             Serial.println("L: Wallet: Secret Button -> Show Secret");
             currentState = STATE_SHOW_SECRET_MNEMONIC;
             goto end_wallet_view_logic; // Skip wallet redraw this cycle
        }
        else if(buttonLeftTriggered) { // Triggered by touch in Bottom-Left Area -> Prev Rotation
             // Serial.println("L: Wallet: Left Trigger -> Prev Rot"); // Optional Log
             currentRotationIndex=(currentRotationIndex==0)?MAX_ROTATION_INDEX:currentRotationIndex-1; // Decrement rotation
             Serial.printf("L: Rotation -> %d\n", currentRotationIndex);
             walletNeedsRedraw = true; // Request redraw
        }
        else if(buttonRightTriggered) { // Triggered by touch in Top-Left Area -> Next Rotation
             // Serial.println("L: Wallet: Right Trigger -> Next Rot"); // Optional Log
             currentRotationIndex=(currentRotationIndex+1)%(MAX_ROTATION_INDEX+1); // Increment rotation
             Serial.printf("L: Rotation -> %d\n", currentRotationIndex);
             walletNeedsRedraw = true; // Request redraw
        }
        // --- END Button Actions ---


        // --- Perform Redraw ONLY if needed ---
        if (walletNeedsRedraw) {
             Serial.printf("L: Redrawing Wallet R%d\n", currentRotationIndex);
             if(loadedMnemonic.length()==0){errorMessage="Mnem Miss!"; displayErrorScreen(errorMessage); break;} if(!passwordConfirmed){errorMessage="PIN Confirmed?"; displayErrorScreen(errorMessage); break;} password[PIN_LENGTH]='\0';
             HDPrivateKey hdMasterKey(loadedMnemonic, "", &Mainnet); if (!hdMasterKey.isValid()) { errorMessage = "MK Fail"; displayErrorScreen(errorMessage); break; } String pP="m"; for(int l=0;l<4;l++)pP+="/"+String(deriveIndexCpp(password,l))+"'"; HDPrivateKey pN=hdMasterKey.derive(pP.c_str()); if (!pN.isValid()) { errorMessage = "PN Fail"; displayErrorScreen(errorMessage); break; } String pC="0/"+String(currentRotationIndex),pP1="0/"+String(currentRotationIndex+1),pP2="0/"+String(currentRotationIndex+2); String ad="",h1="",h2=""; bool ok=true; String er=""; {HDPrivateKey kC=pN.derive(pC.c_str()),kP=pN.derive(pP1.c_str()),kT=pN.derive(pP2.c_str()); if(!kC.isValid()||!kP.isValid()||!kT.isValid()){er="Rel Key Fail R"+String(currentRotationIndex);ok=false;} if(ok){PublicKey pk=kC.publicKey(); if(!pk.isValid()){er="Inv PkC";ok=false;}else{ad=pk.address(&Mainnet);if(ad.length()==0){er="Addr Gen Fail";ok=false;}}} if(ok){PublicKey pk=kP.publicKey(); if(!pk.isValid()){er="Inv PkP";ok=false;}else{h1=hashPublicKey(pk);if(h1.startsWith("H")||h1.length()!=64){er="Hash PkP Fail";ok=false;}}} if(ok){PublicKey pk=kT.publicKey(); if(!pk.isValid()){er="Inv PkT";ok=false;}else{String pkh=pk.toString(); if(pkh.length()>0&&pkh.length()%2==0){size_t l=pkh.length()/2; uint8_t*b=(uint8_t*)malloc(l); if(!b){er="Mem HH";ok=false;}else{bool c=true; for(size_t i=0;i<l;i++){unsigned int v; if((i*2+1)>=pkh.length()||sscanf(pkh.substring(i*2,i*2+2).c_str(),"%x",&v)!=1){er="Hex HH";c=false;break;}b[i]=(uint8_t)v;} if(c){uint8_t hh1[32],hh2[32]; if(sha256Raw(b,l,hh1)&&sha256Raw(hh1,32,hh2)){h2=bytesToHex(hh2,32);if(h2.length()!=64){er="Len HH";ok=false;}}else{er="Hash HH Fail";ok=false;}}else{ok=false;}free(b);}}else{er="PkT Hex Fail";ok=false;}}}}
             if(ok){ String combinedQRData = ad + "|" + h1 + "|" + h2; int estimatedQrVersion = 8; displaySingleRotationQR(currentRotationIndex, combinedQRData, "Yada Data", estimatedQrVersion); }
             else { displayErrorScreen(er.length() > 0 ? er : "Calculation Error"); }
        } // End if(walletNeedsRedraw)

        end_wallet_view_logic:; // Label for goto

        break; // End STATE_WALLET_VIEW
      } // End scope STATE_WALLET_VIEW

    case STATE_SHOW_SECRET_MNEMONIC: if(redrawScreen) displaySecretMnemonicScreen(loadedMnemonic); if(buttonLeftTriggered){Serial.println("L: Exit Secret"); currentState=STATE_WALLET_VIEW; /*selectedQRIndex=0;*/} break;
    case STATE_ERROR: if(buttonLeftTriggered){Serial.println("L: Err Ack"); currentState=STATE_PASSWORD_ENTRY; currentDigitIndex=0; currentDigitValue=0; passwordConfirmed=false; memset(password,'_',PIN_LENGTH); password[PIN_LENGTH]='\0';} break;
    default: Serial.printf("E: Bad State %d\n", currentState); errorMessage="State Err"; displayErrorScreen(errorMessage); break;
  } // End switch

   // delay(30); // Keep commented out
} // End loop
