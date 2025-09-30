#include <Arduino.h>
#include <Bitcoin.h>          // https://github.com/micro-bitcoin/uBitcoin
#include <Networks.h>         // Part of the Bitcoin library
#include <Preferences.h>      // Built-in ESP32 library
#include <QRCodeGenerator.h>  // https://github.com/Tomstark/QRCodeGenerator
#include "bip39_wordlist.h"   // Needs to be included (Make sure this file exists in your project)
#include <BigNumber.h>        // https://github.com/nickgammon/BigNumber download and load the zip file as a library
#include <mbedtls/sha256.h>
#include <esp_system.h>
#include "esp_heap_caps.h"
#include <stdint.h>        // For uint32_t
#include <arpa/inet.h>     // For ntohl (Network to Host Long for endianness handling)
#include <string.h>        // For memcpy
#include <keccak.h>

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
#define MAX_BUTTONS 6
TFT_eSPI_Button buttons[MAX_BUTTONS];
#define BUTTON_H 50 // Increased Height
#define BUTTON_W 100
#define SECRET_BUTTON_SIZE 35
#define BUTTON_SPACING_X 10
#define BUTTON_SPACING_Y 10

// Define button IDs (Based on HORIZONTAL layout + Secret + Jump)
#define BTN_LEFT   0 // Cycle/Back/Prev/OK (Bottom Left drawn -> Touch X=65, Y=205)
#define BTN_RIGHT  1 // Next/Confirm (Bottom Right drawn -> Touch X=35, Y=45)
#define BTN_SECRET 2 // Show Secret Mnemonic (Top Right Drawn -> Touch X=300, Y=20)
#define BTN_JUMP   3 // Jump to Rotation Index (Top Right, below Secret -> New Touch Coordinates)
#define BTN_OK     0
#define BTN_BACK   0
#define BTN_CYCLE  0
#define BTN_NEXT   1
#define BTN_CONFIRM 1

// --- Blockchain Configuration ---
const Network BSCNetwork = {
  0x01,  // name (uint8_t, placeholder for BSC)
  0x00,  // p2pkh (unused for BSC)
  0x00,  // p2sh (unused for BSC)
  0x80   // wif (unused for BSC)
};

struct BlockchainConfig {
  const char* name; // Display name (e.g., "YadaCoin", "BSC")
  uint32_t derivationIndex; // Hardened index (e.g., 0' for YadaCoin, 1' for BSC)
  const Network* network; // Network parameters for address generation
};

BlockchainConfig blockchains[] = {
  {"YadaCoin", 0, &Mainnet}, // YadaCoin uses Bitcoin-style Mainnet
  {"BSC", 1, &Mainnet}   // BSC with custom network
};

const int NUM_BLOCKCHAINS = sizeof(blockchains) / sizeof(blockchains[0]);
int selectedBlockchainIndex = 0; // Default to YadaCoin
const char* BLOCKCHAIN_INDEX_KEY = "blockchain_idx"; // Preferences key for blockchain index

// --- Preferences ---
Preferences prefs;
const char* PREFS_NAMESPACE = "yada-wallet";
const char* MNEMONIC_KEY = "mnemonic";
const char* PROVISIONED_KEY = "provisioned";
const char* ROTATION_INDEX_KEY = "rotation_idx";
const char* CHAINCODE_KEY = "chaincode";

// --- Button State ---
bool buttonLeftTriggered = false;
bool buttonRightTriggered = false;
bool buttonSecretTriggered = false;
bool buttonJumpTriggered = false;
unsigned long touchHoldStartTime = 0;
bool touchIsBeingHeld = false;

// --- State Variables ---
enum AppState {
  STATE_BLOCKCHAIN_SELECTION, // New state for selecting blockchain
  STATE_WALLET_TYPE_SELECTION,
  STATE_INITIALIZING,
  STATE_SHOW_GENERATED_MNEMONIC,
  STATE_PASSWORD_ENTRY,
  STATE_WALLET_VIEW,
  STATE_SHOW_SECRET_MNEMONIC,
  STATE_ERROR,
  STATE_JUMP_ENTRY,
  STATE_MNEMONIC_IMPORT
};
AppState currentState = STATE_BLOCKCHAIN_SELECTION; // Start with blockchain selection

// Provisioned flag
bool provisioned = false;

// Wallet type selection
bool newWalletMode = true;

// --- Jump Entry State ---
const int JUMP_INDEX_LENGTH = 4; // For MAX_ROTATION_INDEX=1000
char jumpIndex[JUMP_INDEX_LENGTH + 1]; // To store digits 0-9
int currentJumpDigitIndex = 0;
int currentJumpDigitValue = 0;

// --- Password Entry State ---
const uint32_t MODULO_2_31 = 2147483647; // 2^31
const int PIN_LENGTH = 6;
char password[PIN_LENGTH + 1];
int currentDigitIndex = 0;
int currentDigitValue = 0;
bool passwordConfirmed = false;

// --- Mnemonic Import State ---
const int NUM_WORDS = 12;
uint16_t wordIndices[NUM_WORDS];
char currentWordBuffer[9]; // Max BIP39 word length 8 + null
int currentWordIndex = 0;
int cursorPos = 0;

// --- Wallet View State ---
int currentRotationIndex = 0;
const int MAX_ROTATION_INDEX = 1000; // Max address index
String errorMessage = "";
String generatedMnemonic = "";
String loadedMnemonic = "";
HDPrivateKey hdWalletKey; // Stores derived key
String baseWalletPath;    // Stores derivation path

const char* alphabet = "abcdefghijklmnopqrstuvwxyz";

int getLetterIndex(char c) {
  if (c >= 'a' && c <= 'z') return c - 'a';
  return -1;
}

char getNextLetter(char c) {
  int idx = getLetterIndex(c);
  if (idx < 0) return 'a';
  idx = (idx + 1) % 26;
  return alphabet[idx];
}

bool isValidWord(const char* wordStr, uint16_t& index) {
  if (strlen(wordStr) < 3 || strlen(wordStr) > 8) return false;
  for (uint16_t i = 0; i < 2048; i++) {
    if (strcmp(wordStr, wordlist[i]) == 0) {
      index = i;
      return true;
    }
  }
  return false;
}

String keccak256Address(const PublicKey& key, unsigned char* output) {
    uint8_t input[64];
    String keyHex = key.toString(); // Should return uncompressed key
    Serial.print("Public Key: ");
    Serial.println(keyHex);
    Serial.print("Public Key Length: ");
    Serial.println(keyHex.length());
    
    // Validate uncompressed key (130 chars, starts with "04")
    if (keyHex.length() != 130 || keyHex.substring(0, 2) != "04") {
        Serial.println("E: Invalid public key format or length (expected 130 chars, starting with 04)");
        memset(output, 0, 32);
        return "";
    }
    
    // Convert hex to bytes, skipping "04" prefix
    for (size_t i = 0; i < 64; i++) {
        String byteStr = keyHex.substring(2 + i * 2, 4 + i * 2);
        input[i] = (uint8_t)strtol(byteStr.c_str(), nullptr, 16);
        if (i < 4 || i >= 60) {
            Serial.printf("Input Byte %d: %02x\n", i, input[i]);
        }
    }
    
    // Compute Keccak-256 hash
    Serial.print("Heap Before Keccak: ");
    Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
    Keccak keccak(Keccak::Keccak256);
    keccak.add(input, 64);
    std::string hash = keccak.getHash();
    
    Serial.print("Keccak-256 Hash: ");
    Serial.println(hash.c_str());
    Serial.print("Hash Length: ");
    Serial.println(hash.length());
    
    if (hash.length() != 64) {
        Serial.println("E: Invalid Keccak-256 hash length");
        memset(output, 0, 32);
        return "";
    }
    
    // Copy the full 32-byte hash to output (for compatibility)
    for (size_t i = 0; i < 32; i++) {
        std::string hexByte = hash.substr(i * 2, 2);
        output[i] = (uint8_t)strtol(hexByte.c_str(), nullptr, 16);
        if (i >= 12 && i < 16) {
            Serial.printf("Output Byte %d: %02x\n", i, output[i]);
        }
    }
    
    // Generate the lowercase address (last 20 bytes)
    String lowercaseAddress = bytesToHex(output + 12, 20);
    Serial.println("Lowercase Address: " + lowercaseAddress);
    
    // Compute Keccak-256 hash of the lowercase address for EIP-55 checksum
    Keccak keccakAddr(Keccak::Keccak256);
    keccakAddr.add((const uint8_t*)lowercaseAddress.c_str(), lowercaseAddress.length());
    std::string addrHash = keccakAddr.getHash();
    
    Serial.print("Address Keccak-256 Hash: ");
    Serial.println(addrHash.c_str());
    
    if (addrHash.length() != 64) {
        Serial.println("E: Invalid address Keccak-256 hash length");
        memset(output, 0, 32);
        return "";
    }
    
    // Apply EIP-55 checksum
    String checksumAddress = "0x";
    checksumAddress.reserve(42); // "0x" + 40 hex chars
    for (size_t i = 0; i < lowercaseAddress.length(); i++) {
        char c = lowercaseAddress[i];
        int hashNibble = hexCharToDec(addrHash[i]);
        if (hashNibble < 0) {
            Serial.println("E: Invalid character in address hash");
            memset(output, 0, 32);
            return "";
        }
        if (hashNibble >= 8 && c >= 'a' && c <= 'f') {
            c = c - 'a' + 'A';
        }
        checksumAddress += c;
    }
    
    Serial.println("Checksummed Address: " + checksumAddress);
    
    Serial.print("Heap After Keccak: ");
    Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
    
    return checksumAddress;
}

bool validateMnemonic(const String& mnemonic) {
  if (mnemonic.length() < 10) return false;
  String tM = mnemonic + " ";
  int wordCount = 0;
  String words[12];
  int pos = 0;
  for (int i = 0; i < tM.length(); i++) {
    if (tM.charAt(i) == ' ') {
      if (pos < i) {
        words[wordCount] = tM.substring(pos, i);
        wordCount++;
      }
      pos = i + 1;
    }
  }
  if (wordCount != 12) return false;

  uint16_t indices[12];
  for (int i = 0; i < 12; i++) {
    indices[i] = 65535; // Invalid
    for (int j = 0; j < 2048; j++) {
      if (words[i] == wordlist[j]) {
        indices[i] = j;
        break;
      }
    }
    if (indices[i] == 65535) return false;
  }

  // Pack bits
  uint8_t entropy[16];
  memset(entropy, 0, 16);
  uint8_t cs = 0;
  int bitCount = 0;
  int byteIdx = 0;
  int csBitPos = 0;
  for (int w = 0; w < 12; w++) {
    uint16_t idx = indices[w];
    for (int b = 10; b >= 0; b--) {
      uint8_t bitVal = (idx >> b) & 1;
      if (bitCount < 128) {
        int bitInByte = bitCount % 8;
        if (bitVal) {
          entropy[byteIdx] |= (1 << (7 - bitInByte));
        }
        bitCount++;
        if (bitCount % 8 == 0) byteIdx++;
      } else {
        if (bitVal) {
          cs |= (1 << (3 - csBitPos));
        }
        csBitPos++;
      }
    }
  }

  // Compute checksum
  uint8_t hash[32];
  if (!sha256Raw(entropy, 16, hash)) return false;
  uint8_t expectedCs = hash[0] >> 4;

  return expectedCs == cs;
}

// ========================================
// Crypto & Utility Functions
// ========================================
String sha256Hex(const uint8_t* data, size_t len) {
  uint8_t h[32];
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c);
  mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, data, len);
  mbedtls_sha256_finish(&c, h);
  mbedtls_sha256_free(&c);
  String s = "";
  s.reserve(64);
  for (int i = 0; i < 32; i++) {
    if (h[i] < 0x10) s += "0";
    s += String(h[i], HEX);
  }
  return s;
}

String hashPublicKey(const PublicKey& pk) {
  String h = pk.toString();
  if (h.length() == 0) return "Hashing Error";
  if (h.length() != 66 && h.length() != 130) Serial.printf("W: Bad Pk len: %d\n", h.length());
  size_t l = h.length() / 2;
  if (l == 0) return "Hashing Error";
  uint8_t* b = (uint8_t*)malloc(l);
  if (!b) return "Hashing Error";
  for (size_t i = 0; i < l; i++) {
    unsigned int v;
    if ((i * 2 + 1) >= h.length() || sscanf(h.substring(i * 2, i * 2 + 2).c_str(), "%x", &v) != 1) {
      free(b);
      return "Hashing Error";
    }
    b[i] = (uint8_t)v;
  }
  String r = sha256Hex(b, l);
  free(b);
  return r;
}

bool sha256Raw(const uint8_t* d, size_t l, uint8_t o[32]) {
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c);
  if (mbedtls_sha256_starts(&c, 0) != 0) {
    mbedtls_sha256_free(&c);
    return false;
  }
  if (mbedtls_sha256_update(&c, d, l) != 0) {
    mbedtls_sha256_free(&c);
    return false;
  }
  if (mbedtls_sha256_finish(&c, o) != 0) {
    mbedtls_sha256_free(&c);
    return false;
  }
  mbedtls_sha256_free(&c);
  return true;
}

String bytesToHex(const uint8_t* b, size_t l) {
  String s = "";
  s.reserve(l * 2);
  for (size_t i = 0; i < l; i++) {
    if (b[i] < 0x10) s += "0";
    s += String(b[i], HEX);
  }
  return s;
}

int hexCharToDec(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return 10 + c - 'A';
  if (c >= 'a' && c <= 'f') return 10 + c - 'a';
  return -1;
}

BigNumber hexToBigNumber(const char* hex) {
  BigNumber result = 0;
  for (const char* p = hex; *p != '\0'; ++p) {
    int digit = hexCharToDec(*p);
    if (digit < 0) continue;
    result *= 16;
    result += digit;
  }
  return result;
}

uint32_t deriveIndex(String factor, int level) {
  BigNumber::begin();
  String combined = factor + String(level);
  unsigned char hash[32];
  mbedtls_sha256((const unsigned char*)combined.c_str(), combined.length(), hash, 0);
  char hex[65];
  for (int i = 0; i < 32; i++) {
    sprintf(&hex[i * 2], "%02x", hash[i]);
  }
  Serial.print("SHA256 hash: ");
  Serial.println(hex);
  BigNumber bigNumber = hexToBigNumber(hex);
  Serial.print("bigNumber: ");
  Serial.println(bigNumber);
  BigNumber modulo(MODULO_2_31);
  BigNumber remainder = bigNumber % modulo;
  Serial.print("deriveIndex index: ");
  Serial.println(remainder);
  BigNumber::finish();
  return remainder;
}

HDPrivateKey deriveHardened(HDPrivateKey root, uint32_t index) {
  String path = String(index) + "'";
  HDPrivateKey key = root.derive(path.c_str());
  bool isValid = key.isValid();
  if (!isValid) {
    String errorMessage = "hdWallet Key Invalid (" + path + ")";
    Serial.println(errorMessage);
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

HDPrivateKey deriveSecurePath(HDPrivateKey root, String secondFactor) {
  HDPrivateKey currentNode = root;
  // First level is the blockchain-specific derivation (e.g., m/0' or m/1')
  currentNode = deriveHardened(currentNode, blockchains[selectedBlockchainIndex].derivationIndex);
  Serial.printf("L: Derived blockchain path m/%u'\n", blockchains[selectedBlockchainIndex].derivationIndex);
  // Continue with 3 levels using the second factor (PIN)
  for (int level = 0; level < 3; level++) {
    uint32_t index = deriveIndex(secondFactor, level);
    currentNode = deriveHardened(currentNode, index);
  }
  return currentNode;
}

String generateMnemonicFromEntropy(const uint8_t* e, size_t len) {
  if (len != 16) return "";
  uint8_t cs_len = (len * 8) / 32;
  uint8_t h[32];
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c);
  mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, e, len);
  mbedtls_sha256_finish(&c, h);
  mbedtls_sha256_free(&c);
  uint8_t cs_byte = h[0];
  uint8_t mask = 0xFF << (8 - cs_len);
  uint8_t cs_bits = cs_byte & mask;
  int total_bits = (len * 8) + cs_len;
  int num_words = total_bits / 11;
  String m = "";
  m.reserve(120);
  uint16_t w_idx = 0;
  int bit_count = 0;
  for (int i = 0; i < total_bits; i++) {
    int byte_idx = i / 8;
    int bit_in_byte = 7 - (i % 8);
    uint8_t curr_byte;
    if (byte_idx < len) {
      curr_byte = e[byte_idx];
    } else {
      int cs_bit_idx = i - (len * 8);
      int shift = 7 - cs_bit_idx;
      curr_byte = cs_bits;
      bit_in_byte = shift;
    }
    uint8_t bit_val = (curr_byte >> bit_in_byte) & 1;
    w_idx = (w_idx << 1) | bit_val;
    bit_count++;
    if (bit_count == 11) {
      if (w_idx >= 2048) return "";
      m += String(wordlist[w_idx]);
      if ((i + 1) < total_bits) m += " ";
      w_idx = 0;
      bit_count = 0;
    }
  }
  return m;
}

// ========================================
// Display Functions
// ========================================
void drawButtons(int numButtons) {
  for (int i = 0; i < numButtons; i++) {
    if (i == BTN_LEFT && currentState == STATE_WALLET_VIEW && currentRotationIndex == 0) {
      Serial.println("L: Skipping BTN_LEFT (rotation 0 in STATE_WALLET_VIEW)");
      continue;
    }
    Serial.printf("L: Drawing button %d in state %d\n", i, currentState);
    buttons[i].drawButton();
  }
}

void displayErrorScreen(String msg) {
  tft.fillScreen(TFT_RED);
  tft.setTextColor(TFT_WHITE, TFT_RED);
  tft.setTextDatum(MC_DATUM);
  tft.setTextSize(2);
  tft.drawString("ERROR", tft.width() / 2, 30);
  tft.drawFastHLine(10, 50, tft.width() - 20, TFT_WHITE);
  tft.setTextDatum(TL_DATUM);
  tft.setTextSize(1);
  tft.setCursor(10, 65);
  int maxC = (tft.width() - 20) / 6;
  String cL = "";
  for (int i = 0; i < msg.length(); i++) {
    cL += msg[i];
    if ((msg[i] == ' ' && cL.length() >= maxC) || cL.length() > maxC + 10) {
      int wP = -1;
      if (msg[i] != ' ') {
        for (int j = cL.length() - 1; j >= 0; j--) if (cL[j] == ' ') {
          wP = j;
          break;
        }
      }
      if (wP != -1) {
        tft.println(cL.substring(0, wP));
        cL = cL.substring(wP + 1);
      } else {
        tft.println(cL);
        cL = "";
      }
      tft.setCursor(10, tft.getCursorY());
      if (tft.getCursorY() > tft.height() - BUTTON_H - 30) {
        tft.print("...");
        break;
      }
    }
  }
  if (cL.length() > 0) tft.println(cL);
  buttons[BTN_OK].initButton(&tft, 65, 205, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_DARKGREY, TFT_BLACK, "OK", 2);
  drawButtons(1);
  currentState = STATE_ERROR;
}

void displayGeneratedMnemonicScreen(String m) {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_YELLOW, TFT_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.setTextSize(2);
  tft.drawString("BACKUP MNEMONIC!", tft.width() / 2, 20);
  tft.drawFastHLine(10, 35, tft.width() - 20, TFT_YELLOW);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextDatum(TL_DATUM);
  tft.setTextSize(1);
  tft.setTextFont(2);
  int wc = 0;
  String cw = "";
  String tM = m + " ";
  int xS = 15, yS = 55, cW = tft.width() / 3 - 5, lH = tft.fontHeight(2) + 3;
  int xP = xS, yP = yS;
  for (int i = 0; i < tM.length(); i++) {
    char c = tM.charAt(i);
    if (c == ' ') {
      if (cw.length() > 0) {
        wc++;
        String wn = String(wc) + ".";
        tft.setTextColor(TFT_CYAN);
        tft.drawString(wn, xP, yP);
        tft.setTextColor(TFT_WHITE);
        tft.drawString(cw, xP + tft.textWidth("XX."), yP);
        cw = "";
        yP += lH;
        if (wc % 4 == 0) {
          xP += cW;
          yP = yS;
        }
        if (wc >= 12) break;
      }
    } else cw += c;
  }
  // Initialize only the "Backed Up" button for BTN_CONFIRM
  int confirmButtonCenterX = 255;
  int confirmButtonCenterY = 205;
  buttons[BTN_CONFIRM].initButton(&tft, confirmButtonCenterX, confirmButtonCenterY, BUTTON_W + 40, BUTTON_H, TFT_WHITE, TFT_GREEN, TFT_BLACK, "Backed Up", 2);
  // Explicitly clear the BTN_CYCLE button to ensure it is not drawn
  buttons[BTN_CYCLE].initButton(&tft, 0, 0, 0, 0, TFT_BLACK, TFT_BLACK, TFT_BLACK, "", 0);
  // Draw only the BTN_CONFIRM button
  buttons[BTN_CONFIRM].drawButton();
}

void displaySecretMnemonicScreen(String m) {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_ORANGE, TFT_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.setTextSize(2);
  tft.drawString("Root Mnemonic", tft.width() / 2, 20);
  tft.drawFastHLine(10, 35, tft.width() - 20, TFT_ORANGE);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextDatum(TL_DATUM);
  tft.setTextSize(1);
  tft.setTextFont(2);
  int wc = 0;
  String cw = "";
  String tM = m + " ";
  int xS = 15, yS = 55, cW = tft.width() / 3 - 5, lH = tft.fontHeight(2) + 3;
  int xP = xS, yP = yS;
  for (int i = 0; i < tM.length(); i++) {
    char c = tM.charAt(i);
    if (c == ' ') {
      if (cw.length() > 0) {
        wc++;
        String wn = String(wc) + ".";
        tft.setTextColor(TFT_CYAN);
        tft.drawString(wn, xP, yP);
        tft.setTextColor(TFT_WHITE);
        tft.drawString(cw, xP + tft.textWidth("XX."), yP);
        cw = "";
        yP += lH;
        if (wc % 4 == 0) {
          xP += cW;
          yP = yS;
        }
        if (wc >= 12) break;
      }
    } else cw += c;
  }
  buttons[BTN_BACK].initButton(&tft, 65, 205, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Back", 2);
  drawButtons(1);
}

void showPasswordEntryScreen() {
  tft.fillScreen(TFT_DARKCYAN);
  tft.setTextColor(TFT_WHITE, TFT_DARKCYAN);
  tft.setTextDatum(MC_DATUM);
  tft.setTextSize(2);
  tft.drawString("Enter Wallet PIN", tft.width() / 2, 30);
  int digitBoxSize = 25;
  int spacing = 8;
  int totalW = PIN_LENGTH * digitBoxSize + (PIN_LENGTH - 1) * spacing;
  int startX = (tft.width() - totalW) / 2;
  int digitY = 80;
  tft.setTextSize(2);
  tft.setTextDatum(MC_DATUM);
  for (int i = 0; i < PIN_LENGTH; i++) {
    int currentX = startX + i * (digitBoxSize + spacing);
    uint16_t boxColor = (i == currentDigitIndex) ? TFT_YELLOW : TFT_WHITE;
    tft.drawRect(currentX, digitY, digitBoxSize, digitBoxSize, boxColor);
    char displayChar;
    if (i < currentDigitIndex) {
      displayChar = '*';
    } else if (i == currentDigitIndex) {
      displayChar = currentDigitValue + '0';
    } else {
      displayChar = '_';
    }
    char tempStr[2] = {displayChar, '\0'};
    tft.drawString(tempStr, currentX + digitBoxSize / 2, digitY + digitBoxSize / 2 + 2);
  }
  char nextLabel[5] = "Next";
  if (currentDigitIndex == PIN_LENGTH - 1) {
    strcpy(nextLabel, "OK");
  }
  int leftButtonCenterX = 65;
  int leftButtonCenterY = 205;
  int rightButtonCenterX = 255;
  int rightButtonCenterY = 205;
  buttons[BTN_CYCLE].initButton(&tft, leftButtonCenterX, leftButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Cycle", 2);
  buttons[BTN_NEXT].initButton(&tft, rightButtonCenterX, rightButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_GREEN, TFT_BLACK, nextLabel, 2);
  drawButtons(2);
}

void showJumpEntryScreen() {
  tft.fillScreen(TFT_DARKCYAN);
  tft.setTextColor(TFT_WHITE, TFT_DARKCYAN);
  tft.setTextDatum(MC_DATUM);
  tft.setTextSize(2);
  tft.drawString("Enter Rotation Index", tft.width() / 2, 30);
  int digitBoxSize = 25;
  int spacing = 8;
  int totalW = JUMP_INDEX_LENGTH * digitBoxSize + (JUMP_INDEX_LENGTH - 1) * spacing;
  int startX = (tft.width() - totalW) / 2;
  int digitY = 80;
  tft.setTextSize(2);
  tft.setTextDatum(MC_DATUM);
  for (int i = 0; i < JUMP_INDEX_LENGTH; i++) {
    int currentX = startX + i * (digitBoxSize + spacing);
    uint16_t boxColor = (i == currentJumpDigitIndex) ? TFT_YELLOW : TFT_WHITE;
    tft.drawRect(currentX, digitY, digitBoxSize, digitBoxSize, boxColor);
    char displayChar;
    if (i < currentJumpDigitIndex) {
      displayChar = '*';
    } else if (i == currentJumpDigitIndex) {
      displayChar = currentJumpDigitValue + '0';
    } else {
      displayChar = '_';
    }
    char tempStr[2] = {displayChar, '\0'};
    tft.drawString(tempStr, currentX + digitBoxSize / 2, digitY + digitBoxSize / 2 + 2);
  }
  char nextLabel[5] = "Next";
  if (currentJumpDigitIndex == JUMP_INDEX_LENGTH - 1) {
    strcpy(nextLabel, "OK");
  }
  int leftButtonCenterX = 65;
  int leftButtonCenterY = 205;
  int rightButtonCenterX = 255;
  int rightButtonCenterY = 205;
  buttons[BTN_CYCLE].initButton(&tft, leftButtonCenterX, leftButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Cycle", 2);
  buttons[BTN_NEXT].initButton(&tft, rightButtonCenterX, rightButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_GREEN, TFT_BLACK, nextLabel, 2);
  drawButtons(2);
}

void showWalletTypeSelectionScreen() {
  tft.fillScreen(TFT_DARKCYAN);
  tft.setTextColor(TFT_WHITE, TFT_DARKCYAN);
  tft.setTextDatum(MC_DATUM);
  tft.setTextSize(2);
  tft.drawString("Wallet Setup", tft.width() / 2, 30);
  String choice = newWalletMode ? "New Wallet" : "Import Wallet";
  tft.setTextSize(3);
  tft.drawString(choice, tft.width() / 2, tft.height() / 2);
  int leftButtonCenterX = 65;
  int leftButtonCenterY = 205;
  int rightButtonCenterX = 255;
  int rightButtonCenterY = 205;
  buttons[BTN_CYCLE].initButton(&tft, leftButtonCenterX, leftButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Cycle", 2);
  buttons[BTN_CONFIRM].initButton(&tft, rightButtonCenterX, rightButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_GREEN, TFT_BLACK, "Proceed", 2);
  drawButtons(2);
}

void showMnemonicImportScreen() {
  tft.fillScreen(TFT_DARKCYAN);
  tft.setTextColor(TFT_WHITE, TFT_DARKCYAN);
  tft.setTextDatum(MC_DATUM);
  tft.setTextSize(2);
  String title = "Import Word " + String(currentWordIndex + 1) + "/" + String(NUM_WORDS);
  tft.drawString(title, tft.width() / 2, 30);
  String disp = String(currentWordBuffer);
  int len = strlen(currentWordBuffer);
  if (cursorPos <= len) {
    disp = String(currentWordBuffer).substring(0, cursorPos) + "|" + String(currentWordBuffer).substring(cursorPos);
  } else {
    disp += "|";
  }
  tft.drawString(disp, tft.width() / 2, 80);
  
  // Preview first matching word
  tft.setTextSize(1);
  tft.setTextDatum(TL_DATUM);
  tft.setCursor(10, 110);
  tft.print("Preview: " + getFirstMatchingWord(currentWordBuffer));
  
  char nextLabel[6] = "Next";
  uint16_t idx;
  if (cursorPos == len && len >= 3 && isValidWord(currentWordBuffer, idx)) {
    strcpy(nextLabel, "OK");
  }
  int leftButtonCenterX = 65;
  int leftButtonCenterY = 205;
  int rightButtonCenterX = 255;
  int rightButtonCenterY = 205;
  buttons[BTN_CYCLE].initButton(&tft, leftButtonCenterX, leftButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Cycle Ltr", 1);
  buttons[BTN_NEXT].initButton(&tft, rightButtonCenterX, rightButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_GREEN, TFT_BLACK, nextLabel, 1);
  drawButtons(2);
}

void showBlockchainSelectionScreen() {
  tft.fillScreen(TFT_DARKCYAN);
  tft.setTextColor(TFT_WHITE, TFT_DARKCYAN);
  tft.setTextDatum(MC_DATUM);
  tft.setTextSize(2);
  tft.drawString("Select Blockchain", tft.width() / 2, 30);
  tft.setTextSize(3);
  tft.drawString(blockchains[selectedBlockchainIndex].name, tft.width() / 2, tft.height() / 2);
  int leftButtonCenterX = 65;
  int leftButtonCenterY = 205;
  int rightButtonCenterX = 255;
  int rightButtonCenterY = 205;
  buttons[BTN_CYCLE].initButton(&tft, leftButtonCenterX, leftButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Cycle", 2);
  buttons[BTN_CONFIRM].initButton(&tft, rightButtonCenterX, rightButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_GREEN, TFT_BLACK, "Select", 2);
  drawButtons(2);
}

void displaySingleRotationQR(int rIdx, const String& combinedQRData, const String& label, int qrVersion) {
  if (combinedQRData.length() == 0) {
    displayErrorScreen("QR Gen Error (Empty)");
    return;
  }
  const int eccLevel = ECC_LOW;
  QRCode qr;
  size_t bufferSize = qrcode_getBufferSize(qrVersion);
  if (bufferSize == 0 || bufferSize > 3500) {
    Serial.printf("E: QR Buffer Size Error V%d, Size: %u\n", qrVersion, bufferSize);
    displayErrorScreen("QR Buffer Size Error V" + String(qrVersion));
    return;
  }
  uint8_t *qrDataBuffer = (uint8_t *)malloc(bufferSize);
  if (!qrDataBuffer) {
    displayErrorScreen("QR Buffer Alloc Fail");
    return;
  }
  if (qrcode_initText(&qr, qrDataBuffer, qrVersion, eccLevel, combinedQRData.c_str()) != 0) {
    Serial.printf("E: QR Init Fail V%d L=%d %s\n", qrVersion, combinedQRData.length(), label.c_str());
    int nextVersion = qrVersion + 1;
    if (nextVersion <= 13) {
      Serial.println("Trying V" + String(nextVersion));
      free(qrDataBuffer);
      displaySingleRotationQR(rIdx, combinedQRData, label, nextVersion);
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
    pixelSize = min(pixelSize, 3);
  }
  int qrDrawSize = qr.size * pixelSize;
  int startX = sideMargin + (availableWidth - qrDrawSize) / 2;
  int startY = topMargin + titleHeight + (availableHeight - qrDrawSize) / 2;
  tft.setTextDatum(TC_DATUM);
  tft.setTextSize(1);
  String tit = String(blockchains[selectedBlockchainIndex].name) + ": " + String(rIdx);
  tft.drawString(tit, tft.width() / 2, topMargin, 2);
  for (uint8_t y = 0; y < qr.size; y++) {
    for (uint8_t x = 0; x < qr.size; x++) {
      if (qrcode_getModule(&qr, x, y)) {
        if (pixelSize == 1) tft.drawPixel(startX + x, startY + y, TFT_BLACK);
        else tft.fillRect(startX + x * pixelSize, startY + y * pixelSize, pixelSize, pixelSize, TFT_BLACK);
      }
    }
  }
  int leftButtonCenterX = 65;
  int leftButtonCenterY = 205;
  int rightButtonCenterX = 255;
  int rightButtonCenterY = 205;
  int secretButtonCenterX = tft.width() - (SECRET_BUTTON_SIZE / 2) - 5;
  int secretButtonCenterY = (SECRET_BUTTON_SIZE / 2) + 5;
  int jumpButtonCenterX = tft.width() - (SECRET_BUTTON_SIZE / 2) - 5;
  int jumpButtonCenterY = (SECRET_BUTTON_SIZE / 2) + 5 + SECRET_BUTTON_SIZE + 5;
  buttons[BTN_LEFT].initButton(&tft, leftButtonCenterX, leftButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "< Prev", 2);
  buttons[BTN_RIGHT].initButton(&tft, rightButtonCenterX, rightButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Next >", 2);
  buttons[BTN_SECRET].initButton(&tft, secretButtonCenterX, secretButtonCenterY, SECRET_BUTTON_SIZE, SECRET_BUTTON_SIZE, TFT_WHITE, TFT_ORANGE, TFT_BLACK, "Seed", 1);
  buttons[BTN_JUMP].initButton(&tft, jumpButtonCenterX, jumpButtonCenterY, SECRET_BUTTON_SIZE, SECRET_BUTTON_SIZE, TFT_WHITE, TFT_CYAN, TFT_BLACK, "Jump", 1);
  drawButtons(4);
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
  static bool wasJumpPressedState = false;
  static unsigned long lastTouchTime = 0;
  const unsigned long debounceDelay = 200;
  buttonLeftTriggered = false;
  buttonRightTriggered = false;
  buttonSecretTriggered = false;
  buttonJumpTriggered = false;
  bool pressed = ts.tirqTouched() && ts.touched();
  bool currentLeftContainsManual = false;
  bool currentRightContainsManual = false;
  bool currentSecretContainsManual = false;
  bool currentJumpContainsManual = false;
  if (pressed) {
    TS_Point p = ts.getPoint();
    t_x = map(p.y, 338, 3739, tft.width(), 0);
    t_y = map(p.x, 414, 3857, tft.height(), 0);
    Serial.printf("L: Touch at (%d, %d)\n", t_x, t_y);
    if (!touchIsBeingHeld) {
      touchIsBeingHeld = true;
      touchHoldStartTime = millis();
    }
    int leftBtnL = 15, leftBtnR = 115, leftBtnT = 180, leftBtnB = 230;
    if (t_x >= leftBtnL && t_x <= leftBtnR && t_y >= leftBtnT && t_y <= leftBtnB) {
      currentLeftContainsManual = true;
      Serial.println("L: Touch in Left Button (Cycle/Prev/Back/OK)");
    }
    int rightBtnL = -15, rightBtnR = 85, rightBtnT = 20, rightBtnB = 70;
    if (t_x >= rightBtnL && t_x <= rightBtnR && t_y >= rightBtnT && t_y <= rightBtnB) {
      currentRightContainsManual = true;
      Serial.println("L: Right Button (Next/Confirm/OK)");
    }
    int secretBtnL = 282, secretBtnR = 318, secretBtnT = 2, secretBtnB = 38;
    if (t_x >= secretBtnL && t_x <= secretBtnR && t_y >= secretBtnT && t_y <= secretBtnB) {
      currentSecretContainsManual = true;
      Serial.println("L: Touch in Secret Button");
    }
    int jumpBtnL = 215, jumpBtnR = 270, jumpBtnT = 2, jumpBtnB = 38;
    if (t_x >= jumpBtnL && t_x <= jumpBtnR && t_y >= jumpBtnT && t_y <= jumpBtnB) {
      currentJumpContainsManual = true;
      Serial.println("L: Touch in Jump Button");
    }
  } else {
    if (touchIsBeingHeld && (millis() - lastTouchTime > debounceDelay)) {
      touchIsBeingHeld = false;
      if (wasLeftPressedState && !currentLeftContainsManual) {
        buttonLeftTriggered = true;
        Serial.println("L: Left Button Triggered");
      }
      if (wasRightPressedState && !currentRightContainsManual) {
        buttonRightTriggered = true;
        Serial.println("L: Right Button Triggered");
      }
      if (wasSecretPressedState && !currentSecretContainsManual) {
        buttonSecretTriggered = true;
        Serial.println("L: Secret Button Triggered");
      }
      if (wasJumpPressedState && !currentJumpContainsManual) {
        buttonJumpTriggered = true;
        Serial.println("L: Jump Button Triggered");
      }
      lastTouchTime = millis();
    }
  }
  wasLeftPressedState = currentLeftContainsManual;
  wasRightPressedState = currentRightContainsManual;
  wasSecretPressedState = currentSecretContainsManual;
  wasJumpPressedState = currentJumpContainsManual;
}

// ========================================
// Setup Function
// ========================================
void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 2000);
  Serial.println("\n\n--- Yada HW (TFT+Touch - PR #1 + Blockchain Selection + Mnemonic Import Letters) ---");
  Serial.print("Setup: Init Heap: ");
  Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
  pinMode(TOUCH_IRQ, INPUT);
  tft.init();
  tft.setRotation(3);
  tft.fillScreen(TFT_BLACK);
  Serial.println("Setup: TFT OK (Rotation 3).");
  Serial.println("Setup: Init Touch SPI (VSPI)...");
  touchSPI.begin(TOUCH_SCK, TOUCH_MISO, TOUCH_MOSI, TOUCH_CS);
  ts.begin(touchSPI);
  ts.setRotation(tft.getRotation());
  Serial.println("Setup: Touch OK (Rotation 3).");
  pinMode(TFT_BL, OUTPUT);
  digitalWrite(TFT_BL, TFT_BACKLIGHT_ON);
  Serial.println("Setup: BL OK.");
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.drawString("YadaCoin Starting...", tft.width() / 2, tft.height() / 2, 4);
  Serial.println("Setup: Init Msg OK.");
  delay(1000);
  memset(password, '_', PIN_LENGTH);
  password[PIN_LENGTH] = '\0';
  currentDigitIndex = 0;
  currentDigitValue = 0;
  passwordConfirmed = false;
  currentState = STATE_BLOCKCHAIN_SELECTION;
  Serial.println("Setup: Init state -> BLOCKCHAIN_SELECTION.");
  currentJumpDigitIndex = 0;
  currentJumpDigitValue = 0;
  Serial.println("Setup: Pwd State OK.");
  strcpy(currentWordBuffer, "");
  memset(wordIndices, 0, sizeof(wordIndices));
  currentWordIndex = 0;
  cursorPos = 0;
  newWalletMode = true;
  if (!prefs.begin(PREFS_NAMESPACE, false)) {
    Serial.println("W: Prefs RW Fail. Trying RO...");
    if (!prefs.begin(PREFS_NAMESPACE, true)) {
      Serial.println("E: Prefs RO Fail!");
      tft.fillScreen(TFT_RED);
      tft.setTextColor(TFT_WHITE);
      tft.drawString("Storage Error!", tft.width() / 2, tft.height() / 2, 2);
      while (1);
    } else {
      Serial.println("Setup: Prefs RO OK (initial RO fail).");
      prefs.end();
    }
  } else {
    Serial.println("Setup: Prefs RW OK.");
    prefs.end();
  }
  bool prv = false;
  String loadedM = "";
  int rotIdx = 0;
  int blkIdx = 0;
  if (prefs.begin(PREFS_NAMESPACE, true)) {
    prv = prefs.getBool(PROVISIONED_KEY, false);
    loadedM = prefs.getString(MNEMONIC_KEY, "");
    rotIdx = prefs.getInt(ROTATION_INDEX_KEY, 0);
    blkIdx = prefs.getInt(BLOCKCHAIN_INDEX_KEY, 0);
    if (blkIdx < 0 || blkIdx >= NUM_BLOCKCHAINS) {
      blkIdx = 0;
    }
    Serial.print("Setup: Restored Blockchain Index = ");
    Serial.println(blkIdx);
    Serial.print("Setup: Restored Rotation Index = ");
    Serial.println(rotIdx);
    prefs.end();
    Serial.print("Setup: Provisioned = ");
    Serial.println(prv);
  } else {
    Serial.println("W: Prefs RO Fail for provisioned/blockchain check.");
    rotIdx = 0;
    blkIdx = 0;
  }
  provisioned = prv;
  loadedMnemonic = loadedM;
  currentRotationIndex = rotIdx;
  selectedBlockchainIndex = blkIdx;
  currentState = STATE_BLOCKCHAIN_SELECTION;
  Serial.println("Setup: Init state -> BLOCKCHAIN_SELECTION.");
  Serial.print("Setup: Exit Heap: ");
  Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
  Serial.println("Setup OK.");
}

// ========================================
// Main Loop
// ========================================
void loop() {
  static bool firstLoop = true;
  static AppState lastState = STATE_BLOCKCHAIN_SELECTION;
  bool redrawScreen = false;
  if (currentState != lastState) {
    redrawScreen = true;
    lastState = currentState;
    buttonLeftTriggered = false;
    buttonRightTriggered = false;
    buttonSecretTriggered = false;
    buttonJumpTriggered = false;
    touchIsBeingHeld = false;
  }
  if (firstLoop) {
    redrawScreen = true;
    firstLoop = false;
  }
  readButtons();
  bool pressed = ts.tirqTouched() && ts.touched();
  switch (currentState) {
    case STATE_BLOCKCHAIN_SELECTION:
      if (redrawScreen) {
        showBlockchainSelectionScreen();
        Serial.println("L: Blockchain Selection Screen Redrawn");
      }
      if (buttonLeftTriggered) {
        selectedBlockchainIndex = (selectedBlockchainIndex + 1) % NUM_BLOCKCHAINS;
        Serial.printf("L: Blockchain cycled to %s (index %d)\n", blockchains[selectedBlockchainIndex].name, selectedBlockchainIndex);
        showBlockchainSelectionScreen();
      } else if (buttonRightTriggered) {
        Serial.printf("L: Blockchain selected: %s (index %d)\n", blockchains[selectedBlockchainIndex].name, selectedBlockchainIndex);
        if (prefs.begin(PREFS_NAMESPACE, false)) {
          if (prefs.putInt(BLOCKCHAIN_INDEX_KEY, selectedBlockchainIndex)) {
            Serial.println("L: Blockchain index saved");
          } else {
            Serial.println("W: Failed to save blockchain index");
          }
          prefs.end();
        } else {
          Serial.println("W: Prefs RW Fail for blockchain save");
        }
        if (prefs.begin(PREFS_NAMESPACE, true)) {
          provisioned = prefs.getBool(PROVISIONED_KEY, false);
          loadedMnemonic = provisioned ? prefs.getString(MNEMONIC_KEY, "") : "";
          prefs.end();
          if (provisioned && loadedMnemonic.length() > 10) {
            Serial.println("L: Mnemonic loaded, proceeding to PIN entry");
            currentState = STATE_PASSWORD_ENTRY;
            currentDigitIndex = 0;
            currentDigitValue = 0;
            passwordConfirmed = false;
            memset(password, '_', PIN_LENGTH);
            password[PIN_LENGTH] = '\0';
          } else {
            Serial.println("L: Not provisioned, go to wallet type selection");
            currentState = STATE_WALLET_TYPE_SELECTION;
            newWalletMode = true;
          }
        } else {
          Serial.println("W: Prefs RO Fail for provisioned/mnemonic check");
          errorMessage = "Storage Access Error";
          displayErrorScreen(errorMessage);
          currentState = STATE_ERROR;
        }
      }
      break;

    case STATE_WALLET_TYPE_SELECTION:
      if (redrawScreen) {
        showWalletTypeSelectionScreen();
        Serial.println("L: Wallet Type Selection Screen Redrawn");
      }
      if (buttonLeftTriggered) {
        newWalletMode = !newWalletMode;
        Serial.printf("L: Wallet mode cycled to %s\n", newWalletMode ? "New" : "Import");
        showWalletTypeSelectionScreen();
      } else if (buttonRightTriggered) {
        Serial.printf("L: Wallet mode selected: %s\n", newWalletMode ? "New" : "Import");
        if (newWalletMode) {
          // Generate new mnemonic
          uint8_t ent[16];
          esp_fill_random(ent, 16);
          generatedMnemonic = generateMnemonicFromEntropy(ent, 16);
          if (generatedMnemonic.length() > 0) {
            Serial.println("L: New mnemonic generated: " + generatedMnemonic);
            currentState = STATE_SHOW_GENERATED_MNEMONIC;
          } else {
            errorMessage = "Key Gen Fail!";
            displayErrorScreen(errorMessage);
            currentState = STATE_ERROR;
          }
        } else {
          // Import mode
          Serial.println("L: Entering mnemonic import mode");
          currentState = STATE_MNEMONIC_IMPORT;
          memset(wordIndices, 0, sizeof(wordIndices));
          strcpy(currentWordBuffer, "");
          currentWordIndex = 0;
          cursorPos = 0;
        }
      }
      break;

        case STATE_MNEMONIC_IMPORT:
      if (redrawScreen) {
        showMnemonicImportScreen();
        Serial.println("L: Mnemonic Import Screen Redrawn");
      }
      // Handle hold for backspace
      if (pressed && touchIsBeingHeld && (millis() - touchHoldStartTime > 1000)) {
        int len = strlen(currentWordBuffer);
        if (len > 0 && cursorPos > 0) {
          // Remove character before cursor
          for (int i = cursorPos - 1; i < len; i++) {
            currentWordBuffer[i] = currentWordBuffer[i + 1];
          }
          cursorPos--;
          Serial.println("L: Backspace - Current buffer: " + String(currentWordBuffer));
          showMnemonicImportScreen();
          touchHoldStartTime = millis(); // Reset for multiple backspaces
          delay(200); // Debounce
        }
      }
      if (buttonLeftTriggered) {
        // Cycle to next valid letter at cursor position
        String prefix = String(currentWordBuffer).substring(0, cursorPos);
        String possibles = getPossibleNextLetters(prefix.c_str(), cursorPos);
        int len = strlen(currentWordBuffer);
        char currentChar = (cursorPos < len) ? currentWordBuffer[cursorPos] : ' ';
        int currentIdx = possibles.indexOf(currentChar);
        if (currentIdx < 0) currentIdx = -1; // If invalid, start from beginning
        char nextChar;
        if (possibles.length() == 0) {
          // No valid continuations, stay or reset
          nextChar = currentChar;
        } else {
          int nextIdx = (currentIdx + 1) % possibles.length();
          nextChar = possibles.charAt(nextIdx);
        }
        if (cursorPos < len) {
          currentWordBuffer[cursorPos] = nextChar;
        } else {
          // Append if at end
          currentWordBuffer[cursorPos] = nextChar;
          currentWordBuffer[cursorPos + 1] = '\0';
        }
        Serial.printf("L: Valid letter cycled at pos %d (word %d): %s (possibles: %s)\n", 
                      cursorPos, currentWordIndex, currentWordBuffer, possibles.c_str());
        showMnemonicImportScreen();
      } else if (buttonRightTriggered) {
        int len = strlen(currentWordBuffer);
        if (cursorPos < len) {
          // Advance cursor
          cursorPos++;
          showMnemonicImportScreen();
        } else {
          // At end
          String firstMatch = getFirstMatchingWord(currentWordBuffer);
          uint16_t idx;
          if (len >= 3 && isValidWord(currentWordBuffer, idx)) {
            wordIndices[currentWordIndex] = idx;
            Serial.printf("L: Word %d confirmed: %s (index %d)\n", currentWordIndex + 1, currentWordBuffer, idx);
            currentWordIndex++;
            if (currentWordIndex >= NUM_WORDS) {
              // Build and validate mnemonic
              String m = "";
              for (int i = 0; i < NUM_WORDS; i++) {
                m += String(wordlist[wordIndices[i]]);
                if (i < NUM_WORDS - 1) m += " ";
              }
              Serial.println("L: Imported mnemonic: " + m);
              if (validateMnemonic(m)) {
                loadedMnemonic = m;
                bool saveOk = false;
                if (prefs.begin(PREFS_NAMESPACE, false)) {
                  if (prefs.putString(MNEMONIC_KEY, m.c_str()) && prefs.putBool(PROVISIONED_KEY, true)) {
                    saveOk = true;
                    provisioned = true;
                  }
                  prefs.end();
                }
                if (saveOk) {
                  Serial.println("L: Imported mnemonic saved, proceeding to PIN entry");
                  currentState = STATE_PASSWORD_ENTRY;
                  currentDigitIndex = 0;
                  currentDigitValue = 0;
                  passwordConfirmed = false;
                  memset(password, '_', PIN_LENGTH);
                  password[PIN_LENGTH] = '\0';
                } else {
                  errorMessage = "Save Failed!";
                  displayErrorScreen(errorMessage);
                  currentState = STATE_ERROR;
                }
              } else {
                errorMessage = "Invalid Checksum!";
                displayErrorScreen(errorMessage);
                currentState = STATE_ERROR;
                strcpy(currentWordBuffer, "");
                cursorPos = 0;
              }
            } else {
              strcpy(currentWordBuffer, "");
              cursorPos = 0;
              showMnemonicImportScreen();
              Serial.printf("L: Word %d entered, now word %d\n", currentWordIndex, currentWordIndex + 1);
            }
          } else if (firstMatch == "None") {
            // Invalid prefix
            Serial.println("E: Invalid prefix: no matching word for '" + String(currentWordBuffer) + "'");
            tft.fillScreen(TFT_RED);
            tft.setTextColor(TFT_WHITE, TFT_RED);
            tft.setTextDatum(MC_DATUM);
            tft.setTextSize(2);
            tft.drawString("Invalid Prefix!", tft.width() / 2, tft.height() / 2);
            delay(1000);
            showMnemonicImportScreen();
          } else {
            // Valid prefix but not ready to confirm (too short or incomplete)
            Serial.println("L: Continue typing word (preview: " + firstMatch + ")");
            showMnemonicImportScreen();
          }
        }
      }
      break;

    case STATE_INITIALIZING:
      Serial.println("W: Init Loop reached. Should not happen.");
      errorMessage = "Init Loop Error";
      displayErrorScreen(errorMessage);
      break;

    case STATE_SHOW_GENERATED_MNEMONIC:
      if (redrawScreen) displayGeneratedMnemonicScreen(generatedMnemonic);
      if (buttonRightTriggered) {
        Serial.println("L: Mnem Confirm.");
        bool sM = false, sF = false;
        if (prefs.begin(PREFS_NAMESPACE, false)) {
          if (prefs.putString(MNEMONIC_KEY, generatedMnemonic.c_str())) {
            sM = true;
          }
          if (sM && prefs.putBool(PROVISIONED_KEY, true)) {
            sF = true;
          }
          prefs.end();
        } else {
          errorMessage = "Store Write Err!";
          displayErrorScreen(errorMessage);
          break;
        }
        if (sM && sF) {
          loadedMnemonic = generatedMnemonic;
          provisioned = true;
          generatedMnemonic = "";
          Serial.println("L: Saved OK -> Enter PIN to proceed to wallet");
          currentState = STATE_PASSWORD_ENTRY;
          currentDigitIndex = 0;
          currentDigitValue = 0;
          passwordConfirmed = false;
          memset(password, '_', PIN_LENGTH);
          password[PIN_LENGTH] = '\0';
        } else {
          errorMessage = "Key Save Fail!";
          displayErrorScreen(errorMessage);
        }
      }
      break;

    case STATE_PASSWORD_ENTRY:
      if (redrawScreen) {
        showPasswordEntryScreen();
        Serial.println("L: Password Entry Screen Redrawn");
      }
      if (buttonLeftTriggered) {
        currentDigitValue = (currentDigitValue + 1) % 10;
        showPasswordEntryScreen();
        Serial.printf("L: Digit cycled to %d at index %d\n", currentDigitValue, currentDigitIndex);
      } else if (buttonRightTriggered) {
        Serial.printf("L: Right Button (Next/OK) Pressed at digit index %d\n", currentDigitIndex);
        password[currentDigitIndex] = currentDigitValue + '0';
        currentDigitIndex++;
        currentDigitValue = 0;
        if (currentDigitIndex >= PIN_LENGTH) {
          password[PIN_LENGTH] = '\0';
          Serial.print("L: Full PIN Entered: ");
          Serial.println(password);
          Serial.print("L: Heap Before Derivation: ");
          Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
          passwordConfirmed = true;
          Serial.println("L: Validating mnemonic and deriving keys...");
          HDPrivateKey hdMasterKey(loadedMnemonic, "", blockchains[selectedBlockchainIndex].network);
          if (!hdMasterKey.isValid()) {
            errorMessage = "MasterKey Invalid";
            Serial.println("E: " + errorMessage);
            displayErrorScreen(errorMessage);
            passwordConfirmed = false;
            currentDigitIndex = 0;
            currentDigitValue = 0;
            memset(password, '_', PIN_LENGTH);
            password[PIN_LENGTH] = '\0';
            currentState = STATE_ERROR;
            break;
          }
          Serial.println("L: Deriving secure path...");
          uint32_t indices[3];
          String pathSegment = "/" + String(blockchains[selectedBlockchainIndex].derivationIndex) + "'";
          HDPrivateKey currentNode = deriveHardened(hdMasterKey, blockchains[selectedBlockchainIndex].derivationIndex);
          for (int level = 0; level < 3; level++) {
            indices[level] = deriveIndex(String(password), level);
            currentNode = deriveHardened(currentNode, indices[level]);
            pathSegment += "/" + String(indices[level]) + "'";
            Serial.printf("L: Path level %d: %u'\n", level, indices[level]);
            if (!currentNode.isValid()) {
              errorMessage = "Derivation Failed at Level " + String(level);
              Serial.println("E: " + errorMessage);
              displayErrorScreen(errorMessage);
              passwordConfirmed = false;
              currentDigitIndex = 0;
              currentDigitValue = 0;
              memset(password, '_', PIN_LENGTH);
              password[PIN_LENGTH] = '\0';
              currentState = STATE_ERROR;
              break;
            }
          }
          if (currentState == STATE_ERROR) break;
          hdWalletKey = currentNode;
          baseWalletPath = pathSegment;
          Serial.println("L: Base wallet path: m" + baseWalletPath);
          Serial.print("L: Heap After Derivation: ");
          Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
          Serial.println("L: Key derivation successful, transitioning to Wallet View");
          currentState = STATE_WALLET_VIEW;
          currentRotationIndex = 0;
        } else {
          showPasswordEntryScreen();
          Serial.printf("L: Digit entered, index now %d\n", currentDigitIndex);
        }
      }
      break;

    case STATE_WALLET_VIEW: {
      bool walletNeedsRedraw = redrawScreen;
      if (buttonSecretTriggered) {
        Serial.println("L: Wallet: Secret Button -> Show Secret Mnemonic");
        currentState = STATE_SHOW_SECRET_MNEMONIC;
        goto end_wallet_view_logic;
      } else if (buttonJumpTriggered) {
        Serial.println("L: Wallet: Jump Button -> Jump Entry");
        currentState = STATE_JUMP_ENTRY;
        currentJumpDigitIndex = 0;
        currentJumpDigitValue = 0;
        memset(jumpIndex, '_', JUMP_INDEX_LENGTH);
        jumpIndex[JUMP_INDEX_LENGTH] = '\0';
        goto end_wallet_view_logic;
      } else if (buttonLeftTriggered && currentRotationIndex > 0) {
        currentRotationIndex = currentRotationIndex - 1;
        Serial.printf("L: Wallet: Prev Rotation -> %d\n", currentRotationIndex);
        walletNeedsRedraw = true;
      } else if (buttonRightTriggered) {
        currentRotationIndex = (currentRotationIndex + 1) % (MAX_ROTATION_INDEX + 1);
        Serial.printf("L: Wallet: Next Rotation -> %d\n", currentRotationIndex);
        walletNeedsRedraw = true;
      }
      if (walletNeedsRedraw) {
        Serial.printf("L: Redrawing Wallet R%d (WIF format)\n", currentRotationIndex);
        Serial.print("L: Heap Before Wallet Redraw: ");
        Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
        if (loadedMnemonic.length() == 0) {
          errorMessage = "Mnem Missing!";
          displayErrorScreen(errorMessage);
          break;
        }
        if (!passwordConfirmed) {
          errorMessage = "PIN Not Confirmed";
          displayErrorScreen(errorMessage);
          break;
        }
        if (!hdWalletKey.isValid()) {
          errorMessage = "hdWallet Key Invalid";
          displayErrorScreen(errorMessage);
          break;
        }
        Serial.print("PIN used for rotation: ");
        Serial.print(password);
        Serial.print(" (bytes: ");
        for (int i = 0; i <= PIN_LENGTH; i++) {
          Serial.print((uint8_t)password[i], HEX);
          Serial.print(" ");
        }
        Serial.println(")");
        uint32_t indices[3];
        String rotationPathSegment = "";
        for (int l = 0; l < 3; l++) {
          indices[l] = deriveIndex(password, l);
          rotationPathSegment += (l > 0 ? "/" : "") + String(indices[l]) + "'";
        }
        HDPrivateKey parentKey = hdWalletKey;
        for (int r = 0; r < currentRotationIndex; r++) {
          parentKey = parentKey.derive(rotationPathSegment.c_str());
          if (!parentKey.isValid()) {
            errorMessage = "Parent Key Invalid (Rotation " + String(r) + ", PathSeg: " + rotationPathSegment + ")";
            displayErrorScreen(errorMessage);
            goto end_wallet_view_logic;
          }
        }
        HDPrivateKey currentKey = parentKey;
        if (!currentKey.isValid()) {
          errorMessage = "Current Key Invalid";
          displayErrorScreen(errorMessage);
          goto end_wallet_view_logic;
        }
        bool saveSuccess = false;
        if (prefs.begin(PREFS_NAMESPACE, false)) {
          if (prefs.putInt(ROTATION_INDEX_KEY, currentRotationIndex)) {
            Serial.printf("L: Saved Rotation Index %d\n", currentRotationIndex);
          } else {
            Serial.println("W: Failed to save Rotation Index");
          }
          uint8_t chaincode[32];
          memcpy(chaincode, currentKey.chainCode, 32);
          String chaincodeHex = bytesToHex(chaincode, 32);
          if (prefs.putString(CHAINCODE_KEY, chaincodeHex.c_str())) {
            Serial.println("L: Saved Chaincode: " + chaincodeHex);
            saveSuccess = true;
          } else {
            Serial.println("W: Failed to save Chaincode");
          }
          prefs.end();
        } else {
          Serial.println("W: Prefs RW Fail for saving chaincode/rotation");
        }
        HDPrivateKey preRotatedKey = currentKey.derive(rotationPathSegment.c_str());
        if (!preRotatedKey.isValid()) {
          errorMessage = "Pre-Rotated Key Invalid (PathSeg: " + rotationPathSegment + ")";
          displayErrorScreen(errorMessage);
          goto end_wallet_view_logic;
        }
        HDPrivateKey twicePreRotatedKey = preRotatedKey.derive(rotationPathSegment.c_str());
        if (!twicePreRotatedKey.isValid()) {
          errorMessage = "Twice-Pre-Rotated Key Invalid (PathSeg: " + rotationPathSegment + ")";
          displayErrorScreen(errorMessage);
          goto end_wallet_view_logic;
        }
        String public_key_hash_prev = "";
        if (currentRotationIndex > 0) {
          HDPrivateKey prevParentKey = hdWalletKey;
          for (int r = 0; r < currentRotationIndex - 1; r++) {
            prevParentKey = prevParentKey.derive(rotationPathSegment.c_str());
            if (!prevParentKey.isValid()) {
              errorMessage = "Prev Parent Key Invalid (Rotation " + String(r) + ")";
              displayErrorScreen(errorMessage);
              goto end_wallet_view_logic;
            }
          }
          PublicKey prevPublicKey = prevParentKey.publicKey();
          prevPublicKey.compressed = false; // Set to uncompressed
          if (String(blockchains[selectedBlockchainIndex].name) == "BSC") {
            unsigned char hash_n_minus_1[32];
            public_key_hash_prev = keccak256Address(prevPublicKey, hash_n_minus_1);
          } else {
            public_key_hash_prev = prevPublicKey.address(blockchains[selectedBlockchainIndex].network);
          }
          if (public_key_hash_prev.length() == 0) {
            errorMessage = "Prev Address Gen Error";
            displayErrorScreen(errorMessage);
            goto end_wallet_view_logic;
          }
          Serial.printf("L: Previous Rotation %d Address: %s\n", currentRotationIndex - 1, public_key_hash_prev.c_str());
        } else {
          Serial.println("L: Index 0, public_key_hash_prev set to blank");
        }
        String wif_n;
        String addr_n_plus_1;
        String addr_n_plus_2;
        if (String(blockchains[selectedBlockchainIndex].name) == "BSC") {
            wif_n = currentKey.wif();
            unsigned char hash_n_plus_1[32];
            unsigned char hash_n_plus_2[32];
            
            // Derive public keys and set uncompressed format
            PublicKey pubKey1 = preRotatedKey.publicKey();
            pubKey1.compressed = false; // Set to uncompressed
            Serial.println("preRotatedKey Public Key: " + pubKey1.toString());
            addr_n_plus_1 = keccak256Address(pubKey1, hash_n_plus_1); // Use returned checksummed address
            
            PublicKey pubKey2 = twicePreRotatedKey.publicKey();
            pubKey2.compressed = false; // Set to uncompressed
            Serial.println("twicePreRotatedKey Public Key: " + pubKey2.toString());
            addr_n_plus_2 = keccak256Address(pubKey2, hash_n_plus_2); // Use returned checksummed address
            
            Serial.println("BSC Address n+1: " + addr_n_plus_1);
            Serial.println("BSC Address n+2: " + addr_n_plus_2);
        } else {
            // YadaCoin: Use Bitcoin-style addresses
            wif_n = currentKey.wif();
            addr_n_plus_1 = preRotatedKey.publicKey().address(blockchains[selectedBlockchainIndex].network);
            addr_n_plus_2 = twicePreRotatedKey.publicKey().address(blockchains[selectedBlockchainIndex].network);
        }
        bool derivation_ok = true;
        String error_msg_detail = "";
        if (wif_n.length() == 0) {
          error_msg_detail = "WIF_n Gen Fail";
          derivation_ok = false;
        }
        if (derivation_ok && addr_n_plus_1.length() == 0) {
          error_msg_detail = "Addr_n+1 Gen Fail";
          derivation_ok = false;
        }
        if (derivation_ok && addr_n_plus_2.length() == 0) {
          error_msg_detail = "Addr_n+2 Gen Fail";
          derivation_ok = false;
        }
        if (derivation_ok && currentRotationIndex > 0 && public_key_hash_prev.length() == 0) {
          error_msg_detail = "Prev Address Gen Fail";
          derivation_ok = false;
        }
        if (derivation_ok) {
          String combinedQRData = wif_n + "|" + addr_n_plus_1 + "|" + addr_n_plus_2 + "|" + public_key_hash_prev + "|" + String(currentRotationIndex);
          Serial.println("QR Data: " + combinedQRData);
          Serial.println("QR Data Length: " + String(combinedQRData.length()));
          int estimatedQrVersion = 12;
          
          // Initialize buttons based on currentRotationIndex
          int numButtons = (currentRotationIndex > 0) ? 4 : 3; // Include BTN_LEFT only if rotation > 0
          int leftButtonCenterX = 65;
          int leftButtonCenterY = 205;
          int rightButtonCenterX = 255;
          int rightButtonCenterY = 205;
          int secretButtonCenterX = tft.width() - (SECRET_BUTTON_SIZE / 2) - 5;
          int secretButtonCenterY = (SECRET_BUTTON_SIZE / 2) + 5;
          int jumpButtonCenterX = tft.width() - (SECRET_BUTTON_SIZE / 2) - 5;
          int jumpButtonCenterY = (SECRET_BUTTON_SIZE / 2) + 5 + SECRET_BUTTON_SIZE + 5;
          
          // Always initialize BTN_RIGHT, BTN_SECRET, and BTN_JUMP
          buttons[BTN_RIGHT].initButton(&tft, rightButtonCenterX, rightButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Next >", 2);
          buttons[BTN_SECRET].initButton(&tft, secretButtonCenterX, secretButtonCenterY, SECRET_BUTTON_SIZE, SECRET_BUTTON_SIZE, TFT_WHITE, TFT_ORANGE, TFT_BLACK, "Seed", 1);
          buttons[BTN_JUMP].initButton(&tft, jumpButtonCenterX, jumpButtonCenterY, SECRET_BUTTON_SIZE, SECRET_BUTTON_SIZE, TFT_WHITE, TFT_CYAN, TFT_BLACK, "Jump", 1);
          
          if (currentRotationIndex > 0) {
            buttons[BTN_LEFT].initButton(&tft, leftButtonCenterX, leftButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "< Prev", 2);
          } else {
            // Explicitly clear BTN_LEFT to prevent any rendering
            buttons[BTN_LEFT].initButton(&tft, 0, 0, 0, 0, TFT_TRANSPARENT, TFT_TRANSPARENT, TFT_TRANSPARENT, "", 0);
          }
          
          // Clear the area where BTN_LEFT would be to prevent artifacts
          if (currentRotationIndex == 0) {
            tft.fillRect(leftButtonCenterX - BUTTON_W / 2, leftButtonCenterY - BUTTON_H / 2, BUTTON_W, BUTTON_H, TFT_WHITE); // Match QR background
          }
          
          // Draw QR code and buttons
          displaySingleRotationQR(currentRotationIndex, combinedQRData, "Rotation", estimatedQrVersion);
        } else {
          displayErrorScreen(error_msg_detail.length() > 0 ? error_msg_detail : "Derivation Error");
        }
        Serial.print("L: Heap After Wallet Redraw: ");
        Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
      }
      end_wallet_view_logic:;
      break;
    }

    case STATE_SHOW_SECRET_MNEMONIC:
      if (redrawScreen) displaySecretMnemonicScreen(loadedMnemonic);
      if (buttonLeftTriggered) {
        Serial.println("L: Exit Secret Mnemonic screen.");
        currentState = STATE_WALLET_VIEW;
      }
      break;

    case STATE_JUMP_ENTRY:
      if (redrawScreen) {
        showJumpEntryScreen();
        Serial.println("L: Jump Entry Screen Redrawn");
      }
      if (buttonLeftTriggered) {
        currentJumpDigitValue = (currentJumpDigitValue + 1) % 10;
        showJumpEntryScreen();
        Serial.printf("L: Jump Digit cycled to %d at index %d\n", currentJumpDigitValue, currentJumpDigitIndex);
      } else if (buttonRightTriggered) {
        Serial.printf("L: Jump Right Button (Next/OK) Pressed at digit index %d\n", currentJumpDigitIndex);
        jumpIndex[currentJumpDigitIndex] = currentJumpDigitValue + '0';
        currentJumpDigitIndex++;
        currentJumpDigitValue = 0;
        if (currentJumpDigitIndex >= JUMP_INDEX_LENGTH) {
          jumpIndex[JUMP_INDEX_LENGTH] = '\0';
          Serial.print("L: Full Jump Index Entered: ");
          Serial.println(jumpIndex);
          int newRotationIndex = 0;
          for (int i = 0; i < JUMP_INDEX_LENGTH; i++) {
            if (jumpIndex[i] >= '0' && jumpIndex[i] <= '9') {
              newRotationIndex = newRotationIndex * 10 + (jumpIndex[i] - '0');
            } else {
              newRotationIndex = 0;
              break;
            }
          }
          if (newRotationIndex >= 0 && newRotationIndex <= MAX_ROTATION_INDEX) {
            currentRotationIndex = newRotationIndex;
            Serial.printf("L: Jump to Rotation Index %d\n", currentRotationIndex);
            currentState = STATE_WALLET_VIEW;
          } else {
            errorMessage = "Invalid Rotation Index";
            Serial.println("E: " + errorMessage);
            displayErrorScreen(errorMessage);
            currentState = STATE_ERROR;
            currentJumpDigitIndex = 0;
            currentJumpDigitValue = 0;
            memset(jumpIndex, '_', JUMP_INDEX_LENGTH);
            jumpIndex[JUMP_INDEX_LENGTH] = '\0';
          }
        } else {
          showJumpEntryScreen();
          Serial.printf("L: Jump Digit entered, index now %d\n", currentJumpDigitIndex);
        }
      }
      break;

    case STATE_ERROR:
      if (buttonLeftTriggered) {
        Serial.println("L: Error Acknowledged.");
        currentState = provisioned ? STATE_PASSWORD_ENTRY : STATE_WALLET_TYPE_SELECTION;
        if (!provisioned) newWalletMode = false;
        currentDigitIndex = 0;
        currentDigitValue = 0;
        passwordConfirmed = false;
        memset(password, '_', PIN_LENGTH);
        password[PIN_LENGTH] = '\0';
        cursorPos = 0;
        strcpy(currentWordBuffer, "");
      }
      break;

    default:
      Serial.printf("E: Unknown State %d\n", currentState);
      errorMessage = "Unknown State Error";
      displayErrorScreen(errorMessage);
      currentState = provisioned ? STATE_PASSWORD_ENTRY : STATE_WALLET_TYPE_SELECTION;
      if (!provisioned) newWalletMode = false;
      currentDigitIndex = 0;
      currentDigitValue = 0;
      passwordConfirmed = false;
      memset(password, '_', PIN_LENGTH);
      password[PIN_LENGTH] = '\0';
      cursorPos = 0;
      strcpy(currentWordBuffer, "");
      break;
  }
}

String getPossibleNextLetters(const char* buffer, int prefixLen) {
  bool hasLetter[26] = {false};
  for (int i = 0; i < 2048; i++) {
    if (strncmp(wordlist[i], buffer, prefixLen) == 0 && strlen(wordlist[i]) > prefixLen) {
      char nextChar = wordlist[i][prefixLen];
      int idx = getLetterIndex(nextChar);
      if (idx >= 0) hasLetter[idx] = true;
    }
  }
  String possibles = "";
  for (int j = 0; j < 26; j++) {
    if (hasLetter[j]) possibles += alphabet[j];
  }
  return possibles;
}

String getFirstMatchingWord(const char* prefix) {
  int prefixLen = strlen(prefix);
  for (int i = 0; i < 2048; i++) {
    if (strncmp(wordlist[i], prefix, prefixLen) == 0) {
      return String(wordlist[i]);
    }
  }
  return "None";
}