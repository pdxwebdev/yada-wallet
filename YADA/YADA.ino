#include <mbedtls/sha256.h>
#include <uECC.h>
#include <U8g2lib.h>
#include <Preferences.h>

// OLED initialization
U8G2_SH1106_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, U8X8_PIN_NONE);
Preferences preferences;

uint8_t privateKey[32];
uint8_t publicKey[65];

// Define Base58 alphabet
const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Function to perform double SHA-256 hash
void doubleSHA256(const uint8_t* input, size_t length, uint8_t* output) {
  uint8_t hash1[32];
  mbedtls_sha256(input, length, hash1, 0);
  mbedtls_sha256(hash1, 32, output, 0);
}

// Function to convert private key to WIF
String privateKeyToWIF(uint8_t* privateKey) {
  uint8_t extendedKey[34];
  uint8_t checksum[32];

  // Add network prefix (0x80 for Bitcoin mainnet or equivalent for Yada)
  extendedKey[0] = 0x80;
  memcpy(&extendedKey[1], privateKey, 32);

  // Add compression flag (optional)
  extendedKey[33] = 0x01;

  // Compute checksum
  doubleSHA256(extendedKey, 34, checksum);

  // Append checksum to extended key
  uint8_t finalKey[38];
  memcpy(finalKey, extendedKey, 34);
  memcpy(&finalKey[34], checksum, 4);

  // Base58Check encode the final key
  return base58CheckEncode(finalKey, 38);
}

// Function to perform Base58Check encoding
String base58CheckEncode(uint8_t* payload, size_t payloadLength) {
  uint8_t digits[50] = {0};
  size_t digitLength = 1;

  for (size_t i = 0; i < payloadLength; i++) {
    int carry = payload[i];
    for (size_t j = 0; j < digitLength; j++) {
      carry += digits[j] * 256;
      digits[j] = carry % 58;
      carry /= 58;
    }
    while (carry) {
      digits[digitLength++] = carry % 58;
      carry /= 58;
    }
  }

  String result = "";
  for (size_t i = 0; i < payloadLength && payload[i] == 0; i++) {
    result += BASE58_ALPHABET[0];
  }
  for (int i = digitLength - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}

// Flash LED function
void flashLED(int flashes, int duration) {
  for (int i = 0; i < flashes; i++) {
    digitalWrite(2, HIGH);
    delay(duration);
    digitalWrite(2, LOW);
    delay(duration);
  }
}

void setup() {
  Serial.begin(115200);
  delay(2000);
  Serial.println("Starting up...");

  // Initialize OLED
  u8g2.begin();
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x10_tr);
  u8g2.drawStr(0, 20, "Initializing...");
  u8g2.sendBuffer();
  delay(2000);

  preferences.begin("wallet", false);
  String storedWIF = preferences.getString("privateKey", "");
  String storedAddress = preferences.getString("publicAddress", "");

  if (storedWIF.length() == 0 || storedAddress.length() == 0) {
    Serial.println("No stored keys found. Generating new ones...");

    // Generate private key
    for (int i = 0; i < 32; i++) privateKey[i] = esp_random() & 0xFF;

    // Generate WIF
    String wif = privateKeyToWIF(privateKey);
    Serial.println("Generated WIF: " + wif);

    // Generate placeholder public address
    String publicAddress = "YadaCoinPlaceholder"; // Replace with actual public address logic

    preferences.putString("privateKey", wif);
    preferences.putString("publicAddress", publicAddress);
    storedWIF = wif;
    storedAddress = publicAddress;

    Serial.println("Stored WIF and Address.");
  } else {
    Serial.println("Stored keys found.");
  }

  // Display WIF
  Serial.println("Displaying WIF on OLED...");
  u8g2.clearBuffer();
  u8g2.drawStr(0, 10, "WIF:");
  for (int i = 0; i < (int)storedWIF.length(); i += 20) {
    String line = storedWIF.substring(i, i + 20);
    u8g2.drawStr(0, 20 + (i / 20) * 10, line.c_str());
  }
  u8g2.sendBuffer();
  delay(20000);

  // Flash LED 2 times
  flashLED(2, 300);

  // Display Address
  Serial.println("Displaying Address on OLED...");
  u8g2.clearBuffer();
  u8g2.drawStr(0, 10, "Address:");
  for (int i = 0; i < (int)storedAddress.length(); i += 20) {
    String line = storedAddress.substring(i, i + 20);
    u8g2.drawStr(0, 20 + (i / 20) * 10, line.c_str());
  }
  u8g2.sendBuffer();
  delay(5000);

  preferences.end();
  Serial.println("Setup complete.");
}

void loop() {
  // Nothing needed in the loop
}
