#include <Arduino.h>
#include <Arduino.h>
#include <string.h>
// Bluetooth includes
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <BLE2902.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEClient.h>
#include <BLEAdvertisedDevice.h>
//mbed includes
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ecp.h>

// ecdh & aes statics
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

static mbedtls_ecp_group   ecp_group;
static mbedtls_mpi         privKey;      // our private scalar d
static mbedtls_ecp_point   pubKey;       // our public point Q
static mbedtls_ecp_point   peerPubKey; 

static uint8_t aes_key[32];
static bool handshakeDone = false;

void crypto_init() 
{
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  const char *pers = "random_seed"; // this string helps generate a random nonce. This can be known by everyone and should still help create unique nonce
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));

  mbedtls_ecp_group_init(&ecp_group);
  mbedtls_mpi_init(&privKey);
  mbedtls_ecp_point_init(&pubKey);
  mbedtls_ecp_point_init(&peerPubKey);

  mbedtls_ecp_group_load(&ecp_group, MBEDTLS_ECP_DP_SECP256R1);
}

// Generate local keypair and return our public key in outPub
size_t ecdh_generate_public(uint8_t *outPub, size_t outSize) 
{
  size_t olen = 0;

  int ret = mbedtls_ecdh_gen_public(&ecp_group, &privKey, &pubKey, mbedtls_ctr_drbg_random, &ctr_drbg);
  
  if (ret != 0) 
  {
    Serial.print("mbedtls_ecdh_gen_public failed: ");
    Serial.println(ret);
    return 0;
  }

  ret = mbedtls_ecp_point_write_binary(&ecp_group, &pubKey, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, outPub, outSize);

  if (ret != 0) {
    Serial.print("mbedtls_ecp_point_write_binary failed: ");
    Serial.println(ret);
    return 0;
  }

  return olen;
}

// Given peer public key, compute shared secret and derive AES-256 key
void ecdh_compute_key_and_derive_aes(const uint8_t *peerPub, size_t peerLen) {
  int ret;

  // Load peer public key into ecdh_ctx.Qp
  ret = mbedtls_ecp_point_read_binary(&ecp_group, &peerPubKey, peerPub, peerLen);
  if (ret != 0)
  {
    Serial.print("mbedtls_ecp_point_read_binary failed: ");
    Serial.println(ret);
    return;
  }

  // Compute shared secret
  mbedtls_mpi shared;
  mbedtls_mpi_init(&shared);

  ret = mbedtls_ecdh_compute_shared(&ecp_group, &shared, &peerPubKey, &privKey, mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0)
  {
    Serial.print("mbedtls_ecdh_compute_shared failed: ");
    Serial.println(ret);
    mbedtls_mpi_free(&shared);
    return;
  }

  // Export shared secret to bytes
  uint8_t secretBuf[32];
  memset(secretBuf, 0, sizeof(secretBuf));

  size_t secretLen = mbedtls_mpi_size(&shared);
  if (secretLen > sizeof(secretBuf)) secretLen = sizeof(secretBuf);
  mbedtls_mpi_write_binary(&shared, secretBuf, secretLen);
  mbedtls_mpi_free(&shared);

  // Derive AES key = SHA-256(sharedSecret)
  mbedtls_sha256(secretBuf, secretLen, aes_key, 0);
  handshakeDone = true;
}

size_t pkcs7_pad(const uint8_t *in, size_t inLen, uint8_t *out, size_t blockSize) 
{
  size_t padLen = blockSize - (inLen % blockSize);
  memcpy(out, in, inLen);
  for (size_t i = 0; i < padLen; i++) 
  {
    out[inLen + i] = (uint8_t)padLen;
  }
  return inLen + padLen;
}

size_t pkcs7_unpad(uint8_t *buf, size_t len, size_t blockSize) 
{
  if (len == 0 || (len % blockSize) != 0) 
    return 0;
  uint8_t padLen = buf[len - 1];
  if (padLen == 0 || padLen > blockSize) 
    return 0;
  return len - padLen;
}

size_t aes256_encrypt(const uint8_t *plaintext, size_t plen, const uint8_t key[32], const uint8_t iv[16], uint8_t *out) {
  uint8_t padded[256];   
  size_t paddedLen = pkcs7_pad(plaintext, plen, padded, 16);

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, key, 256);

  uint8_t ivCopy[16];
  memcpy(ivCopy, iv, 16);

  mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, paddedLen, ivCopy, padded, out);

  mbedtls_aes_free(&ctx);
  return paddedLen;
}

size_t aes256_decrypt(const uint8_t *cipher, size_t clen, const uint8_t key[32], const uint8_t iv[16], uint8_t *out) {
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_dec(&ctx, key, 256);

  uint8_t ivCopy[16];
  memcpy(ivCopy, iv, 16);

  mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, clen, ivCopy, cipher, out);

  mbedtls_aes_free(&ctx);

  size_t plainLen = pkcs7_unpad(out, clen, 16);
  return plainLen;
}

void generate_iv(uint8_t iv[16]) 
{
  for (int i = 0; i < 4; i++) 
  {
    uint32_t r = esp_random();
    memcpy(iv + i * 4, &r, 4);
  }
}

void printHex(const uint8_t *data, size_t len) 
{
  for (size_t i = 0; i < len; i++) 
  {
    if (data[i] < 0x10) Serial.print('0');
    Serial.print(data[i], HEX);
  }
  Serial.println();
}

// defines for bluetooth
#define SERVICE_UUID        "12345678-1234-1234-1234-1234567890ab"
#define CHARACTERISTIC_UUID "abcdefab-1234-5678-1234-abcdefabcdef"

static BLEAddress *pServerAddress = nullptr;
static bool doConnect = false;
static bool connected = false;

static BLERemoteCharacteristic* pRemoteCharacteristic = nullptr;

// Called when a notification is received from the server
static void notifyCallback(
  BLERemoteCharacteristic* pBLERemoteCharacteristic,
  uint8_t* pData,
  size_t length,
  bool isNotify
) {
  if (!handshakeDone) {
    // Should not happen if handshake is done first
    Serial.println("Notification received before handshake complete");
    return;
  }

  if (length < 16) { // need at least an IV
    Serial.println("Ciphertext too short");
    return;
  }

  uint8_t iv[16];
  memcpy(iv, pData, 16);

  uint8_t *cipher = pData + 16;
  size_t cipherLen = length - 16;

  Serial.print("Received ciphertext: ");
  printHex(pData, length);

  uint8_t plaintext[256];
  size_t plainLen = aes256_decrypt(cipher, cipherLen, aes_key, iv, plaintext);

  if (plainLen == 0) {
    Serial.println("Decryption / padding error");
    return;
  }

  // Ensure null-terminated string for printing
  if (plainLen >= sizeof(plaintext)) plainLen = sizeof(plaintext) - 1;
  plaintext[plainLen] = 0;

  Serial.print("Decrypted text: ");
  Serial.println((char*)plaintext);
}


// Advertised device callbacks: find our server by name or UUID
class MyAdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) override {
    // Match by name or by service UUID
    if (advertisedDevice.getName() == "ESP32_Chat_Server" ||
        advertisedDevice.haveServiceUUID() &&
        advertisedDevice.isAdvertisingService(BLEUUID(SERVICE_UUID))) {

      Serial.println("Found target server, stopping scan");
      BLEDevice::getScan()->stop();
      pServerAddress = new BLEAddress(advertisedDevice.getAddress());
      doConnect = true;
    }
  }
};

bool connectToServer(BLEAddress pAddress) {
  Serial.print("Connecting to server at: ");
  Serial.println(pAddress.toString().c_str());

  BLEClient* pClient = BLEDevice::createClient();
  if (!pClient->connect(pAddress)) {
    Serial.println("Failed to connect");
    return false;
  }

  Serial.println("Connected to server");

  BLERemoteService* pRemoteService = pClient->getService(SERVICE_UUID);
  if (pRemoteService == nullptr) {
    Serial.println("Failed to find our service UUID");
    pClient->disconnect();
    return false;
  }

  pRemoteCharacteristic = pRemoteService->getCharacteristic(CHARACTERISTIC_UUID);

  crypto_init();

  String srvPub = pRemoteCharacteristic->readValue();
  const uint8_t *serverPub = (const uint8_t*)srvPub.c_str();
  size_t serverPubLen = srvPub.length();
  Serial.print("Got server public key (");
  Serial.print(serverPubLen);
  Serial.println(" bytes)");

  uint8_t clientPub[65];
  size_t clientPubLen = ecdh_generate_public(clientPub, sizeof(clientPub));

  ecdh_compute_key_and_derive_aes(serverPub, serverPubLen);
  Serial.println("Shared AES key derived on client.");

  pRemoteCharacteristic->writeValue(clientPub, clientPubLen, true);

  Serial.println("Client public key sent to server.");

  if (pRemoteCharacteristic == nullptr) {
    Serial.println("Failed to find our characteristic UUID");
    pClient->disconnect();
    return false;
  }

  // Enable notifications so we get messages
  if (pRemoteCharacteristic->canNotify()) {
    pRemoteCharacteristic->registerForNotify(notifyCallback);
  }

  Serial.println("Ready to chat!");
  return true;
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("Starting BLE Chat Client...");

  // No pairing/bonding configuration => unencrypted
  BLEDevice::init("ESP32_Chat_Client");

  // Start scan
  BLEScan* pScan = BLEDevice::getScan();
  pScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pScan->setInterval(1349);
  pScan->setWindow(449);
  pScan->setActiveScan(true);
  pScan->start(5, false);  // scan for 5 seconds, no stop after callback
}

void loop() {
  if (doConnect && pServerAddress != nullptr) {
    if (connectToServer(*pServerAddress)) {
      connected = true;
    } else {
      Serial.println("Retrying scan...");
      BLEDevice::getScan()->start(5, false);
    }
    doConnect = false;
  }

  // If connected, read Serial and send to server
  if (connected && handshakeDone && pRemoteCharacteristic && Serial.available())
  {
    String msg = Serial.readStringUntil('\n');
    msg.trim();
    if (msg.length() > 0) 
    {
      uint8_t iv[16];
      generate_iv(iv);

      uint8_t cipher[16 + 256];   // 16 bytes IV + ciphertext
      uint8_t *cipherBody = cipher + 16;

      // Encrypt the message using AES-256-CBC
      size_t cipherLen = aes256_encrypt(
        (const uint8_t*)msg.c_str(),
        msg.length(),
        aes_key,
        iv,
        cipherBody
      );

      // Prepend IV
      memcpy(cipher, iv, 16);
      size_t totalLen = 16 + cipherLen;
      Serial.print("Sending Msg: ");
      Serial.println(msg);
      Serial.print("Sending ciphertext: ");
      printHex(cipher, totalLen);
      Serial.println("");

      // Send IV + ciphertext to server
      pRemoteCharacteristic->writeValue(cipher, totalLen, true);
    }
  }

  delay(10);
}
