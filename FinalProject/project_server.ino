#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <Arduino.h>
#include <string.h>
// Bluetooth includes
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <BLE2902.h>
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
  mbedtls_entropy_init(&entropy);     // initialize the context at entropy
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

BLEServer* pServer = nullptr;
BLECharacteristic* pChatCharacteristic = nullptr;
bool deviceConnected = false;

// Callback to know when client connects/disconnects
class MyServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer* pServer) override 
  {
    deviceConnected = true;
    Serial.println("Client connected");
  }

  void onDisconnect(BLEServer* pServer) override 
  {
    deviceConnected = false;
    Serial.println("Client disconnected");
    // Restart advertising so client can reconnect
    pServer->getAdvertising()->start();
    Serial.println("Advertising restarted");
  }
};

// Callback to handle messages written by the client
class ChatCallbacks : public BLECharacteristicCallbacks 
{
  void onWrite(BLECharacteristic* pCharacteristic) override 
  {
    String value = pCharacteristic->getValue();
    const uint8_t *buf = (const uint8_t*)value.c_str();
    size_t len = value.length();

    if (!handshakeDone) 
    {
      // First message from client = its ECDH public key
      Serial.println("Received client ECDH public key");
      ecdh_compute_key_and_derive_aes(buf, len);
      Serial.println("Shared AES key derived. Handshake complete.");
      return;
    }

    if (len < 16) 
    {
      Serial.println("Received data too short to contain IV + ciphertext");
      return;
    }

    uint8_t iv[16];
    memcpy(iv, buf, 16);

    const uint8_t *cipher = buf + 16;
    size_t cipherLen = len - 16;

    Serial.print("Received ciphertext: ");
    printHex(buf, len);   // print IV + ciphertext as hex

    uint8_t plaintext[256];
    size_t plainLen = aes256_decrypt(cipher, cipherLen, aes_key, iv, plaintext);

    if (plainLen == 0) 
    {
      Serial.println("Decryption / padding error on server");
      return;
    }

    // Null-terminate for safe printing
    if (plainLen >= sizeof(plaintext)) plainLen = sizeof(plaintext) - 1;
    plaintext[plainLen] = 0;

    Serial.print("Decrypted text: ");
    Serial.println((char*)plaintext);
  }
};

void setup() 
{
  Serial.begin(115200);
  delay(1000);
  Serial.println("Starting BLE Chat Server...");

  crypto_init();

  uint8_t serverPub[65];
  size_t serverPubLen = ecdh_generate_public(serverPub, sizeof(serverPub));

  // No explicit security setup => no pairing/bonding, unencrypted
  BLEDevice::init("ESP32_Chat_Server");

  pServer = BLEDevice::createServer();
  pServer->setCallbacks(new MyServerCallbacks());

  BLEService* pService = pServer->createService(SERVICE_UUID);

  pChatCharacteristic = pService->createCharacteristic(
    CHARACTERISTIC_UUID,
    BLECharacteristic::PROPERTY_READ   |
    BLECharacteristic::PROPERTY_WRITE  |
    BLECharacteristic::PROPERTY_NOTIFY |
    BLECharacteristic::PROPERTY_INDICATE
  );

  pChatCharacteristic->setCallbacks(new ChatCallbacks());


  pChatCharacteristic->setValue(serverPub, serverPubLen);

  
  pChatCharacteristic->addDescriptor(new BLE2902());

  pService->start();

  BLEAdvertising* pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(SERVICE_UUID);
  pAdvertising->setScanResponse(true);
  pAdvertising->setMinPreferred(0x06);
  pAdvertising->setMaxPreferred(0x12);
  BLEDevice::startAdvertising();

  Serial.println("BLE Chat Server is advertising");
}

void loop() 
{
  
  if (deviceConnected && handshakeDone && Serial.available()) 
  {
    String msg = Serial.readStringUntil('\n');
    msg.trim();
    if (msg.length() > 0) {
      uint8_t iv[16];
      generate_iv(iv);

      uint8_t cipher[16 + 256]; // 16 bytes IV + ciphertext
      uint8_t *cipherBody = cipher + 16;

      size_t cipherLen = aes256_encrypt(
        (const uint8_t*)msg.c_str(), msg.length(),
        aes_key, iv,
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

      pChatCharacteristic->setValue(cipher, totalLen);
      pChatCharacteristic->notify();
    }
  }

  delay(10);
}
