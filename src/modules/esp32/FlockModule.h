#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && !MESHTASTIC_EXCLUDE_FLOCK

#include "SinglePortModule.h"
#include "concurrency/OSThread.h"
#include <NimBLEDevice.h>

/**
 * FlockModule - Surveillance Camera Detection System
 *
 * Integrates the flock-you project (https://github.com/colonelpanichacks/flock-you)
 * into Meshtastic firmware to detect Flock Safety cameras, Raven gunshot detectors,
 * and similar surveillance devices.
 *
 * Detection methods:
 * - WiFi promiscuous mode scanning (probe requests and beacon frames)
 * - Bluetooth Low Energy (BLE) advertisement monitoring
 * - MAC address prefix matching
 * - SSID pattern recognition
 * - Device name pattern matching
 * - BLE service UUID fingerprinting (for Raven devices)
 */
class FlockModule : public SinglePortModule, private concurrency::OSThread
{
  public:
    FlockModule();
    virtual ~FlockModule();

    // Start/stop scanning
    void startScanning();
    void stopScanning();
    bool isScanning() const { return scanning; }

    // Check if module can run (WiFi/BLE availability)
    bool isActive();
    bool canUseWiFi();
    bool canUseBLE();

  protected:
    virtual int32_t runOnce() override;

  private:
    bool firstTime = true;
    bool scanning = false;
    bool wifiScanEnabled = false;  // True if WiFi promiscuous mode is active
    bool bleScanEnabled = false;   // True if BLE scanning is active
    uint32_t lastSentToMesh = 0;
    uint32_t lastBLEScan = 0;
    uint8_t currentChannel = 1;
    unsigned long lastChannelHop = 0;
    bool deviceInRange = false;
    unsigned long lastDetectionTime = 0;
    unsigned long lastHeartbeat = 0;
    bool triggered = false;

    // BLE scanner
    NimBLEScan *pBLEScan = nullptr;

    // Detection methods
    bool checkMacPrefix(const uint8_t *mac);
    bool checkSSIDPattern(const char *ssid);
    bool checkDeviceNamePattern(const char *name);
    bool checkRavenServiceUUID(NimBLEAdvertisedDevice *device, char *detectedServiceOut = nullptr);
    const char *getRavenServiceDescription(const char *uuid);
    const char *estimateRavenFirmwareVersion(NimBLEAdvertisedDevice *device);

    // Message sending
    void sendDetectionMessage(const char *deviceType, const char *identifier, int rssi, const char *method);
    void sendHeartbeatMessage();

    // WiFi promiscuous mode
    void initWiFiPromiscuous();
    void hopChannel();
    static void wifiSnifferPacketHandler(void *buff, wifi_promiscuous_pkt_type_t type);

    // BLE scanning
    void initBLEScanner();
    void performBLEScan();

    // Singleton for WiFi callback
    static FlockModule *instance;

    // BLE callback class
    class AdvertisedDeviceCallbacks : public NimBLEAdvertisedDeviceCallbacks
    {
      public:
        AdvertisedDeviceCallbacks(FlockModule *module) : flockModule(module) {}
        void onResult(NimBLEAdvertisedDevice *advertisedDevice) override;

      private:
        FlockModule *flockModule;
    };

    AdvertisedDeviceCallbacks *bleCallbacks = nullptr;
};

extern FlockModule *flockModule;

#endif // ARCH_ESP32 && !MESHTASTIC_EXCLUDE_FLOCK
