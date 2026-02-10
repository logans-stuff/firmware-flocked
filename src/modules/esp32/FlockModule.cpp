#include "configuration.h"

#if defined(ARCH_ESP32) && !MESHTASTIC_EXCLUDE_FLOCK

#include "FlockModule.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "GPSStatus.h"
#include "main.h"
#include <Throttle.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <cstring>

// config is already declared in NodeDB.h as meshtastic_LocalConfig

FlockModule *flockModule = nullptr;
FlockModule *FlockModule::instance = nullptr;

// Configuration
#define FLOCK_CHANNEL_HOP_INTERVAL 500    // milliseconds between WiFi channel hops
#define FLOCK_MAX_CHANNEL 13              // Max WiFi channel
#define FLOCK_BLE_SCAN_DURATION 1         // BLE scan duration in seconds
#define FLOCK_BLE_SCAN_INTERVAL 5000      // milliseconds between BLE scans
#define FLOCK_MIN_BROADCAST_INTERVAL 30000 // minimum 30 seconds between mesh broadcasts
#define FLOCK_HEARTBEAT_INTERVAL 60000    // heartbeat every 60 seconds while device in range
#define FLOCK_DEVICE_TIMEOUT 120000       // device considered out of range after 2 minutes
#define FLOCK_DEDUPE_INTERVAL 1800000     // 30 minutes - don't re-alert for same device within this window
#define FLOCK_DEDUPE_CLEANUP_INTERVAL 300000 // cleanup old entries every 5 minutes

// WiFi SSID patterns to detect (case-insensitive)
static const char *wifi_ssid_patterns[] = {
    "flock",
    "Flock",
    "FLOCK",
    "FS Ext Battery",
    "Penguin",
    "Pigvision"
};
static const int wifi_ssid_patterns_count = sizeof(wifi_ssid_patterns) / sizeof(wifi_ssid_patterns[0]);

// Known surveillance device MAC address prefixes
static const char *mac_prefixes[] = {
    // FS Ext Battery devices
    "58:8e:81", "cc:cc:cc", "ec:1b:bd", "90:35:ea", "04:0d:84",
    "f0:82:c0", "1c:34:f1", "38:5b:44", "94:34:69", "b4:e3:f9",
    // Flock WiFi devices
    "70:c9:4e", "3c:91:80", "d8:f3:bc", "80:30:49", "14:5a:fc",
    "74:4c:a1", "08:3a:88", "9c:2f:9d", "94:08:53", "e4:aa:ea"
};
static const int mac_prefixes_count = sizeof(mac_prefixes) / sizeof(mac_prefixes[0]);

// Device name patterns for BLE advertisement detection
static const char *device_name_patterns[] = {
    "FS Ext Battery",
    "Penguin",
    "Flock",
    "Pigvision"
};
static const int device_name_patterns_count = sizeof(device_name_patterns) / sizeof(device_name_patterns[0]);

// Raven surveillance device service UUIDs
#define RAVEN_DEVICE_INFO_SERVICE "0000180a-0000-1000-8000-00805f9b34fb"
#define RAVEN_GPS_SERVICE "00003100-0000-1000-8000-00805f9b34fb"
#define RAVEN_POWER_SERVICE "00003200-0000-1000-8000-00805f9b34fb"
#define RAVEN_NETWORK_SERVICE "00003300-0000-1000-8000-00805f9b34fb"
#define RAVEN_UPLOAD_SERVICE "00003400-0000-1000-8000-00805f9b34fb"
#define RAVEN_ERROR_SERVICE "00003500-0000-1000-8000-00805f9b34fb"
#define RAVEN_OLD_HEALTH_SERVICE "00001809-0000-1000-8000-00805f9b34fb"
#define RAVEN_OLD_LOCATION_SERVICE "00001819-0000-1000-8000-00805f9b34fb"

static const char *raven_service_uuids[] = {
    RAVEN_DEVICE_INFO_SERVICE,
    RAVEN_GPS_SERVICE,
    RAVEN_POWER_SERVICE,
    RAVEN_NETWORK_SERVICE,
    RAVEN_UPLOAD_SERVICE,
    RAVEN_ERROR_SERVICE,
    RAVEN_OLD_HEALTH_SERVICE,
    RAVEN_OLD_LOCATION_SERVICE
};
static const int raven_service_uuids_count = sizeof(raven_service_uuids) / sizeof(raven_service_uuids[0]);

// Helper function for case-insensitive substring search
static const char *strcasestr_local(const char *haystack, const char *needle)
{
    if (!haystack || !needle)
        return nullptr;

    size_t needle_len = strlen(needle);
    if (needle_len == 0)
        return haystack;

    for (const char *p = haystack; *p; p++) {
        if (strncasecmp(p, needle, needle_len) == 0) {
            return p;
        }
    }
    return nullptr;
}

// WiFi packet structure
typedef struct {
    unsigned frame_ctrl : 16;
    unsigned duration_id : 16;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    unsigned sequence_ctrl : 16;
    uint8_t addr4[6];
} wifi_ieee80211_mac_hdr_t;

typedef struct {
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0];
} wifi_ieee80211_packet_t;

FlockModule::FlockModule()
    : SinglePortModule("flock", meshtastic_PortNum_TEXT_MESSAGE_APP), OSThread("FlockModule")
{
    instance = this;
    // Initialize dedup array
    memset(seenDevices, 0, sizeof(seenDevices));
    seenDeviceCount = 0;
}

FlockModule::~FlockModule()
{
    stopScanning();
    if (bleCallbacks) {
        delete bleCallbacks;
        bleCallbacks = nullptr;
    }
    instance = nullptr;
}

bool FlockModule::canUseWiFi()
{
    // WiFi promiscuous mode conflicts with normal WiFi operations
    // Only use if WiFi networking is disabled
    return !config.network.wifi_enabled;
}

bool FlockModule::canUseBLE()
{
    // BLE scanning conflicts with Meshtastic's phone app BLE
    // Only use if Bluetooth is disabled
    return !config.bluetooth.enabled;
}

bool FlockModule::isActive()
{
    // Module is only active if we can use at least one scanning method
    return canUseWiFi() || canUseBLE();
}

void FlockModule::startScanning()
{
    if (scanning)
        return;

    if (!isActive()) {
        LOG_WARN("FlockModule: Cannot start - WiFi and/or Bluetooth in use by Meshtastic");
        LOG_WARN("FlockModule: Disable WiFi (config.network.wifi_enabled) and Bluetooth (config.bluetooth.enabled) to enable surveillance detection");
        return;
    }

    LOG_INFO("FlockModule: Starting surveillance detection scanning");

    // Only init WiFi promiscuous if WiFi is not being used
    if (canUseWiFi()) {
        wifiScanEnabled = true;
        initWiFiPromiscuous();
    } else {
        wifiScanEnabled = false;
        LOG_WARN("FlockModule: WiFi scanning disabled - WiFi in use by Meshtastic networking");
    }

    // Only init BLE scanner if Bluetooth is not being used
    if (canUseBLE()) {
        bleScanEnabled = true;
        initBLEScanner();
    } else {
        bleScanEnabled = false;
        LOG_WARN("FlockModule: BLE scanning disabled - Bluetooth in use by Meshtastic");
    }

    scanning = true;
    triggered = false;
    deviceInRange = false;
    lastDetectionTime = 0;
    lastHeartbeat = 0;
}

void FlockModule::stopScanning()
{
    if (!scanning)
        return;

    LOG_INFO("FlockModule: Stopping surveillance detection scanning");

    // Disable WiFi promiscuous mode if we were using it
    if (wifiScanEnabled) {
        esp_wifi_set_promiscuous(false);
    }

    // Stop BLE scanning if we were using it
    if (bleScanEnabled && pBLEScan && pBLEScan->isScanning()) {
        pBLEScan->stop();
    }

    scanning = false;
    wifiScanEnabled = false;
    bleScanEnabled = false;
}

void FlockModule::initWiFiPromiscuous()
{
    LOG_INFO("FlockModule: Initializing WiFi promiscuous mode");

    // Initialize WiFi in station mode first
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    // Enable promiscuous mode
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&FlockModule::wifiSnifferPacketHandler);
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

    lastChannelHop = millis();
    LOG_INFO("FlockModule: WiFi promiscuous mode enabled on channel %d", currentChannel);
}

void FlockModule::initBLEScanner()
{
    LOG_INFO("FlockModule: Initializing BLE scanner");

    if (!NimBLEDevice::getInitialized()) {
        NimBLEDevice::init("");
    }

    pBLEScan = NimBLEDevice::getScan();
    if (pBLEScan) {
        if (!bleCallbacks) {
            bleCallbacks = new AdvertisedDeviceCallbacks(this);
        }
        pBLEScan->setAdvertisedDeviceCallbacks(bleCallbacks, false);
        pBLEScan->setActiveScan(true);
        pBLEScan->setInterval(100);
        pBLEScan->setWindow(99);
        LOG_INFO("FlockModule: BLE scanner initialized");
    }
}

void FlockModule::hopChannel()
{
    unsigned long now = millis();
    if (now - lastChannelHop > FLOCK_CHANNEL_HOP_INTERVAL) {
        currentChannel++;
        if (currentChannel > FLOCK_MAX_CHANNEL) {
            currentChannel = 1;
            LOG_DEBUG("FlockModule: WiFi channel rotation complete, back to channel 1");
        }
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
        lastChannelHop = now;
        LOG_DEBUG("FlockModule: Hopped to WiFi channel %d", currentChannel);
    }
}

void FlockModule::wifiSnifferPacketHandler(void *buff, wifi_promiscuous_pkt_type_t type)
{
    if (!instance || !instance->scanning || !instance->wifiScanEnabled)
        return;

    // Only process management frames (beacons, probe requests, etc.)
    if (type != WIFI_PKT_MGMT)
        return;

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    // Frame Control: Protocol(2) | Type(2) | Subtype(4) | Flags(8)
    // Type 0 = Management, Subtype 8 = Beacon (0x80), Subtype 4 = Probe Request (0x40)
    uint8_t frame_subtype = (hdr->frame_ctrl & 0xF0);  // Get subtype nibble

    bool isBeacon = (frame_subtype == 0x80);        // Subtype 8 = Beacon
    bool isProbeReq = (frame_subtype == 0x40);      // Subtype 4 = Probe Request
    bool isProbeResp = (frame_subtype == 0x50);     // Subtype 5 = Probe Response

    if (!isBeacon && !isProbeReq && !isProbeResp) {
        return;
    }

    // Extract SSID from management frame
    char ssid[33] = {0};
    uint8_t *frame_body = (uint8_t *)ppkt->payload + 24;  // Skip MAC header (24 bytes)

    if (isBeacon || isProbeResp) {
        // Beacon/Probe Response: skip fixed parameters (timestamp 8 + beacon interval 2 + capability 2 = 12 bytes)
        frame_body += 12;
    }
    // Probe Request: SSID element starts immediately in frame body

    // Parse SSID element (Element ID 0, Length, SSID data)
    if (frame_body[0] == 0 && frame_body[1] <= 32 && frame_body[1] > 0) {
        memcpy(ssid, &frame_body[2], frame_body[1]);
        ssid[frame_body[1]] = '\0';

        // Debug: log all SSIDs we see
        LOG_DEBUG("FlockModule: WiFi saw SSID '%s' RSSI:%d", ssid, ppkt->rx_ctrl.rssi);
    }

    // Check if SSID matches our patterns
    if (strlen(ssid) > 0 && instance->checkSSIDPattern(ssid)) {
        char macStr[18];
        snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                 hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
                 hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);

        const char *detectionType = isBeacon ? "WiFi Beacon" : (isProbeReq ? "WiFi Probe" : "WiFi ProbeResp");
        instance->sendDetectionMessage("Flock/Surveillance", macStr, ppkt->rx_ctrl.rssi, detectionType);
        return;
    }

    // Check MAC address prefix
    if (instance->checkMacPrefix(hdr->addr2)) {
        char macStr[18];
        snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                 hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
                 hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);

        const char *detectionType = isBeacon ? "WiFi Beacon MAC" : (isProbeReq ? "WiFi Probe MAC" : "WiFi ProbeResp MAC");
        instance->sendDetectionMessage("Flock/Surveillance", macStr, ppkt->rx_ctrl.rssi, detectionType);
    }
}

void FlockModule::performBLEScan()
{
    if (!pBLEScan || pBLEScan->isScanning())
        return;

    LOG_DEBUG("FlockModule: Starting BLE scan");
    pBLEScan->start(FLOCK_BLE_SCAN_DURATION, false);
}

void FlockModule::AdvertisedDeviceCallbacks::onResult(NimBLEAdvertisedDevice *advertisedDevice)
{
    if (!flockModule || !flockModule->scanning)
        return;

    NimBLEAddress addr = advertisedDevice->getAddress();
    std::string addrStr = addr.toString();

    // Parse MAC address
    uint8_t mac[6];
    sscanf(addrStr.c_str(), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

    int rssi = advertisedDevice->getRSSI();
    std::string name = "";
    if (advertisedDevice->haveName()) {
        name = advertisedDevice->getName();
    }

    // Check MAC prefix
    if (flockModule->checkMacPrefix(mac)) {
        flockModule->sendDetectionMessage("Flock BLE", addrStr.c_str(), rssi, "BLE MAC");
        return;
    }

    // Check device name
    if (!name.empty() && flockModule->checkDeviceNamePattern(name.c_str())) {
        flockModule->sendDetectionMessage("Flock BLE", name.c_str(), rssi, "BLE Name");
        return;
    }

    // Check for Raven surveillance device service UUIDs
    char detectedServiceUUID[41] = {0};
    if (flockModule->checkRavenServiceUUID(advertisedDevice, detectedServiceUUID)) {
        const char *fwVersion = flockModule->estimateRavenFirmwareVersion(advertisedDevice);
        char deviceInfo[80];
        snprintf(deviceInfo, sizeof(deviceInfo), "Raven FW:%s", fwVersion);
        flockModule->sendDetectionMessage(deviceInfo, addrStr.c_str(), rssi, "Raven UUID");
    }
}

bool FlockModule::checkMacPrefix(const uint8_t *mac)
{
    char macStr[9];
    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x", mac[0], mac[1], mac[2]);

    for (int i = 0; i < mac_prefixes_count; i++) {
        if (strncasecmp(macStr, mac_prefixes[i], 8) == 0) {
            return true;
        }
    }
    return false;
}

bool FlockModule::checkSSIDPattern(const char *ssid)
{
    if (!ssid)
        return false;

    for (int i = 0; i < wifi_ssid_patterns_count; i++) {
        if (strcasestr_local(ssid, wifi_ssid_patterns[i])) {
            return true;
        }
    }
    return false;
}

bool FlockModule::checkDeviceNamePattern(const char *name)
{
    if (!name)
        return false;

    for (int i = 0; i < device_name_patterns_count; i++) {
        if (strcasestr_local(name, device_name_patterns[i])) {
            return true;
        }
    }
    return false;
}

bool FlockModule::checkRavenServiceUUID(NimBLEAdvertisedDevice *device, char *detectedServiceOut)
{
    if (!device || !device->haveServiceUUID())
        return false;

    int serviceCount = device->getServiceUUIDCount();
    if (serviceCount == 0)
        return false;

    for (int i = 0; i < serviceCount; i++) {
        NimBLEUUID serviceUUID = device->getServiceUUID(i);
        std::string uuidStr = serviceUUID.toString();

        for (int j = 0; j < raven_service_uuids_count; j++) {
            if (strcasecmp(uuidStr.c_str(), raven_service_uuids[j]) == 0) {
                if (detectedServiceOut) {
                    strncpy(detectedServiceOut, uuidStr.c_str(), 40);
                }
                return true;
            }
        }
    }
    return false;
}

const char *FlockModule::getRavenServiceDescription(const char *uuid)
{
    if (!uuid)
        return "Unknown";

    if (strcasecmp(uuid, RAVEN_DEVICE_INFO_SERVICE) == 0)
        return "Device Info";
    if (strcasecmp(uuid, RAVEN_GPS_SERVICE) == 0)
        return "GPS Location";
    if (strcasecmp(uuid, RAVEN_POWER_SERVICE) == 0)
        return "Power/Battery";
    if (strcasecmp(uuid, RAVEN_NETWORK_SERVICE) == 0)
        return "Network Status";
    if (strcasecmp(uuid, RAVEN_UPLOAD_SERVICE) == 0)
        return "Upload Stats";
    if (strcasecmp(uuid, RAVEN_ERROR_SERVICE) == 0)
        return "Error Tracking";
    if (strcasecmp(uuid, RAVEN_OLD_HEALTH_SERVICE) == 0)
        return "Health (Legacy)";
    if (strcasecmp(uuid, RAVEN_OLD_LOCATION_SERVICE) == 0)
        return "Location (Legacy)";

    return "Unknown";
}

const char *FlockModule::estimateRavenFirmwareVersion(NimBLEAdvertisedDevice *device)
{
    if (!device || !device->haveServiceUUID())
        return "Unknown";

    bool hasNewGPS = false;
    bool hasOldLocation = false;
    bool hasPowerService = false;

    int serviceCount = device->getServiceUUIDCount();
    for (int i = 0; i < serviceCount; i++) {
        NimBLEUUID serviceUUID = device->getServiceUUID(i);
        std::string uuidStr = serviceUUID.toString();

        if (strcasecmp(uuidStr.c_str(), RAVEN_GPS_SERVICE) == 0)
            hasNewGPS = true;
        if (strcasecmp(uuidStr.c_str(), RAVEN_OLD_LOCATION_SERVICE) == 0)
            hasOldLocation = true;
        if (strcasecmp(uuidStr.c_str(), RAVEN_POWER_SERVICE) == 0)
            hasPowerService = true;
    }

    if (hasOldLocation && !hasNewGPS)
        return "1.1.x";
    if (hasNewGPS && !hasPowerService)
        return "1.2.x";
    if (hasNewGPS && hasPowerService)
        return "1.3.x";

    return "Unknown";
}

// Check if we should alert for this device
// Returns: 0 = skip (deduped), 1 = new detection, 2 = getting closer (RSSI improved)
int FlockModule::shouldAlertForDevice(const char *identifier, int rssi)
{
    if (!identifier)
        return 0;

    uint32_t now = millis();

    // Search for this device in our list
    for (int i = 0; i < seenDeviceCount; i++) {
        if (strncmp(seenDevices[i].identifier, identifier, sizeof(seenDevices[i].identifier) - 1) == 0) {
            // Found it - check if RSSI improved significantly (signal getting stronger = getting closer)
            int rssiImprovement = rssi - seenDevices[i].lastRssi;
            if (rssiImprovement >= RSSI_IMPROVEMENT_THRESHOLD) {
                LOG_INFO("FlockModule: RSSI improved by %d dB (was %d, now %d) - getting closer!",
                         rssiImprovement, seenDevices[i].lastRssi, rssi);
                return 2;  // Getting closer
            }

            // Check if enough time has passed
            uint32_t elapsed = now - seenDevices[i].lastAlertTime;
            if (elapsed >= FLOCK_DEDUPE_INTERVAL) {
                return 1;  // Timeout, treat as new detection
            }

            LOG_DEBUG("FlockModule: Dedup - skipping %s (RSSI:%d, last:%d, %d sec ago)",
                      identifier, rssi, seenDevices[i].lastRssi, elapsed / 1000);
            return 0;  // Skip
        }
    }

    // Never seen this device before
    return 1;  // New detection
}

// Record that we sent an alert for this device
void FlockModule::recordDeviceAlert(const char *identifier, int rssi)
{
    if (!identifier)
        return;

    uint32_t now = millis();

    // Check if device already exists, update timestamp and RSSI
    for (int i = 0; i < seenDeviceCount; i++) {
        if (strncmp(seenDevices[i].identifier, identifier, sizeof(seenDevices[i].identifier) - 1) == 0) {
            seenDevices[i].lastAlertTime = now;
            seenDevices[i].lastRssi = (int8_t)rssi;
            return;
        }
    }

    // Need to add new entry
    if (seenDeviceCount >= MAX_TRACKED_DEVICES) {
        // Find and replace oldest entry
        int oldestIdx = 0;
        uint32_t oldestTime = seenDevices[0].lastAlertTime;
        for (int i = 1; i < seenDeviceCount; i++) {
            if (seenDevices[i].lastAlertTime < oldestTime) {
                oldestTime = seenDevices[i].lastAlertTime;
                oldestIdx = i;
            }
        }
        LOG_DEBUG("FlockModule: Dedup cache full, replacing %s", seenDevices[oldestIdx].identifier);
        strncpy(seenDevices[oldestIdx].identifier, identifier, sizeof(seenDevices[oldestIdx].identifier) - 1);
        seenDevices[oldestIdx].identifier[sizeof(seenDevices[oldestIdx].identifier) - 1] = '\0';
        seenDevices[oldestIdx].lastAlertTime = now;
        seenDevices[oldestIdx].lastRssi = (int8_t)rssi;
    } else {
        // Add to end
        strncpy(seenDevices[seenDeviceCount].identifier, identifier, sizeof(seenDevices[seenDeviceCount].identifier) - 1);
        seenDevices[seenDeviceCount].identifier[sizeof(seenDevices[seenDeviceCount].identifier) - 1] = '\0';
        seenDevices[seenDeviceCount].lastAlertTime = now;
        seenDevices[seenDeviceCount].lastRssi = (int8_t)rssi;
        seenDeviceCount++;
    }
    LOG_DEBUG("FlockModule: Recorded alert for %s RSSI:%d (tracking %d devices)", identifier, rssi, seenDeviceCount);
}

// Clean up devices that haven't been seen in a long time
void FlockModule::cleanupOldDevices()
{
    if (Throttle::isWithinTimespanMs(lastDedupeCleanup, FLOCK_DEDUPE_CLEANUP_INTERVAL)) {
        return;
    }

    uint32_t now = millis();
    int removed = 0;

    // Compact array, removing stale entries
    int writeIdx = 0;
    for (int readIdx = 0; readIdx < seenDeviceCount; readIdx++) {
        uint32_t elapsed = now - seenDevices[readIdx].lastAlertTime;
        if (elapsed <= FLOCK_DEDUPE_INTERVAL * 2) {
            // Keep this entry
            if (writeIdx != readIdx) {
                memcpy(&seenDevices[writeIdx], &seenDevices[readIdx], sizeof(SeenDevice));
            }
            writeIdx++;
        } else {
            removed++;
        }
    }
    seenDeviceCount = writeIdx;

    if (removed > 0) {
        LOG_INFO("FlockModule: Dedup cleanup removed %d stale entries, %d remaining", removed, seenDeviceCount);
    }

    lastDedupeCleanup = now;
}

void FlockModule::sendDetectionMessage(const char *deviceType, const char *identifier, int rssi, const char *method)
{
    // Per-device deduplication - returns: 0=skip, 1=new, 2=closer
    int alertType = shouldAlertForDevice(identifier, rssi);
    if (alertType == 0) {
        // Still update detection state even if deduplicated
        deviceInRange = true;
        lastDetectionTime = millis();
        return;
    }

    // Throttle messages to mesh (global rate limit) - but allow first detection through
    if (lastSentToMesh != 0 && Throttle::isWithinTimespanMs(lastSentToMesh, FLOCK_MIN_BROADCAST_INTERVAL)) {
        LOG_DEBUG("FlockModule: Detection throttled - %s %s RSSI:%d via %s", deviceType, identifier, rssi, method);
        // Still update detection state even if throttled
        deviceInRange = true;
        lastDetectionTime = millis();
        return;
    }

    // Query GPS for current location
    bool hasGpsLock = false;
    double latitude = 0.0;
    double longitude = 0.0;
    int32_t altitude = 0;

    if (gpsStatus && gpsStatus->getHasLock()) {
        hasGpsLock = true;
        // GPS coordinates are stored as integers scaled by 1e7
        latitude = gpsStatus->getLatitude() * 1e-7;
        longitude = gpsStatus->getLongitude() * 1e-7;
        altitude = gpsStatus->getAltitude();
        LOG_INFO("FlockModule: GPS lock - lat:%.6f lon:%.6f alt:%dm", latitude, longitude, altitude);
    } else {
        LOG_WARN("FlockModule: No GPS lock available for detection location");
    }

    LOG_WARN("FlockModule: DETECTED %s - %s RSSI:%d via %s", deviceType, identifier, rssi, method);

    // Build detection message - different format for new vs getting closer
    char message[237]; // Max Meshtastic payload size
    bool gettingCloser = (alertType == 2);

    if (gettingCloser) {
        // Getting closer message
        if (hasGpsLock) {
            snprintf(message, sizeof(message), "CLOSER: %s ID:%s RSSI:%d Loc:%.6f,%.6f",
                     deviceType, identifier, rssi, latitude, longitude);
        } else {
            snprintf(message, sizeof(message), "CLOSER: %s ID:%s RSSI:%d",
                     deviceType, identifier, rssi);
        }
    } else {
        // New detection message
        if (hasGpsLock) {
            snprintf(message, sizeof(message), "ALERT: %s detected! ID:%s RSSI:%d Loc:%.6f,%.6f Alt:%dm",
                     deviceType, identifier, rssi, latitude, longitude, altitude);
        } else {
            snprintf(message, sizeof(message), "ALERT: %s detected! ID:%s RSSI:%d (No GPS)",
                     deviceType, identifier, rssi);
        }
    }

    // Send to mesh
    meshtastic_MeshPacket *p = allocDataPacket();
    if (p) {
        p->want_ack = false;
        p->decoded.payload.size = strlen(message);
        if (p->decoded.payload.size > sizeof(p->decoded.payload.bytes)) {
            p->decoded.payload.size = sizeof(p->decoded.payload.bytes);
        }
        memcpy(p->decoded.payload.bytes, message, p->decoded.payload.size);

        // Add bell character for external notification
        if (p->decoded.payload.size < meshtastic_Constants_DATA_PAYLOAD_LEN - 1) {
            p->decoded.payload.bytes[p->decoded.payload.size] = 7; // Bell character
            p->decoded.payload.size++;
        }

        lastSentToMesh = millis();

        // Send on channel 1 (secondary channel) instead of primary
        p->channel = 1;
        LOG_INFO("FlockModule: Sending detection to mesh on channel 1, id=%d", p->id);
        service->sendToMesh(p);
    }

    // Update detection state
    deviceInRange = true;
    lastDetectionTime = millis();
    lastHeartbeat = millis();
    triggered = true;

    // Record this device for deduplication with current RSSI
    recordDeviceAlert(identifier, rssi);
}

void FlockModule::sendHeartbeatMessage()
{
    if (!deviceInRange)
        return;

    if (!Throttle::isWithinTimespanMs(lastHeartbeat, FLOCK_HEARTBEAT_INTERVAL)) {
        LOG_INFO("FlockModule: Heartbeat - surveillance device still in range");

        // Query GPS for current location
        char message[150];
        if (gpsStatus && gpsStatus->getHasLock()) {
            double latitude = gpsStatus->getLatitude() * 1e-7;
            double longitude = gpsStatus->getLongitude() * 1e-7;
            int32_t altitude = gpsStatus->getAltitude();
            snprintf(message, sizeof(message), "Surveillance device still nearby Loc:%.6f,%.6f Alt:%dm",
                     latitude, longitude, altitude);
        } else {
            snprintf(message, sizeof(message), "Surveillance device still detected nearby (No GPS)");
        }

        meshtastic_MeshPacket *p = allocDataPacket();
        if (p) {
            p->want_ack = false;
            p->decoded.payload.size = strlen(message);
            memcpy(p->decoded.payload.bytes, message, p->decoded.payload.size);

            // Send on channel 1 (secondary channel)
            p->channel = 1;
            service->sendToMesh(p);
        }

        lastHeartbeat = millis();
    }
}

int32_t FlockModule::runOnce()
{
    if (firstTime) {
        firstTime = false;
        LOG_INFO("FlockModule: Initializing surveillance detection system");

        // Check if we can run at all
        if (!isActive()) {
            LOG_WARN("FlockModule: INACTIVE - Both WiFi and Bluetooth are in use by Meshtastic");
            LOG_WARN("FlockModule: To enable flock detection, disable WiFi and/or Bluetooth in device config");
            return 30000; // Check again in 30 seconds in case config changes
        }

        // Auto-start scanning
        startScanning();

        return 1000; // Check again in 1 second
    }

    // If not scanning but could be active, try to start
    if (!scanning && isActive()) {
        LOG_INFO("FlockModule: Config changed, attempting to start scanning");
        startScanning();
        return 1000;
    }

    if (!scanning) {
        return 5000; // Check if we should start scanning
    }

    // Handle WiFi channel hopping (only if WiFi scanning is enabled)
    if (wifiScanEnabled) {
        hopChannel();
    }

    // Handle BLE scanning (only if BLE scanning is enabled)
    unsigned long now = millis();
    if (bleScanEnabled) {
        if (now - lastBLEScan >= FLOCK_BLE_SCAN_INTERVAL) {
            performBLEScan();
            lastBLEScan = now;
        }

        // Clear BLE results after scan completes
        if (pBLEScan && !pBLEScan->isScanning() && now - lastBLEScan > FLOCK_BLE_SCAN_DURATION * 1000) {
            pBLEScan->clearResults();
        }
    }

    // Check if device has gone out of range
    if (deviceInRange && now - lastDetectionTime >= FLOCK_DEVICE_TIMEOUT) {
        LOG_INFO("FlockModule: Device out of range - no detection for %d seconds", FLOCK_DEVICE_TIMEOUT / 1000);
        deviceInRange = false;
        triggered = false;
    }

    // Periodically clean up old entries from dedup cache
    cleanupOldDevices();

    return 100; // Run every 100ms for responsive channel hopping
}

#endif // ARCH_ESP32 && !MESHTASTIC_EXCLUDE_FLOCK
