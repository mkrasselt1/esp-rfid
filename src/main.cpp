/*
MIT License

Copyright (c) 2018 esp-rfid Community
Copyright (c) 2017 Ömer Şiar Baysal

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */
//#define DEBUG

#include "Arduino.h"
#include <Arduino.h>
#include "WiFi.h"
#include <mDNS.h>
#include <WiFiUdp.h>
#include <Timezone.h>
#include <Time.h>
#include <AsyncMqttClient.h>
#include <Update.h>
#include <ESPmDNS.h>
#include <FS.h>
#include <SPIFFS.h>
#include <ESPAsyncWebServer.h>
#include <SPI.h>
#include <ArduinoJson.h>
#include <Ticker.h>
#include <Bounce2.h>

#include <Wiegand.h>
#include <MFRC522.h>
#include <Adafruit_PN532.h>
#include <Wiegand.h>
#include "rfid125kHz.h"

#include <Wifi.h>
#include <mDNS.h>

#define VERSION "1.0.2"

#define LEDoff HIGH
#define LEDon LOW

MFRC522 mfrc522 = MFRC522();
Adafruit_PN532 pn532(-1);
WIEGAND wg;
RFID_Reader RFIDr;

int rfidss;
int readerType;
int relayPin;
int wifipin = 255;
int buttonpin = 255;

// NTPClient NTP;
AsyncMqttClient mqttClient;
Ticker mqttReconnectTimer;
// WiFiEventHandler wifiDisconnectHandler, wifiConnectHandler;
Bounce button;

AsyncWebServer server(80);
AsyncWebSocket ws("/ws");

unsigned long blink_ = millis();
bool wifiFlag = false;
bool configMode = false;
int ntpinter = 0;
int wmode;
uint8_t WiFi_pin = 255;
uint8_t buttonPin = 255;

char *http_username = "admin";
char *http_pass = NULL;
unsigned long previousMillis = 0;
unsigned long previousLoopMillis = 0;
unsigned long currentMillis = 0;
unsigned long cooldown = 0;
unsigned long deltaTime = 0;
unsigned long uptime = 0;
bool shouldReboot = false;
bool activateRelay = false;
bool deactivateRelay = false;
bool inAPMode = false;
bool isWifiConnected = false;
unsigned long autoRestartIntervalSeconds = 0;

bool wifiDisabled = true;
bool doDisableWifi = false;
bool doEnableWifi = false;
bool timerequest = false;
bool formatreq = false;
unsigned long wifiTimeout = 0;
unsigned long wiFiUptimeMillis = 0;
char *deviceHostname = NULL;

int mqttEnabled = 0;
char *mqttTopic = NULL;
char *mhs = NULL;
char *muser = NULL;
char *mpas = NULL;
int mport;

int lockType;
int relayType;
unsigned long activateTime;
char timeZone[20];

unsigned long nextbeat = 0;
unsigned long interval = 1800;

void writeEvent(String type, String src, String desc, String data)
{
	DynamicJsonDocument jsonBuffer(1024);
	jsonBuffer["type"] = type;
	jsonBuffer["src"] = src;
	jsonBuffer["desc"] = desc;
	jsonBuffer["data"] = data;
	jsonBuffer["time"] = now();
	File eventlog = SPIFFS.open("/eventlog.json", "a");
	serializeJson(jsonBuffer, eventlog);
	eventlog.print("\n");
	eventlog.close();
};

void writeLatest(String uid, String username, int acctype)
{
	DynamicJsonDocument jsonBuffer(1024);

	jsonBuffer["uid"] = uid;
	jsonBuffer["username"] = username;
	jsonBuffer["acctype"] = acctype;
	jsonBuffer["timestamp"] = now();
	File latestlog = SPIFFS.open("/latestlog.json", "a");
	serializeJson(jsonBuffer, latestlog);
	latestlog.print("\n");
	latestlog.close();
};

void sendEventLog(int page)
{
	DynamicJsonDocument jsonBuffer(1024);
	DynamicJsonDocument list(1024);
	JsonArray array = list.to<JsonArray>();

	jsonBuffer["command"] = "eventlist";
	jsonBuffer["page"] = page;
	// JsonObject items = array.createNestedObject(); // list ?
	File eventlog = SPIFFS.open("/eventlog.json", "r");
	int first = (page - 1) * 10;
	int last = page * 10;
	int i = 0;
	while (eventlog.available())
	{
		String item = String();
		item = eventlog.readStringUntil('\n');
		if (i >= first && i < last)
		{
			array.add(item);
		}
		i++;
	};
	jsonBuffer["list"] = list;
	eventlog.close();
	float pages = i / 10.0;
	jsonBuffer["haspages"] = ceil(pages);
	size_t len = measureJson(jsonBuffer);
	AsyncWebSocketMessageBuffer *buffer = ws.makeBuffer(len);
	if (buffer)
	{
		serializeJson(jsonBuffer, (char *)buffer->get(), len + 1);
		ws.textAll(buffer);
		ws.textAll("{\"command\":\"result\",\"resultof\":\"eventlist\",\"result\": true}");
	};
};

void sendLatestLog(int page)
{
	DynamicJsonDocument jsonBuffer(1024);
	DynamicJsonDocument list(1024);
	JsonArray array = list.to<JsonArray>();

	jsonBuffer["command"] = "latestlist";
	jsonBuffer["page"] = page;
	File latestlog = SPIFFS.open("/latestlog.json", "r");
	int first = (page - 1) * 10;
	int last = page * 10;
	int i = 0;
	while (latestlog.available())
	{
		String item = String();
		item = latestlog.readStringUntil('\n');
		if (i >= first && i < last)
		{
			array.add(item);
		}
		i++;
	}
	jsonBuffer["list"] = list;
	latestlog.close();
	float pages = i / 10.0;
	jsonBuffer["haspages"] = ceil(pages);
	size_t len = measureJson(jsonBuffer);
	AsyncWebSocketMessageBuffer *buffer = ws.makeBuffer(len);
	if (buffer)
	{
		serializeJson(jsonBuffer, (char *)buffer->get(), len + 1);
		ws.textAll(buffer);
		ws.textAll("{\"command\":\"result\",\"resultof\":\"latestlist\",\"result\": true}");
	}
};
void connectToMqtt()
{
#ifdef DEBUG
	Serial.println("[ INFO ] try to connect mqtt ");
#endif
	mqttClient.connect();
}

void onMqttDisconnect(AsyncMqttClientDisconnectReason reason)
{
	String reasonstr = "";
	switch (reason)
	{
	case (AsyncMqttClientDisconnectReason::TCP_DISCONNECTED):
		reasonstr = "TCP_DISCONNECTED";
		break;
	case (AsyncMqttClientDisconnectReason::MQTT_UNACCEPTABLE_PROTOCOL_VERSION):
		reasonstr = "MQTT_UNACCEPTABLE_PROTOCOL_VERSION";
		break;
	case (AsyncMqttClientDisconnectReason::MQTT_IDENTIFIER_REJECTED):
		reasonstr = "MQTT_IDENTIFIER_REJECTED";
		break;
	case (AsyncMqttClientDisconnectReason::MQTT_SERVER_UNAVAILABLE):
		reasonstr = "MQTT_SERVER_UNAVAILABLE";
		break;
	case (AsyncMqttClientDisconnectReason::MQTT_MALFORMED_CREDENTIALS):
		reasonstr = "MQTT_MALFORMED_CREDENTIALS";
		break;
	case (AsyncMqttClientDisconnectReason::MQTT_NOT_AUTHORIZED):
		reasonstr = "MQTT_NOT_AUTHORIZED";
		break;
	case (AsyncMqttClientDisconnectReason::ESP8266_NOT_ENOUGH_SPACE):
		reasonstr = "ESP8266_NOT_ENOUGH_SPACE";
		break;
	default:
		reasonstr = "Unknown";
		break;
	}
	writeEvent("WARN", "mqtt", "Disconnected from MQTT server", reasonstr);

	if (WiFi.isConnected())
	{
		// mqttClient.setServer(mhs, mport);
		mqttReconnectTimer.once(60, connectToMqtt);
	}
}

void mqtt_publish_boot(time_t boot_time, String const &wifi, String const &ip)
{
	const char *topic = mqttTopic;
	DynamicJsonDocument jsonBuffer(1024);

	jsonBuffer["type"] = "boot";
	jsonBuffer["time"] = boot_time;
	jsonBuffer["Wifi SSID"] = wifi;
	jsonBuffer["Local IP"] = ip;
	String mqttBuffer_boot;
	serializeJson(jsonBuffer, mqttBuffer_boot);
	mqttClient.publish(topic, 0, false, mqttBuffer_boot.c_str());
#ifdef DEBUG
	Serial.print("[ INFO ] Mqtt Publish:");
	Serial.println(mqttBuffer_boot);
#endif
}

void mqtt_publish_heartbeat(time_t heartbeat)
{
	const char *topic = mqttTopic;
	DynamicJsonDocument jsonBuffer(1024);

	jsonBuffer["type"] = "heartbeat";
	jsonBuffer["time"] = heartbeat;
	String mqttBuffer4;
	serializeJson(jsonBuffer, mqttBuffer4);
	mqttClient.publish(topic, 0, false, mqttBuffer4.c_str());
#ifdef DEBUG
	Serial.print("[ INFO ] Mqtt Publish:");
	Serial.println(mqttBuffer4);
#endif
}

void mqtt_publish_access(time_t accesstime, String const &isknown, String const &type, String const &user, String const &uid)
{
	if (mqttClient.connected())
	{
		const char *topic = mqttTopic;
		DynamicJsonDocument jsonBuffer(1024);

		jsonBuffer["type"] = "access";
		jsonBuffer["time"] = accesstime;
		jsonBuffer["isKnown"] = isknown;
		jsonBuffer["access"] = type;
		jsonBuffer["username"] = user;
		jsonBuffer["uid"] = uid;
		String mqttBuffer;
		serializeJson(jsonBuffer, mqttBuffer);
		mqttClient.publish(topic, 0, false, mqttBuffer.c_str());
#ifdef DEBUG
		Serial.print("[ INFO ] Mqtt Publish:");
		Serial.println(mqttBuffer);
#endif
	}
}

void onMqttPublish(uint16_t packetId)
{
	writeEvent("INFO", "mqtt", "MQTT publish acknowledged", String(packetId));
}

void onMqttConnect(bool sessionPresent)
{
#ifdef DEBUG
	Serial.println("[ INFO ] MQTT Connected session");
#endif
	if (sessionPresent == true)
	{
#ifdef DEBUG
		Serial.println("[ INFO ]MQTT session Present: True");
#endif
		writeEvent("INFO", "mqtt", "Connected to MQTT Server", "Session Present");
	}
	mqtt_publish_boot(now(), WiFi.SSID(), WiFi.localIP().toString());
}
String printIP(IPAddress address)
{
	return (String)address[0] + "." + (String)address[1] + "." + (String)address[2] + "." + (String)address[3];
}

void parseBytes(const char *str, char sep, byte *bytes, int maxBytes, int base)
{
	for (int i = 0; i < maxBytes; i++)
	{
		bytes[i] = strtoul(str, NULL, base); // Convert byte
		str = strchr(str, sep);				 // Find next separator
		if (str == NULL || *str == '\0')
		{
			break; // No more separators, exit
		}
		str++; // Point to next character after separator
	}
}

void sendUserList(int page, AsyncWebSocketClient *client)
{
	DynamicJsonDocument jsonBuffer(1024);

	jsonBuffer["command"] = "userlist";
	jsonBuffer["page"] = page;

	File root = SPIFFS.open("/P/");
	File file = root.openNextFile();
	int first = (page - 1) * 15;
	int last = page * 15;
	int i = 0;
	while (file)
	{
		if (i >= first && i < last)
		{
			JsonObject item = jsonBuffer["list"].createNestedObject();
			String uid = file.name();
			uid.remove(0, 3);
			item["uid"] = uid;
			File f = SPIFFS.open(file.name(), "r");
			size_t size = f.size();
			std::unique_ptr<char[]> buf(new char[size]);
			f.readBytes(buf.get(), size);
			DynamicJsonDocument jsonBuffer2(1024);
			DeserializationError error = deserializeJson(jsonBuffer2, buf.get());
			if (!error)
			{
				String username = jsonBuffer2["user"] | "";
				int AccType = jsonBuffer2["acctype"] | -1;
				unsigned long validuntil = jsonBuffer2["validuntil"] | -1;
				item["username"] = username;
				item["acctype"] = AccType;
				item["validuntil"] = validuntil;
			}
		}
		i++;
		file = file.openNextFile();
	}
	float pages = i / 15.0;
	jsonBuffer["haspages"] = ceil(pages);
	size_t len = measureJson(jsonBuffer);
	AsyncWebSocketMessageBuffer *buffer = ws.makeBuffer(len);
	if (buffer)
	{
		serializeJson(jsonBuffer, (char *)buffer->get(), len + 1);
		if (client)
		{
			client->text(buffer);
			client->text("{\"command\":\"result\",\"resultof\":\"userlist\",\"result\": true}");
		}
		else
		{
			ws.textAll("{\"command\":\"result\",\"resultof\":\"userlist\",\"result\": false}");
		}
	}
};

void sendStatus()
{
	if (!SPIFFS.totalBytes())
	{
#ifdef DEBUG
		Serial.print(F("[ WARN ] Error getting info on SPIFFS"));
#endif
	}
	DynamicJsonDocument jsonBuffer(1024);

	jsonBuffer["command"] = "status";
	jsonBuffer["board"] = "esp32poe";
	jsonBuffer["heap"] = ESP.getFreeHeap();
	jsonBuffer["mac"] = WiFi.macAddress();
	jsonBuffer["cpu"] = ESP.getCpuFreqMHz();
	jsonBuffer["sketchsize"] = ESP.getSketchSize();
	jsonBuffer["availsize"] = ESP.getFreeSketchSpace();
	jsonBuffer["availspiffs"] = SPIFFS.totalBytes() - SPIFFS.usedBytes();
	jsonBuffer["spiffssize"] = SPIFFS.totalBytes();
	jsonBuffer["uptime"] = time(nullptr);
	jsonBuffer["version"] = "0x00b";

	jsonBuffer["ssid"] = WiFi.SSID();
	if (inAPMode)
	{
		jsonBuffer["dns"] = printIP(WiFi.softAPIP());
		jsonBuffer["mac"] = WiFi.softAPmacAddress();
	}
	else
	{
		jsonBuffer["dns"] = printIP(WiFi.dnsIP());
		jsonBuffer["mac"] = WiFi.macAddress();
	}

	IPAddress ipaddr = WiFi.localIP();
	IPAddress gwaddr = WiFi.gatewayIP();
	IPAddress nmaddr = WiFi.subnetMask();
	jsonBuffer["ip"] = printIP(ipaddr);
	jsonBuffer["gateway"] = printIP(gwaddr);
	jsonBuffer["netmask"] = printIP(nmaddr);

	size_t len = measureJson(jsonBuffer);
	AsyncWebSocketMessageBuffer *buffer = ws.makeBuffer(len);
	if (buffer)
	{
		serializeJson(jsonBuffer, (char *)buffer->get(), len + 1);
		ws.textAll(buffer);
	}
};

void printScanResult(int networksFound)
{
	// sort by RSSI
	int n = networksFound;
	int indices[n];
	int skip[n];
	for (int i = 0; i < networksFound; i++)
	{
		indices[i] = i;
	}
	for (int i = 0; i < networksFound; i++)
	{
		for (int j = i + 1; j < networksFound; j++)
		{
			if (WiFi.RSSI(indices[j]) > WiFi.RSSI(indices[i]))
			{
				std::swap(indices[i], indices[j]);
				std::swap(skip[i], skip[j]);
			}
		}
	}
	DynamicJsonDocument jsonBuffer(1024);

	jsonBuffer["command"] = "ssidlist";
	for (int i = 0; i < 5 && i < networksFound; ++i)
	{
		JsonObject item = jsonBuffer["list"].createNestedObject();
		item["ssid"] = WiFi.SSID(indices[i]);
		item["bssid"] = WiFi.BSSIDstr(indices[i]);
		item["rssi"] = WiFi.RSSI(indices[i]);
		item["channel"] = WiFi.channel(indices[i]);
		item["enctype"] = WiFi.encryptionType(indices[i]);
	}
	size_t len = measureJson(jsonBuffer);
	AsyncWebSocketMessageBuffer *buffer = ws.makeBuffer(len); //  creates a buffer (len + 1) for you.
	if (buffer)
	{
		serializeJson(jsonBuffer, (char *)buffer->get(), len + 1);
		ws.textAll(buffer);
	}
	WiFi.scanDelete();
};

void sendTime()
{
	DynamicJsonDocument jsonBuffer(1024);

	jsonBuffer["command"] = "gettime";
	jsonBuffer["epoch"] = now();
	jsonBuffer["timezone"] = timeZone;
	size_t len = measureJson(jsonBuffer);
	AsyncWebSocketMessageBuffer *buffer = ws.makeBuffer(len);
	if (buffer)
	{
		serializeJson(jsonBuffer, (char *)buffer->get(), len + 1);
		ws.textAll(buffer);
	}
};
enum eCardType
{
	CARD_Unknown = 0,	// Mifare Classic or other card
	CARD_Desfire = 1,	// A Desfire card with normal 7 byte UID  (bit 0)
	CARD_DesRandom = 3, // A Desfire card with 4 byte random UID  (bit 0 + 1)
};
void rfidloop()
{
	String uid = "";
	String type = "";
	if (readerType == 0)
	{
		if (!mfrc522.PICC_IsNewCardPresent())
		{
			delay(50);
			return;
		}
		if (!mfrc522.PICC_ReadCardSerial())
		{
			delay(50);
			return;
		}
		mfrc522.PICC_HaltA();
		cooldown = millis() + 2000;
#ifdef DEBUG
		Serial.print(F("[ INFO ] PICC's UID: "));
#endif
		for (int i = 0; i < mfrc522.uid.size; ++i)
		{
			uid += String(mfrc522.uid.uidByte[i], HEX);
		}
#ifdef DEBUG
		Serial.print(uid);
#endif
		MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
		type = mfrc522.PICC_GetTypeName(piccType);
#ifdef DEBUG
		Serial.print(" " + type);
#endif
	}
	else if (readerType == 1)
	{
		if (wg.available())
		{
#ifdef DEBUG
			Serial.print(F("[ INFO ] PICC's UID: "));
			Serial.println(wg.getCode());
#endif
			uid = String(wg.getCode(), DEC);
			type = String(wg.getWiegandType(), DEC);
			cooldown = millis() + 2000;
		}
		else
		{
			return;
		}
	}
	else if (readerType == 2)
	{
		bool found = false;
		byte pnuid[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		eCardType e_CardType;
		byte u8_UidLength = 0x00; // UID = 4 or 7 bytes
		found = pn532.readPassiveTargetID(PN532_MIFARE_ISO14443A, pnuid, &u8_UidLength);
		if (found && u8_UidLength >= 4)
		{
#ifdef DEBUG
			Serial.print(F("[ INFO ] PICC's UID: "));
#endif
			for (uint8_t i = 0; i < u8_UidLength; i++)
			{
				uid += String(pnuid[i], HEX);
			}
#ifdef DEBUG
			Serial.print(uid);
#endif
			cooldown = millis() + 2000;
		}
		else
		{
			delay(50);
			return;
		}
	}
	else if (readerType > 2)
	{
		while (Serial.available() > 0)
		{
			RFIDr.rfidSerial(Serial.read());
		}
		if (RFIDr.Available())
		{
			uid = RFIDr.GetHexID();
			type = RFIDr.GetTagType();
			cooldown = millis() + 2000;
#ifdef DEBUG
			Serial.print(F("[ INFO ] PICC's UID: "));
			Serial.print(uid);
#endif
		}
		else
		{
			if (readerType == 3)
			{
				delay(50);
				return;
			}
		}

		if (readerType == 4 && uid.length() == 0)
		{
			if (!mfrc522.PICC_IsNewCardPresent())
			{
				delay(50);
				return;
			}
			if (!mfrc522.PICC_ReadCardSerial())
			{
				delay(50);
				return;
			}
			mfrc522.PICC_HaltA();
			cooldown = millis() + 2000;
#ifdef DEBUG
			Serial.print(F("[ INFO ] PICC's UID: "));
#endif
			for (int i = 0; i < mfrc522.uid.size; ++i)
			{
				uid += String(mfrc522.uid.uidByte[i], HEX);
			}
#ifdef DEBUG
			Serial.print(uid);
#endif
			MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
			type = mfrc522.PICC_GetTypeName(piccType);
#ifdef DEBUG
			Serial.print(" " + type);
#endif
		}

		else if (readerType == 5 && uid.length() == 0)
		{
			if (wg.available())
			{
#ifdef DEBUG
				Serial.print(F("[ INFO ] PICC's UID: "));
				Serial.println(wg.getCode());
#endif
				uid = String(wg.getCode(), DEC);
				type = String(wg.getWiegandType(), DEC);
				cooldown = millis() + 2000;
			}
			else
			{
				return;
			}
		}

		else if (readerType == 6 && uid.length() == 0)
		{
			bool found = false;
			byte pnuid[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
			eCardType e_CardType;
			byte u8_UidLength = 0x00; // UID = 4 or 7 bytes
			found = pn532.readPassiveTargetID(PN532_MIFARE_ISO14443A, pnuid, &u8_UidLength);
			if (found && u8_UidLength >= 4)
			{
#ifdef DEBUG
				Serial.print(F("[ INFO ] PICC's UID: "));
#endif
				for (uint8_t i = 0; i < u8_UidLength; i++)
				{
					uid += String(pnuid[i], HEX);
				}
#ifdef DEBUG
				Serial.print(uid);
#endif
				cooldown = millis() + 2000;
			}
			else
			{
				delay(50);
				return;
			}
		}
	}

	else // no reader selected
	{
		delay(50);
		return;
	}
	int AccType = 0;
	String filename = "/P/";
	filename += uid;
	File f = SPIFFS.open(filename, "r");
	if (f)
	{
		size_t size = f.size();
		std::unique_ptr<char[]> buf(new char[size]);
		f.readBytes(buf.get(), size);
		DynamicJsonDocument doc(size);
		DeserializationError error = deserializeJson(doc, buf.get());

		if (!error)
		{
			String username = doc["user"] | "none";
			AccType = doc["acctype"] | -1;
#ifdef DEBUG
			Serial.println(" = known PICC");
			Serial.print("[ INFO ] User Name: ");
			if (username == "undefined")
				Serial.print(uid);
			else
				Serial.print(username);
#endif
			if (AccType == 1)
			{
				unsigned long validL = doc["validuntil"] | -1;
				unsigned long nowL = now();

				if (validL > nowL)
				{
					activateRelay = true;
					ws.textAll("{\"command\":\"giveAccess\"}");
#ifdef DEBUG
					Serial.println(" have access");
#endif
					if (mqttEnabled == 1)
					{
						mqtt_publish_access(now(), "true", "Always", username, uid);
					}
				}

				else
				{
#ifdef DEBUG
					Serial.println(" expired");
#endif
					if (mqttEnabled == 1)
					{
						mqtt_publish_access(now(), "true", "Expired", username, uid);
					}
					AccType = 2;
				}
			}
			else if (AccType == 99)
			{
				doEnableWifi = true;
				activateRelay = true;
				ws.textAll("{\"command\":\"giveAccess\"}");
#ifdef DEBUG
				Serial.println(" have admin access, enable wifi");
#endif
				if (mqttEnabled == 1)
				{
					mqtt_publish_access(now(), "true", "Admin", username, uid);
				}
			}
			else
			{
#ifdef DEBUG
				Serial.println(" does not have access");
#endif
				if (mqttEnabled == 1)
				{
					mqtt_publish_access(now(), "true", "Disabled", username, uid);
				}
			}
			writeLatest(uid, username, AccType);
			DynamicJsonDocument jsonBuffer(1024);
			jsonBuffer["command"] = "piccscan";
			jsonBuffer["uid"] = uid;
			jsonBuffer["type"] = type;
			jsonBuffer["known"] = 1;
			jsonBuffer["acctype"] = AccType;
			jsonBuffer["user"] = username;
			size_t len = measureJson(jsonBuffer);
			AsyncWebSocketMessageBuffer *buffer = ws.makeBuffer(len);
			if (buffer)
			{
				serializeJson(jsonBuffer, (char *)buffer->get(), len + 1);
				ws.textAll(buffer);
			}
		}
		else
		{
#ifdef DEBUG
			Serial.println("");
			Serial.println(F("[ WARN ] Failed to parse User Data"));
#endif
		}
		f.close();
	}
	else
	{
		String data = String(uid);
		data += " " + String(type);
		writeEvent("WARN", "rfid", "Unknown rfid tag is scanned", data);
		writeLatest(uid, "Unknown", 98);
#ifdef DEBUG
		Serial.println(" = unknown PICC");
#endif
		DynamicJsonDocument jsonBuffer(1024);

		jsonBuffer["command"] = "piccscan";
		jsonBuffer["uid"] = uid;
		jsonBuffer["type"] = type;
		jsonBuffer["known"] = 0;
		size_t len = measureJson(jsonBuffer);
		AsyncWebSocketMessageBuffer *buffer = ws.makeBuffer(len);
		if (buffer)
		{
			serializeJson(jsonBuffer, (char *)buffer->get(), len + 1);
			ws.textAll(buffer);
		}
		if (mqttEnabled == 1)
		{
			mqtt_publish_access(now(), "false", "Denied", "Unknown", uid);
		}
	}
}

#ifdef DEBUG
void ShowMFRC522ReaderDetails()
{
	// Get the MFRC522 software version
	byte v = mfrc522.PCD_ReadRegister(mfrc522.VersionReg);
	Serial.print(F("[ INFO ] MFRC522 Version: 0x"));
	Serial.print(v, HEX);
	if (v == 0x91)
		Serial.print(F(" = v1.0"));
	else if (v == 0x92)
		Serial.print(F(" = v2.0"));
	else if (v == 0x88)
		Serial.print(F(" = clone"));
	else
		Serial.print(F(" (unknown)"));
	Serial.println("");
	// When 0x00 or 0xFF is returned, communication probably failed
	if ((v == 0x00) || (v == 0xFF))
	{
		Serial.println(F("[ WARN ] Communication failure, check if MFRC522 properly connected"));
	}
}
#endif

void setupWiegandReader(int d0, int d1)
{
	wg.begin(d0, d1);
}

void setupMFRC522Reader(int rfidss, int rfidgain)
{
	SPI.begin();						 // MFRC522 Hardware uses SPI protocol
	mfrc522.PCD_Init(rfidss, UINT8_MAX); // Initialize MFRC522 Hardware
	// Set RFID Hardware Antenna Gain
	// This may not work with some boards
	mfrc522.PCD_SetAntennaGain(rfidgain);
#ifdef DEBUG
	Serial.printf("[ INFO ] RFID SS_PIN: %u and Gain Factor: %u", rfidss, rfidgain);
	Serial.println("");
#endif
#ifdef DEBUG
	ShowMFRC522ReaderDetails(); // Show details of PCD - MFRC522 Card Reader details
#endif
}

void setupPN532Reader(int rfidss)
{
	// init controller
	Adafruit_PN532 pn532(rfidss);
	do
	{ // pseudo loop (just used for aborting with break;)
		// Reset the PN532
		pn532.begin(); // delay > 400 ms
		byte IC, VersionHi, VersionLo, Flags;
		uint32_t versiondata = pn532.getFirmwareVersion();
		if (!versiondata)
		{
			Serial.print("Didn't find PN53x board");
			break;
		}
#ifdef DEBUG
		Serial.print("Found chip PN5");
		Serial.println((versiondata >> 24) & 0xFF, HEX);
		Serial.print("Firmware ver. ");
		Serial.print(, DEC);
		Serial.print('.');
		Serial.println((versiondata >> 8) & 0xFF, DEC);
#endif
		// Set the max number of retry attempts to read from a card.
		// This prevents us from waiting forever for a card, which is the default behaviour of the PN532.
		if (!pn532.setPassiveActivationRetries(5))
		{
			break;
		}
		// configure the PN532 to read RFID tags
		if (!pn532.SAMConfig())
		{
			break;
		}
	} while (false);
}

void wifiLedOn()
{
	if (wifipin != 255)
		digitalWrite(wifipin, LEDon);
}

void wifiLedOff()
{
	if (wifipin != 255)
		digitalWrite(wifipin, LEDoff);
}

void onWifiConnect(const WiFiEvent_t &event, WiFiEventInfo_t info)
{
	wifiFlag = true;
	wifiLedOn();
#ifdef DEBUG
	Serial.println(F("\n[ INFO ] WiFi STA Connected"));
#endif
	// mqttReconnectTimer.detach();
}
void onWifiDisconnect(const WiFiEvent_t &event, WiFiEventInfo_t info)
{
	mqttReconnectTimer.detach();
	if (wifiFlag)
	{
#ifdef DEBUG
		Serial.println(F("[ INFO ] WiFi STA Disconnected"));
#endif
		wifiFlag = false;
		wifiLedOff();
	}
}

bool startAP(IPAddress apip, IPAddress apsubnet, int hid, const char *ssid, const char *password)
{
	inAPMode = true;
	WiFi.mode(WIFI_AP);
#ifdef DEBUG
	Serial.print(F("[ INFO ] Configuring access point... "));
#endif

	WiFi.softAPConfig(apip, apip, apsubnet);

	bool success;
	if (hid == 1)
	{
		success = WiFi.softAP(ssid, password, 3, true);
	}
	else
	{
		success = WiFi.softAP(ssid, password);
	}
#ifdef DEBUG
	Serial.println(success ? F("Ready") : F("Failed!"));
#endif

	if (!success)
	{
		ESP.restart();
	}
	else
		wifiLedOn();

#ifdef DEBUG
	IPAddress myIP = WiFi.softAPIP();

	Serial.print(F("[ INFO ] AP IP address: "));
	Serial.println(myIP);
	Serial.printf("[ INFO ] AP SSID: %s\n", ssid);
#endif
	isWifiConnected = success;
	return success;
}

// Fallback to AP Mode, so we can connect to ESP if there is no Internet connection
void fallbacktoAPMode()
{
	inAPMode = true;
#ifdef DEBUG
	Serial.println(F("[ INFO ] ESP-RFID is running in Fallback AP Mode"));
#endif
	uint8_t macAddr[6];
	WiFi.softAPmacAddress(macAddr);
	char ssid[15];
	sprintf(ssid, "ESP-RFID-%02x%02x%02x", macAddr[3], macAddr[4], macAddr[5]);
	WiFi.mode(WIFI_AP);
	bool success;
	success = WiFi.softAP(ssid);
	isWifiConnected = success;
	if (success)
	{
		wifiLedOn();
	}
}

// Try to connect Wi-Fi
bool connectSTA(const char *ssid, const char *password, byte bssid[6])
{
	WiFi.mode(WIFI_STA);
	WiFi.begin(ssid, password, 0, bssid);
#ifdef DEBUG
	Serial.print(F("[ INFO ] Trying to connect WiFi: "));
	Serial.print(ssid);
#endif
	unsigned long now = millis();
	uint8_t timeout = 20; // define when to time out in seconds
	Serial.println();
	do
	{
		if (WiFi.status() == WL_CONNECTED)
		{
			wifiLedOn();
			break;
		}
		delay(500);
		if (wifipin != 255)
			digitalWrite(wifipin, !digitalRead(wifipin));
#ifdef DEBUG
		if (!wifiFlag)
			Serial.print(F("."));
#endif
	} while (millis() - now < timeout * 1000);
	//} while ((millis() - now < timeout * 1000)||noAPfallback);
	// We now out of the while loop, either time is out or we connected. check what happened
	if (WiFi.status() == WL_CONNECTED)
	{
		// Assume time is out first and check
#ifdef DEBUG
		// Serial.println();
		Serial.print(F("[ INFO ] Client IP address: "));
		Serial.println(WiFi.localIP());
#endif
		isWifiConnected = true;
		String data = ssid;
		data += " " + WiFi.localIP().toString();
		writeEvent("INFO", "wifi", "WiFi is connected", data);
		return true;
	}
	else
	{
		// We couln't connect, time is out, inform
#ifdef DEBUG
		Serial.println();
		Serial.println(F("[ WARN ] Couldn't connect in time"));
#endif
		return false;
	}
}

void disableWifi()
{
	isWifiConnected = false;
	WiFi.disconnect(true);
#ifdef DEBUG
	Serial.println(F("Turn wifi off."));
#endif
}

void enableWifi()
{
#ifdef DEBUG
	Serial.println(F("[ INFO ] Restarting the board to connect wi-fi again"));
#endif
	ESP.restart();
}

struct EspRfidConfig
{
    struct Config_Network
    {
        char ssid[64];
        char password[64];
        char hostnm[20];
    } network;
    struct Config_Hardware
    {
        uint16_t wifipin = 255;
        uint16_t readerType = 0;
        uint16_t wgd0pin = 255;
        uint16_t wgd1pin = 255;
        uint16_t sspin = 0;
        uint16_t rfidgain = 255;
        uint16_t ltype = 255;
        uint16_t rtype = 255;
        uint16_t rpin = 255;
    } hardware;
    struct Config_General
    {
        uint16_t restart = 10000;
        uint16_t offtime = 10000;
    } general;
    struct Config_Mqtt
    {
    } mqtt;
    struct Config_Ntp
    {
        char server[20];
        long interval = 360000;
        uint16_t timezone = 0;
    } ntp;
};
bool loadConfiguration()
{
	File configFile = SPIFFS.open("/config.json", "r");
	if (!configFile)
	{
#ifdef DEBUG
		Serial.println(F("[ WARN ] Failed to open config file"));
#endif
		return false;
	}
	StaticJsonDocument<sizeof(EspRfidConfig)> configJson;
	EspRfidConfig config;

	// Deserialize the JSON document
	DeserializationError error = deserializeJson(configJson, configFile);

	configFile.close();

	if (error)
	{
#ifdef DEBUG
		Serial.println(F("[ WARN ] Failed to parse config file"));
#endif
		return false;
	}
#ifdef DEBUG
	Serial.println(F("[ INFO ] Config file found"));
	json.prettyPrintTo(Serial);
	Serial.println();
#endif
	// Example
	// config.port = doc["port"] | 2731;
	// strlcpy(config.hostname,                  // <- destination
	// 		doc["hostname"] | "example.com",  // <- source
	// 		sizeof(config.hostname));         // <- destination's capacity

	// // Close the file (Curiously, File's destructor doesn't close the file)
	// file.close();

	// Old Code
	// JsonObject &network = json["network"];
	// JsonObject &general = json["general"];
	// JsonObject &mqtt = json["mqtt"];
	// JsonObject &ntp = json["ntp"];
#ifdef DEBUG
	Serial.println(F("[ INFO ] Trying to setup RFID Hardware"));
#endif
	// Hardware Section
	if (configJson.containsKey("hardware"))
	{
		if (configJson["hardware"].containsKey("wifipin"))
		{
			wifipin = configJson["hardware"]["wifipin"] | 255;
			if (wifipin != 255)
			{
				pinMode(wifipin, OUTPUT);
				digitalWrite(wifipin, LEDoff);
			}
		}
		if (configJson["hardware"].containsKey("buttonpin"))
		{
			buttonPin = configJson["hardware"]["buttonpin"] | 255;
			if (buttonPin != 255)
			{
				button = Bounce();
				button.attach(buttonPin, INPUT_PULLUP);
				button.interval(30);
			}
		}
		activateTime = configJson["hardware"]["rtime"] | 255;
		lockType = configJson["hardware"]["ltype"] | 255;
		relayType = configJson["hardware"]["rtype"] | 255;
		readerType = configJson["hardware"]["readerType"];
		if (readerType == 1 || readerType == 5)
		{
			int wgd0pin = configJson["hardware"]["wgd0pin"] | 255;
			int wgd1pin = configJson["hardware"]["wgd1pin"] | 255;
			setupWiegandReader(wgd0pin, wgd1pin); // also some other settings like weather to use keypad or not, LED pin, BUZZER pin, Wiegand 26/34 version
		}
		else if (readerType == 0 || readerType == 4)
		{
			// if (configJson["hardware"].containsKey("sspin"))
			int rfidss = configJson["hardware"]["sspin"] | 15;

			int rfidgain = configJson["hardware"]["rfidgain"];
			setupMFRC522Reader(rfidss, rfidgain);
		}
		else if (readerType == 2 || readerType == 6)
		{
			rfidss = configJson["hardware"]["sspin"];
			setupPN532Reader(rfidss);
		}
#ifndef DEBUG
		if (readerType > 2)
			Serial.begin(9600);
#endif
	}

	// General Section
	if (configJson.containsKey("general"))
	{
		autoRestartIntervalSeconds = configJson["general"]["restart"] | 10000;
		deviceHostname = strdup(configJson["general"]["hostnm"]);
		WiFi.hostname(deviceHostname);
		if (!MDNS.begin(deviceHostname))
		{
#ifdef DEBUG
			Serial.println("[ WARN ]Error setting up MDNS responder!");
#endif
		}
		MDNS.addService("http", "tcp", 80);
	}
	// Network Section
	if (configJson.containsKey("network"))
	{
		wifiTimeout = configJson["network"]["offtime"];
		byte bssid[6];
		parseBytes(configJson["network"]["bssid"] | "000000000000", ':', bssid, 6, 16);
		const char *ssid = configJson["network"]["ssid"];
		const char *password = configJson["network"]["pswd"];
		wmode = configJson["network"]["wmode"];
		http_pass = strdup(configJson["general"]["pswd"]);
		ws.setAuthentication("admin", http_pass);
		if (wmode == 1)
		{
			int hid = configJson["network"]["hide"];
#ifdef DEBUG
			Serial.println(F("[ INFO ] ESP-RFID is running in AP Mode "));
#endif
			const char *apipch;
			if (configJson["network"].containsKey("apip"))
			{
				apipch = configJson["network"]["apip"];
			}
			else
			{
				apipch = "192.168.4.1";
			}
			const char *apsubnetch;
			if (configJson["network"].containsKey("apsubnet"))
			{
				apsubnetch = configJson["network"]["apsubnet"];
			}
			else
			{
				apsubnetch = "255.255.255.0";
			}
			IPAddress apip;
			IPAddress apsubnet;
			apip.fromString(apipch);
			apsubnet.fromString(apsubnetch);
			return startAP(apip, apsubnet, hid, ssid, password);
		}
		else
		{
			if (configJson["network"]["dhcp"] == "0")
			{
				WiFi.mode(WIFI_STA);
				const char *clientipch = configJson["network"]["ip"];
				const char *subnetch = configJson["network"]["subnet"];
				const char *gatewaych = configJson["network"]["gateway"];
				const char *dnsch = configJson["network"]["dns"];
				IPAddress clientip;
				IPAddress subnet;
				IPAddress gateway;
				IPAddress dns;
				clientip.fromString(clientipch);
				subnet.fromString(subnetch);
				gateway.fromString(gatewaych);
				dns.fromString(dnsch);
				WiFi.config(clientip, gateway, subnet, dns);
			}
			if (!connectSTA(ssid, password, bssid))
			{
				return false;
			}
		}
	}
	// NTP Section
	if (configJson.containsKey("ntp"))
	{
		const char *ntpserver = configJson["ntp"]["server"];
		ntpinter = configJson["ntp"]["interval"];
		strlcpy(timeZone,										 // <- destination
				configJson["ntp"]["timezone"] | "Europe/Berlin", // <- source
				sizeof(timezone)*sizeof(char));								 // <- destination's capacity
#ifdef DEBUG
		Serial.println("[ INFO ] Trying to setup NTP Server");
#endif
		//configTime(0, 0, ntpserver, "pool.ntp.org");
		configTzTime(timeZone, ntpserver, "pool.ntp.org");		
	}
	if (configJson.containsKey("mqtt"))

		mqttEnabled = configJson["mqtt"]["enabled"] | 0;
	if (mqttEnabled == 1)
	{
#ifdef DEBUG
		Serial.println("[ INFO ] Trying to setup MQTT");
#endif
		String mhsString = configJson["mqtt"]["host"];
		mhs = strdup(mhsString.c_str());

		mport = configJson["mqtt"]["port"];

		String muserString = configJson["mqtt"]["user"];
		muser = strdup(muserString.c_str());
		String mpasString = configJson["mqtt"]["pswd"];
		mpas = strdup(mpasString.c_str());
		String mqttTopicString = configJson["mqtt"]["topic"];
		mqttTopic = strdup(mqttTopicString.c_str());

		mqttClient.setServer(mhs, mport);
		mqttClient.setCredentials(muser, mpas);
		mqttClient.onDisconnect(onMqttDisconnect);
		mqttClient.onPublish(onMqttPublish);
		mqttClient.onConnect(onMqttConnect);
#ifdef DEBUG
		Serial.println("[ INFO ] try to call mqttconnect ");
#endif
		connectToMqtt();
	}
#ifdef DEBUG
	Serial.println(F("[ INFO ] Configuration done."));
#endif
	return true;
}

void procMsg(AsyncWebSocketClient *client, size_t sz)
{
	// We should always get a JSON object (stringfied) from browser, so parse it
	char json[sz + 1];
	memcpy(json, (char *)(client->_tempObject), sz);
	json[sz] = '\0';
	DynamicJsonDocument jsonDoc(1024);
	auto error = deserializeJson(jsonDoc, json);
	if (error)
	{
#ifdef DEBUG
		Serial.println(F("[ WARN ] Couldn't parse WebSocket message"));
#endif
		free(client->_tempObject);
		client->_tempObject = NULL;
		//delete client->_tempObject;
		return;
	}
	// Web Browser sends some commands, check which command is given
	const char *command = jsonDoc["command"];
	// Check whatever the command is and act accordingly
	if (strcmp(command, "remove") == 0)
	{
		const char *uid = jsonDoc["uid"];
		String filename = "/P/";
		filename += uid;
		SPIFFS.remove(filename);
	}
	else if (strcmp(command, "configfile") == 0)
	{
		File f = SPIFFS.open("/config.json", "w+");
		if (f)
		{
			size_t len = measureJsonPretty(jsonDoc);
			serializeJsonPretty(jsonDoc,f);
			//f.print(msg);
			f.close();
			shouldReboot = true;
			//ESP.restart();
			writeEvent("INFO", "sys", "Config stored in the SPIFFS", String(len) + " bytes");
#ifdef DEBUG
			Serial.print(F("[ INFO ] Config stored in the SPIFFS ("));
			Serial.print(len);
			Serial.println(F(" bytes)"));
#endif
		}
	}
	else if (strcmp(command, "userlist") == 0)
	{
		int page = jsonDoc["page"];
		sendUserList(page, client);
	}
	else if (strcmp(command, "status") == 0)
	{
		sendStatus();
	}
	else if (strcmp(command, "restart") == 0)
	{
		shouldReboot = true;
	}
	else if (strcmp(command, "destroy") == 0)
	{
		formatreq = true;
	}
	else if (strcmp(command, "geteventlog") == 0)
	{
		int page = jsonDoc["page"];
		sendEventLog(page);
	}
	else if (strcmp(command, "getlatestlog") == 0)
	{
		int page = jsonDoc["page"];
		sendLatestLog(page);
	}
	else if (strcmp(command, "clearevent") == 0)
	{
		SPIFFS.remove("/eventlog.json");
		writeEvent("WARN", "sys", "Event log cleared!", "");
	}
	else if (strcmp(command, "clearlatest") == 0)
	{
		SPIFFS.remove("/latestlog.json");
		writeEvent("WARN", "sys", "Latest Access log cleared!", "");
	}
	else if (strcmp(command, "userfile") == 0)
	{
		const char *uid = jsonDoc["uid"];
		String filename = "/P/";
		filename += uid;
		File f = SPIFFS.open(filename, "w+");
		// Check if we created the file
		if (f)
		{
			//f.print(msg);
			serializeJson(jsonDoc, f);
		}
		f.close();
		ws.textAll("{\"command\":\"result\",\"resultof\":\"userfile\",\"result\": true}");
	}
	else if (strcmp(command, "testrelay") == 0)
	{
		activateRelay = true;
		previousMillis = millis();
		ws.textAll("{\"command\":\"giveAccess\"}");
	}
	else if (strcmp(command, "scan") == 0)
	{
		WiFi.scanNetworks(printScanResult, true);
	}
	else if (strcmp(command, "gettime") == 0)
	{
		timerequest = true;
	}
	else if (strcmp(command, "settime") == 0)
	{
		time_t t = jsonDoc["epoch"];
		setTime(t);
		timerequest = true;
	}
	else if (strcmp(command, "getconf") == 0)
	{
		File configFile = SPIFFS.open("/config.json", "r");
		if (configFile)
		{
			size_t len = configFile.size();
			AsyncWebSocketMessageBuffer *buffer = ws.makeBuffer(len); //  creates a buffer (len + 1) for you.
			if (buffer)
			{
				configFile.readBytes((char *)buffer->get(), len + 1);
				ws.textAll(buffer);
			}
			configFile.close();
		}
	}
	free(client->_tempObject);
	client->_tempObject = NULL;
}

// Handles WebSocket Events
void onWsEvent(AsyncWebSocket *server, AsyncWebSocketClient *client, AwsEventType type, void *arg, uint8_t *data, size_t len)
{
	if (type == WS_EVT_ERROR)
	{
#ifdef DEBUG
		Serial.printf("[ WARN ] WebSocket[%s][%u] error(%u): %s\r\n", server->url(), client->id(), *((uint16_t *)arg), (char *)data);
#endif
	}
	else if (type == WS_EVT_DATA)
	{
		AwsFrameInfo *info = (AwsFrameInfo *)arg;
		uint64_t index = info->index;
		uint64_t infolen = info->len;
		if (info->final && info->index == 0 && infolen == len)
		{
			//the whole message is in a single frame and we got all of it's data
			client->_tempObject = malloc(len);
			if (client->_tempObject != NULL)
			{
				memcpy((uint8_t *)(client->_tempObject), data, len);
			}
			procMsg(client, infolen);
		}
		else
		{
			//message is comprised of multiple frames or the frame is split into multiple packets
			if (index == 0)
			{
				if (info->num == 0 && client->_tempObject == NULL)
				{
					client->_tempObject = malloc(infolen);
				}
			}
			if (client->_tempObject != NULL)
			{
				memcpy((uint8_t *)(client->_tempObject) + index, data, len);
			}
			if ((index + len) == infolen)
			{
				if (info->final)
				{
					procMsg(client, infolen);
				}
			}
		}
	}
}



void setupWebServer() {
	server.addHandler(&ws);
	ws.onEvent(onWsEvent);
	server.onNotFound([](AsyncWebServerRequest *request) {
		AsyncWebServerResponse *response = request->beginResponse(404, "text/plain", "Not found");
		request->send(response);
	});
	server.on("/update", HTTP_POST, [](AsyncWebServerRequest *request) {
		AsyncWebServerResponse * response = request->beginResponse(200, "text/plain", shouldReboot ? "OK" : "FAIL");
		response->addHeader("Connection", "close");
		request->send(response);
	}, [](AsyncWebServerRequest *request, String filename, size_t index, uint8_t *data, size_t len, bool final) {
		if (!request->authenticate(http_username, http_pass)) {
			return;
		}
		if (!index) {
			writeEvent("INFO", "updt", "Firmware update started", filename.c_str());
#ifdef DEBUG
			Serial.printf("[ UPDT ] Firmware update started: %s\n", filename.c_str());
#endif
			// Update.runAsync(true);
			if (filename == "spiffs.bin")
                {
                    // size_t fsSize = ((size_t)&_FS_end - (size_t)&_FS_start);
                    size_t fsSize = SPIFFS.totalBytes();
                    SPIFFS.end();
                    SPIFFS.begin();
                    if (!Update.begin(fsSize, U_SPIFFS)) // start with max available size
                    {
                        Update.printError(Serial);
                    }
                }
                else if (filename == "firmware.bin")
                {
                    if (!Update.begin((ESP.getFreeSketchSpace() - 0x1000) & 0xFFFFF000))
                    {
                        Update.printError(Serial);
                    }
                }
                else
                {
                    Serial.println("Filename not matching");
                }
			if (!Update.begin((ESP.getFreeSketchSpace() - 0x1000) & 0xFFFFF000)) {
				writeEvent("ERRO", "updt", "Not enough space to update","");
				#ifdef DEBUG
				Update.printError(Serial);
				#endif
			}
		}
		if (!Update.hasError()) {
			if (Update.write(data, len) != len) {
				writeEvent("ERRO", "updt", "Writing to flash is failed", filename.c_str());
				#ifdef DEBUG
				Update.printError(Serial);
				#endif
			}
		}
		if (final) {
			if (Update.end(true)) {
				writeEvent("INFO", "updt", "Firmware update is finished", "");
#ifdef DEBUG
				Serial.printf("[ UPDT ] Firmware update finished: %uB\n", index + len);
#endif
				shouldReboot = !Update.hasError();
			} else {
				writeEvent("ERRO", "updt", "Update is failed", "");
				#ifdef DEBUG
				Update.printError(Serial);
				#endif
			}
		}
	});
	
	if (http_pass == NULL) {
		http_pass = strdup("admin");
	}

	server.serveStatic("/", SPIFFS, "/www/")
		.setDefaultFile("index.html")
    .setAuthentication(http_username, http_pass);
	
	server.begin();
}


void setup()
{
#ifdef DEBUG
	Serial.begin(9600);
	Serial.println();

	Serial.print(F("[ INFO ] ESP RFID v"));
	Serial.println(VERSION);

	uint32_t realSize = ESP.getFlashChipRealSize();
	uint32_t ideSize = ESP.getFlashChipSize();
	FlashMode_t ideMode = ESP.getFlashChipMode();
	Serial.printf("Flash real id:   %08X\n", ESP.getFlashChipId());
	Serial.printf("Flash real size: %u\n\n", realSize);
	Serial.printf("Flash ide  size: %u\n", ideSize);
	Serial.printf("Flash ide speed: %u\n", ESP.getFlashChipSpeed());
	Serial.printf("Flash ide mode:  %s\n", (ideMode == FM_QIO ? "QIO" : ideMode == FM_QOUT ? "QOUT"
																	: ideMode == FM_DIO	   ? "DIO"
																	: ideMode == FM_DOUT   ? "DOUT"
																						   : "UNKNOWN"));
	if (ideSize != realSize)
	{
		Serial.println("Flash Chip configuration wrong!\n");
	}
	else
	{
		Serial.println("Flash Chip configuration ok.\n");
	}
#endif

	if (!SPIFFS.begin())
	{
#ifdef DEBUG
		Serial.print(F("[ WARN ] Formatting filesystem..."));
#endif
		if (SPIFFS.format())
		{
			writeEvent("WARN", "sys", "Filesystem formatted", "");

#ifdef DEBUG
			Serial.println(F(" completed!"));
#endif
		}
		else
		{
#ifdef DEBUG
			Serial.println(F(" failed!"));
			Serial.println(F("[ WARN ] Could not format filesystem!"));
#endif
		}
	}
	WiFi.onEvent(onWifiConnect, SYSTEM_EVENT_STA_CONNECTED);
	WiFi.onEvent(onWifiDisconnect, SYSTEM_EVENT_STA_DISCONNECTED);

	configMode = loadConfiguration();
	if (!configMode)
	{
		fallbacktoAPMode();
		configMode = false;
	}
	else
	{
		configMode = true;
	}
	setupWebServer();
	writeEvent("INFO", "sys", "System setup completed, running", "");
};

void loop()
{
	currentMillis = millis();
	deltaTime = currentMillis - previousLoopMillis;
	uptime = now();
	previousLoopMillis = currentMillis;

	button.update();
	if (button.fell())
	{
#ifdef DEBUG
		Serial.println("Button has been pressed");
#endif
		writeLatest("", "(used open/close button)", 1);
		activateRelay = true;
	}

	if (WiFi_pin != 255 && configMode && !wmode)
	{
		if (!wifiFlag)
		{
			if ((currentMillis - blink_) > 500)
			{
				blink_ = currentMillis;
				digitalWrite(WiFi_pin, !digitalRead(WiFi_pin));
			}
		}
		else
		{
			if (!(digitalRead(WiFi_pin) == LEDon))
				digitalWrite(WiFi_pin, LEDon);
		}
	}

	if (currentMillis >= cooldown)
	{
		rfidloop();
	}

	// Continuous relay mode
	if (lockType == 1)
	{
		if (activateRelay)
		{
			// currently OFF, need to switch ON
			if (digitalRead(relayPin) == !relayType)
			{
#ifdef DEBUG
				Serial.print("mili : ");
				Serial.println(millis());
				Serial.println("activating relay now");
#endif
				digitalWrite(relayPin, relayType);
			}
			else // currently ON, need to switch OFF
			{
#ifdef DEBUG
				Serial.print("mili : ");
				Serial.println(millis());
				Serial.println("deactivating relay now");
#endif
				digitalWrite(relayPin, !relayType);
			}
			activateRelay = false;
		}
	}
	else if (lockType == 0) // momentary relay mode
	{
		if (activateRelay)
		{
#ifdef DEBUG
			Serial.print("mili : ");
			Serial.println(millis());
			Serial.println("activating relay now");
#endif
			digitalWrite(relayPin, relayType);
			previousMillis = millis();
			activateRelay = false;
			deactivateRelay = true;
		}
		else if ((currentMillis - previousMillis >= activateTime) && (deactivateRelay))
		{
#ifdef DEBUG
			Serial.println(currentMillis);
			Serial.println(previousMillis);
			Serial.println(activateTime);
			Serial.println(activateRelay);
			Serial.println("deactivate relay after this");
			Serial.print("mili : ");
			Serial.println(millis());
#endif
			digitalWrite(relayPin, !relayType);
			deactivateRelay = false;
		}
	}

	if (formatreq)
	{
#ifdef DEBUG
		Serial.println(F("[ WARN ] Factory reset initiated..."));
#endif
		SPIFFS.end();
		ws.enable(false);
		SPIFFS.format();
		ESP.restart();
	}

	if (timerequest)
	{
		timerequest = false;
		sendTime();
	}

	if (autoRestartIntervalSeconds > 0 && uptime > autoRestartIntervalSeconds * 1000)
	{
		writeEvent("INFO", "sys", "System is going to reboot", "");
#ifdef DEBUG
		Serial.println(F("[ WARN ] Auto restarting..."));
#endif
		shouldReboot = true;
	}

	if (shouldReboot)
	{
		writeEvent("INFO", "sys", "System is going to reboot", "");
#ifdef DEBUG
		Serial.println(F("[ INFO ] Rebooting..."));
#endif
		ESP.restart();
	}

	if (isWifiConnected)
	{
		wiFiUptimeMillis += deltaTime;
	}

	if (wifiTimeout > 0 && wiFiUptimeMillis > (wifiTimeout * 1000) && isWifiConnected == true)
	{
		writeEvent("INFO", "wifi", "WiFi is going to be disabled", "");
		doDisableWifi = true;
	}

	if (doDisableWifi == true)
	{
		doDisableWifi = false;
		wiFiUptimeMillis = 0;
		disableWifi();
	}
	else if (doEnableWifi == true)
	{
		writeEvent("INFO", "wifi", "Enabling WiFi", "");
		doEnableWifi = false;
		if (!isWifiConnected)
		{
			wiFiUptimeMillis = 0;
			enableWifi();
		}
	}

	if (mqttEnabled == 1)
	{
		if (mqttClient.connected())
		{
			if ((unsigned)now() > nextbeat)
			{
				mqtt_publish_heartbeat(now());
				nextbeat = (unsigned)now() + interval;
#ifdef DEBUG
				Serial.print("[ INFO ] Nextbeat=");
				Serial.println(nextbeat);
#endif
			}
		}
	}
};
