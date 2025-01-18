#pragma once
#include <vector>
#include <cstdint>
#include <string>

// Beacon 패킷 내의 SSID IE(Tag 0)를 찾아 newSSID로 교체한다.
// 새로운 SSID 길이에 맞게 IE의 길이 필드도 업데이트하며 기존 데이터를 수정한다.
bool replaceSSID(std::vector<uint8_t>& packet, const std::string& newSSID);

// Beacon 패킷 내의 송신자(SA)와 BSSID 필드(Addr2와 Addr3)를 newMac로 변경한다.
// newMac은 "xx:xx:xx:xx:xx:xx" 형식의 문자열이어야 한다.
bool replaceBssidAndSa(std::vector<uint8_t>& packet, const std::string& newMac);

// libpcap을 이용하여 지정한 인터페이스에서 Beacon 패킷을 한 개 캡처한다.
// 캡처한 패킷은 packet 벡터에 저장된다.
bool captureBeaconPacket(const std::string& interface, std::vector<uint8_t>& packet);
