#include "utils.h"
#include <pcap/pcap.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <vector>

// Beacon 프레임 구성:
// - Radiotap Header (전체 길이: packet[2~3]에 little-endian으로 기록됨)
// - IEEE 802.11 Beacon Header (24바이트)
// - Fixed Parameters (12바이트)
// - Tagged Parameters (여러 IE가 연달아 있음)
// SSID IE는 Tagged Parameters 중 Tag 값이 0이며,
// [Tag (1바이트)] [Length (1바이트)] [SSID 문자열 (Length 바이트)]로 구성된다.
bool replaceSSID(std::vector<uint8_t>& packet, const std::string& newSSID) {
    if (packet.size() < 4)
        return false;
    
    uint16_t rtap_len;
    std::memcpy(&rtap_len, &packet[2], sizeof(rtap_len));
    if (packet.size() < rtap_len + 36) {  // Beacon Header(24) + Fixed Parameters(12)
        std::cerr << "Packet too short to be a Beacon.\n";
        return false;
    }
    
    size_t pos = rtap_len + 36;
    while (pos + 2 <= packet.size()) {
        uint8_t tagNum = packet[pos];
        uint8_t tagLen = packet[pos + 1];
        if (tagNum == 0) {
            uint8_t newLen = static_cast<uint8_t>(newSSID.length());
            packet[pos + 1] = newLen;
            packet.erase(packet.begin() + pos + 2, packet.begin() + pos + 2 + tagLen);
            packet.insert(packet.begin() + pos + 2, newSSID.begin(), newSSID.end());
            return true;
        }
        pos += 2 + tagLen;
    }
    std::cerr << "SSID IE not found in the captured packet.\n";
    return false;
}

// Beacon Header 구성 (Radiotap 뒤에 시작):
// Addr1: 목적지 (브로드캐스트) → 수정하지 않음
// Addr2: 송신자 (SA)
// Addr3: BSSID
// 두 필드 모두 크기가 6바이트이므로, newMac 문자열에 따라 Addr2와 Addr3를 동일하게 설정한다.
bool replaceBssidAndSa(std::vector<uint8_t>& packet, const std::string& newMac) {
    if (packet.size() < 4)
        return false;
    uint16_t rtap_len;
    std::memcpy(&rtap_len, &packet[2], sizeof(rtap_len));
    // Beacon Header는 Radiotap Header 직후 시작하며 총 24바이트이다.
    // Addr2는 Beacon Header에서 10번째 바이트부터(즉, packet[rtap_len + 10]) 6바이트,
    // Addr3는 Beacon Header에서 16번째 바이트부터(즉, packet[rtap_len + 16]) 6바이트에 위치한다.
    size_t addr2Pos = rtap_len + 10;
    size_t addr3Pos = rtap_len + 16;
    if (packet.size() < addr3Pos + 6) {
        std::cerr << "Packet too short to contain MAC address fields.\n";
        return false;
    }
    
    // newMac 문자열을 파싱하여 바이트 배열로 변환 ("xx:xx:xx:xx:xx:xx")
    std::istringstream iss(newMac);
    std::string byteStr;
    int macBytes[6] = {0};
    int i = 0;
    while (std::getline(iss, byteStr, ':') && i < 6) {
        macBytes[i++] = std::stoi(byteStr, nullptr, 16);
    }
    if (i != 6) {
        std::cerr << "Invalid MAC address format: " << newMac << "\n";
        return false;
    }
    
    // Addr2(송신자)와 Addr3(BSSID)를 동일하게 설정
    for (int j = 0; j < 6; j++) {
        packet[addr2Pos + j] = static_cast<uint8_t>(macBytes[j]);
        packet[addr3Pos + j] = static_cast<uint8_t>(macBytes[j]);
    }
    return true;
}

bool captureBeaconPacket(const std::string& interface, std::vector<uint8_t>& packet) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* handle = pcap_open_live(interface.c_str(), 65535, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live() error: " << errbuf << "\n";
        return false;
    }
    
    struct bpf_program fp;
    const char* filter_exp = "type mgt subtype beacon";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "pcap_compile() error\n";
        pcap_close(handle);
        return false;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "pcap_setfilter() error\n";
        pcap_freecode(&fp);
        pcap_close(handle);
        return false;
    }
    pcap_freecode(&fp);
    
    std::cout << "Beacon 패킷을 캡처 중입니다... (인터페이스: " << interface << ")\n";
    struct pcap_pkthdr* header;
    const u_char* data;
    int res = pcap_next_ex(handle, &header, &data);
    if (res != 1) {
        std::cerr << "Beacon 패킷 캡처 실패\n";
        pcap_close(handle);
        return false;
    }
    packet.assign(data, data + header->caplen);
    pcap_close(handle);
    std::cout << "Beacon 패킷 캡처 완료, 길이: " << header->caplen << " 바이트\n";
    return true;
}
