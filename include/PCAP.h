#pragma once
#include "Packet.h"
#include <vector>
#include <string>
#include <cstdint>

class PCAP
{
public:
    PCAP(const char* path);
    ~PCAP();

    // (Re)Sets all the private members
    void ReadPcapFile(const char* path);

    // Getters
    const std::string& GetPcapFile() const;
    uint32_t GetMagic() const;
    uint16_t GetMajorVersion() const;
    uint16_t GetMinorVersion() const;
    uint32_t GetSnapLen() const;
    uint32_t GetLinkType() const;
    uint8_t GetFCS() const;
    const std::vector<Packet>& GetPackets() const;

private:
    std::string m_pcapFile;
    uint32_t m_Magic;
    uint16_t m_MajorVersion;
    uint16_t m_MinorVersion;
    uint32_t m_SnapLen;
    uint32_t m_LinkType;
    uint8_t m_FCS;
    std::vector<Packet> m_Packets;
};
