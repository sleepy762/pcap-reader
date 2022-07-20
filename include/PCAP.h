#pragma once
#include "Packet.h"
#include <vector>
#include <string>
#include <cstdint>

// a PCAP file must have one of these two magic numbers
#define MICROSECONDS_MAGIC (0xA1B2C3D4)
#define NANOSECONDS_MAGIC (0xA1B23C4D)

class PCAP
{
public:
    PCAP(const char* path);
    PCAP();
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

    void ParsePcapHeader(const std::vector<uint8_t>& pcapBytes, uint32_t& pcapFilePos);
    void ParsePackets(const std::vector<uint8_t>& pcapBytes, uint32_t& pcapFilePos);
};
