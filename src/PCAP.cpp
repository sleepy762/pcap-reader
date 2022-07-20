#include "PCAP.h"
#include <fstream>
#include "byteconverter.h"

#define PCAP_HEADER_SIZE (24)

PCAP::PCAP(std::string path)
{
    this->ReadPcapFile(path);
}

PCAP::PCAP()
{
    this->m_pcapFilePath = "";
    this->m_Magic = 0;
    this->m_MajorVersion = 0;
    this->m_MinorVersion = 0;
    this->m_SnapLen = 0;
    this->m_LinkType = 0;
    this->m_FCS = 0;
}

PCAP::~PCAP() {}

void PCAP::ReadPcapFile(std::string path)
{
    // Open the pcap file and read all of it into a vector of bytes
    std::ifstream pcap(path, std::ios::binary);
    if (!pcap.is_open())
    {
        throw std::runtime_error("Failed to open file.");
    }
    this->m_pcapFilePath = path;

    std::vector<uint8_t> pcapBytes((std::istreambuf_iterator<char>(pcap)), std::istreambuf_iterator<char>());
    uint32_t pcapFilePos = 0;

    this->ParsePcapHeader(pcapBytes, pcapFilePos);
    this->ParsePackets(pcapBytes, pcapFilePos);
}

void PCAP::ParsePcapHeader(const std::vector<uint8_t>& pcapBytes, uint32_t& pcapFilePos)
{
    // Get the magic number at the first 4 bytes of the pcap file
    this->m_Magic = BytesToInteger<uint32_t>(pcapBytes, pcapFilePos);
    // Make sure the magic is valid
    if (this->m_Magic != MICROSECONDS_MAGIC && this->m_Magic != NANOSECONDS_MAGIC)
    {
        throw std::runtime_error("Invalid PCAP magic.");
    }
    pcapFilePos += sizeof(uint32_t);

    // Get the version numbers
    this->m_MajorVersion = BytesToInteger<uint16_t>(pcapBytes, pcapFilePos);
    pcapFilePos += sizeof(uint16_t);
    this->m_MinorVersion = BytesToInteger<uint16_t>(pcapBytes, pcapFilePos);
    pcapFilePos += sizeof(uint16_t);

    // Skip the 2 reserved fields
    pcapFilePos += sizeof(uint32_t) * 2;

    // Get the snap len
    this->m_SnapLen = BytesToInteger<uint32_t>(pcapBytes, pcapFilePos);
    pcapFilePos += sizeof(uint32_t);

    // Get the link type
    this->m_LinkType = BytesToInteger<uint32_t>(pcapBytes, pcapFilePos);

    // Get the FCS
    this->m_FCS = BytesToInteger<uint8_t>(pcapBytes, pcapFilePos);
    this->m_FCS >>= 4; // The FCS is 4 bits long

    // Go to the beginning of the first packet
    pcapFilePos += sizeof(uint32_t);
}

void PCAP::ParsePackets(const std::vector<uint8_t>& pcapBytes, uint32_t& pcapFilePos)
{
    if (pcapFilePos < PCAP_HEADER_SIZE)
    {
        throw std::runtime_error("PCAP header was not parsed properly.");
    }

    while (pcapFilePos < pcapBytes.size())
    {
        Packet packet;
        packet.ParsePacket(pcapBytes, pcapFilePos);
        this->m_Packets.push_back(packet);
    }
}

const std::string& PCAP::GetPcapFilePath() const
{
    return this->m_pcapFilePath;
}

uint32_t PCAP::GetMagic() const
{
    return this->m_Magic;
}

uint16_t PCAP::GetMajorVersion() const
{
    return this->m_MajorVersion;
}

uint16_t PCAP::GetMinorVersion() const
{
    return this->m_MinorVersion;
}

uint32_t PCAP::GetSnapLen() const
{
    return this->m_SnapLen;
}

uint32_t PCAP::GetLinkType() const
{
    return this->m_LinkType;
}

uint8_t PCAP::GetFCS() const
{
    return this->m_FCS;
}

const std::vector<Packet>& PCAP::GetPackets() const
{
    return this->m_Packets;
}
