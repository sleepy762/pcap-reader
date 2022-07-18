#include "PCAP.h"
#include <fstream>
#include "byteconverter.h"

PCAP::PCAP(const char* path)
{
    this->ReadPcapFile(path);
}

PCAP::~PCAP() {}

void PCAP::ReadPcapFile(const char* path)
{
    // Open the pcap file and read all of it into a vector of bytes
    std::ifstream pcap(path, std::ios::binary);
    std::vector<uint8_t> pcapBytes((std::istreambuf_iterator<char>(pcap)), std::istreambuf_iterator<char>());
    uint32_t pcapFilePos = 0;

    // Get the magic number at the first 4 bytes of the pcap file
    this->m_Magic = BytesToInteger<uint32_t>(pcapBytes, pcapFilePos);
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
    this->m_FCS >>= 4;
}

const std::string& PCAP::GetPcapFile() const
{
    return this->m_pcapFile;
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
