#include "Packet.h"
#include "byteconverter.h"

Packet::Packet()
{
    this->m_tsSeconds = 0;
    this->m_tsFractions = 0;
    this->m_CapturedLen = 0;
    this->m_OriginalLen = 0;
}

Packet::~Packet() {}

void Packet::ParsePacket(const std::vector<uint8_t>& data, uint32_t& pcapFilePos)
{
    // Get the seconds timestamp
    this->m_tsSeconds = BytesToInteger<uint32_t>(data, pcapFilePos);
    pcapFilePos += sizeof(uint32_t);

    // Get the microseconds/nanoseconds timestamp (depends on the magic number)
    this->m_tsFractions = BytesToInteger<uint32_t>(data, pcapFilePos);
    pcapFilePos += sizeof(uint32_t);

    // Get the captured packet length (size of the data)
    this->m_CapturedLen = BytesToInteger<uint32_t>(data, pcapFilePos);
    pcapFilePos += sizeof(uint32_t);

    // Get the original packet length
    this->m_OriginalLen = BytesToInteger<uint32_t>(data, pcapFilePos);
    pcapFilePos += sizeof(uint32_t);

    // Reserve the exact amount of space for the data
    this->m_Data.reserve(this->m_CapturedLen);
    auto dataStart = data.begin() + pcapFilePos;
    auto dataEnd = dataStart + this->m_CapturedLen;
    this->m_Data = {dataStart, dataEnd};

    // Move the position pointer to the beginning of the next packet
    pcapFilePos += this->m_CapturedLen;
}

uint32_t Packet::GetTimestampSeconds() const
{
    return this->m_tsSeconds;
}

uint32_t Packet::GetTimestampFractions() const
{
    return this->m_tsFractions;
}

uint32_t Packet::GetCapturedLen() const
{
    return this->m_CapturedLen;
}

uint32_t Packet::GetOriginalLen() const
{
    return this->m_OriginalLen;
}

const std::vector<uint8_t>& Packet::GetData() const
{
    return this->m_Data;
}
