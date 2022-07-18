#pragma once
#include <vector>
#include <string>
#include <cstdint>

class Packet
{
public:
    // Sets all the private members
    void ParsePacket(const std::string data);

    // Getters
    uint32_t GetTimestampSeconds() const;
    uint32_t GetTimestampFractions() const;
    uint32_t GetCapturedLen() const;
    uint32_t GetOriginalLen() const;
    const std::vector<std::byte>& GetData() const;

private:
    uint32_t m_tsSeconds;
    uint32_t m_tsFractions;
    uint32_t m_CapturedLen;
    uint32_t m_OriginalLen;
    std::string data;
};
