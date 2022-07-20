#pragma once
#include "PCAP.h"

class PCAPOutput
{
public:
    PCAPOutput(const PCAP& pcap, uint32_t dataLineSize);
    ~PCAPOutput();

    void PrintPcapHeader() const;
    void PrintPacket(uint32_t index) const;
    void PrintPacketData(const Packet& p) const;

private:
    const PCAP& m_PCAP;
    const uint32_t m_FirstPacketSeconds;
    const uint32_t m_FirstPacketFractions;
    uint32_t m_DataLineSize;
};
