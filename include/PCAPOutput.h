#pragma once
#include "PCAP.h"
#include "ProgramOpts.h"

class PCAPOutput
{
public:
    PCAPOutput(const PCAP& pcap, ProgramOpts& opts);
    ~PCAPOutput();

    void PrintPcapHeader() const;
    void PrintPacket() const;
    void PrintPacketData(const Packet& p) const;

    void StartOutput() const;

private:
    void InteractiveMode() const;
    void NonInteractiveMode() const;

    const PCAP& m_PCAP;
    ProgramOpts& m_Opts;
    const uint32_t m_FirstPacketSeconds;
    const uint32_t m_FirstPacketFractions;
};
