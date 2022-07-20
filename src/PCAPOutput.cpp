#include "PCAPOutput.h"
#include <iostream>
#include <stdexcept>
#include <iomanip>
#include <cctype>

#define CLEAR_SCREEN ("\033[2J\033[1;1H")

using std::cout;

PCAPOutput::PCAPOutput(const PCAP& pcap, uint32_t dataLineSize)
    : m_PCAP(pcap), 
    m_FirstPacketSeconds(pcap.GetPackets()[0].GetTimestampSeconds()),
    m_FirstPacketFractions(pcap.GetPackets()[0].GetTimestampFractions()) 
{
    this->m_DataLineSize = dataLineSize;
}

PCAPOutput::~PCAPOutput() {}

void PCAPOutput::PrintPcapHeader() const
{
    cout << "== PCAP HEADER ==\n";
    cout << "PCAP path: " << this->m_PCAP.GetPcapFilePath() << '\n';
    cout << "Magic: 0x" << std::hex << this->m_PCAP.GetMagic() << std::dec << '\n';
    cout << "PCAP format version: " << this->m_PCAP.GetMajorVersion() << '.' 
        << this->m_PCAP.GetMinorVersion()<< '\n';
    cout << "Snap len: " << this->m_PCAP.GetSnapLen() << '\n';
    cout << "Link type: " << this->m_PCAP.GetLinkType() << '\n';
    cout << "FCS: " << (int)this->m_PCAP.GetFCS() << '\n';
    cout << "Packets number: " << this->m_PCAP.GetPackets().size() << "\n\n";
}

void PCAPOutput::PrintPacket(uint32_t index) const
{
    auto packetVector = this->m_PCAP.GetPackets();
    if (index >= packetVector.size())
    {
        throw std::runtime_error("Packet index out of range.");
    }

    Packet packet = packetVector[index];

    uint32_t pcapMagic = this->m_PCAP.GetMagic();
    int32_t relativeSeconds = packet.GetTimestampSeconds() - this->m_FirstPacketSeconds;
    int32_t relativeFractions = packet.GetTimestampFractions() - this->m_FirstPacketFractions;
    if (relativeFractions < 0) // Calculate the relative timestamp for the packet
    {
        relativeSeconds--;
        // Add the negative relativeFractions to 1 second
        if (pcapMagic == MICROSECONDS_MAGIC)
        {
            relativeFractions += 1000000;
        }
        else
        {
            relativeFractions += 1000000000;
        }
    }

    cout << "== Packet #" << index << " ==\n";

    // Print the correct time, according to the pcap magic
    int32_t paddingWidth = (pcapMagic == MICROSECONDS_MAGIC) ? 6 : 9;
    cout << "Unix timestamp: " << packet.GetTimestampSeconds() << '.'
        << std::setfill('0') << std::setw(paddingWidth) << packet.GetTimestampFractions() << '\n';

    cout << "Relative timestamp: " << relativeSeconds << '.' 
        << std::setfill('0') << std::setw(paddingWidth) << relativeFractions << '\n';

    cout << "Captured packet size: " << packet.GetCapturedLen() << '\n';
    cout << "Original packet size: " << packet.GetOriginalLen() << '\n';

    this->PrintPacketData(packet);
}

void PCAPOutput::PrintPacketData(const Packet& p) const
{
    cout << "Packet data:\n";

    auto data = p.GetData();
    for (uint32_t i = 0; i < data.size(); i += this->m_DataLineSize)
    {
        std::string printableData = "";
        cout << std::setfill('0') << std::setw(4) << std::hex << i << ": ";
        for (uint8_t j = 0; j < this->m_DataLineSize; j++)
        {
            // Avoid going out of bounds
            if (i + j >= data.size())
            {
                // Add padding if the last line is shorter
                for (uint8_t k = 0; k < this->m_DataLineSize - j; k++)
                {
                    cout << "   ";
                }
                break;
            }

            int c = data[i + j]; // Read a byte from the data
            cout << std::setfill('0') << std::setw(2) << c << ' '; // Output in hex

            // Save ASCII character, if it's printable
            printableData += std::isprint(c) ? c : '.';
        }
        cout << '|' << printableData << "|\n";
    }
}
