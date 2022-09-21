#include "PCAPOutput.h"
#include <stdexcept>
#include <cctype>
#include "getch.h"
#include <iostream>
#include <fmt/core.h>

#define INTERACTIVE_QUIT_KEY ('q')
#define INTERACTIVE_FORWARD_KEY ('n')
#define INTERACTIVE_BACKWARD_KEY ('b')

#define CLEAR_SCREEN ("\033[2J\033[1;1H")

PCAPOutput::PCAPOutput(const PCAP& pcap, ProgramOpts& opts)
    : m_PCAP(pcap), m_Opts(opts),
    m_FirstPacketSeconds(pcap.GetPackets()[0].GetTimestampSeconds()),
    m_FirstPacketFractions(pcap.GetPackets()[0].GetTimestampFractions())
{}

PCAPOutput::~PCAPOutput() {}

void PCAPOutput::PrintPcapHeader() const
{
    // Don't print the pcap header if the omit flag is set
    if (this->m_Opts.GetOmitHeadersFlag())
    {
        return;
    }

    fmt::print(
        "== PCAP HEADER ==\n"
        "PCAP path: {}\n"
        "Magic: {:#x}\n"
        "PCAP format version: {}.{}\n"
        "Snap length: {}\n"
        "Link type: {}\n"
        "FCS: {}\n"
        "Amount of packets: {}\n\n",
        this->m_PCAP.GetPcapFilePath(),
        this->m_PCAP.GetMagic(),
        this->m_PCAP.GetMajorVersion(), this->m_PCAP.GetMinorVersion(),
        this->m_PCAP.GetSnapLen(),
        this->m_PCAP.GetLinkType(),
        (int)this->m_PCAP.GetFCS(),
        this->m_PCAP.GetPackets().size());
}

void PCAPOutput::PrintPacketHeader(const Packet& packet, const unsigned int index) const
{
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

    fmt::print("== Packet {} ==\n", index);

    // Print the correct time, according to the pcap magic
    int32_t paddingWidth = (pcapMagic == MICROSECONDS_MAGIC) ? 6 : 9;
    fmt::print("Unix timestamp: {}.{:0{}}\n", packet.GetTimestampSeconds(), 
        packet.GetTimestampFractions(), paddingWidth);

    fmt::print("Relative timestamp: {}.{:0{}}\n", relativeSeconds, 
        relativeFractions, paddingWidth);

    fmt::print("Captured packet size: {}\n", packet.GetCapturedLen());
    fmt::print("Original packet size: {}\n", packet.GetOriginalLen());
}

void PCAPOutput::PrintPacket() const
{
    unsigned int index = 0;
    if (!this->m_Opts.GetPacketIndexSetFlag() && !this->m_Opts.GetInteractiveModeFlag())
    {
        fmt::print("Specify a packet to print with the -n flag, or open in interactive mode with -i.\n");
        return;
    }
    else
    {
        index = this->m_Opts.GetPacketIndex();
    }

    auto packetVector = this->m_PCAP.GetPackets();
    if (index >= packetVector.size())
    {
        throw std::runtime_error("Packet index out of range.");
    }

    Packet packet = packetVector[index];

    if (!this->m_Opts.GetOmitHeadersFlag())
    {
        this->PrintPacketHeader(packet, index);
    }

    if (this->m_Opts.GetRawDataModeFlag())
    {
        this->PrintPacketDataRaw(packet);
    }
    else
    {
        this->PrintPacketDataFormatted(packet);
    }
}

void PCAPOutput::PrintPacketDataRaw(const Packet& packet) const
{
    std::string dataStr = "";
    auto data = packet.GetData();
    for (size_t i = 0; i < data.size(); i++)
    {
        dataStr += data[i];
    }
    std::cout << dataStr;
}

void PCAPOutput::PrintPacketDataFormatted(const Packet& packet) const
{
    const int dataLineSize = this->m_Opts.GetDataLineSize();
    if (dataLineSize < 1)
    {
        throw std::runtime_error("Data line size is less than 1.");
    }

    fmt::print("Packet data:\n");

    auto data = packet.GetData();
    for (uint32_t i = 0; i < data.size(); i += dataLineSize)
    {
        std::string printableData = "";
        fmt::print("{:#06x}: ", i); // Print offset
        for (uint8_t j = 0; j < dataLineSize; j++)
        {
            // Avoid going out of bounds
            if (i + j >= data.size())
            {
                // Add padding if the last line is shorter
                for (uint8_t k = 0; k < dataLineSize - j; k++)
                {
                    fmt::print("   ");
                }
                break;
            }

            int c = data[i + j]; // Read a byte from the data and store in int to print the byte in hex
            fmt::print("{:02x} ", c); // Output in hex

            // Save ASCII character, if it's printable
            printableData += std::isprint(c) ? c : '.';
        }
        fmt::print("|{}|\n", printableData);
    }
}

void PCAPOutput::StartOutput() const
{
    if (this->m_Opts.GetInteractiveModeFlag())
    {
        this->InteractiveMode();
    }
    else
    {
        this->NonInteractiveMode();
    }
}

void PCAPOutput::InteractiveMode() const
{
    int maxIndex = this->m_PCAP.GetPackets().size() - 1;
    char c;

    do
    {
        int currentIndex = this->m_Opts.GetPacketIndex();

        fmt::print(CLEAR_SCREEN);
        this->PrintPcapHeader();
        this->PrintPacket();

        fmt::print("\nPress 'N' to go to the next packet, 'B' to go to the previous packet, "
            "or 'Q' to quit the program.\n");

        c = getch();
        switch (c)
        {
            case INTERACTIVE_FORWARD_KEY:
                if (currentIndex + 1 <= maxIndex)
                {
                    this->m_Opts.SetPacketIndex(currentIndex + 1);
                }
                break;

            case INTERACTIVE_BACKWARD_KEY:
                if (currentIndex - 1 >= 0)
                {
                    this->m_Opts.SetPacketIndex(currentIndex - 1);
                }
                break;

            default:
                break;
        }
    } while (c != INTERACTIVE_QUIT_KEY);
}

void PCAPOutput::NonInteractiveMode() const
{
    this->PrintPcapHeader();
    this->PrintPacket();
}
