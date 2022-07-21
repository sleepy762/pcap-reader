#include "PCAPOutput.h"
#include <iostream>
#include <stdexcept>
#include <iomanip>
#include <cctype>
#include "getch.h"

#define INTERACTIVE_QUIT_KEY ('q')
#define INTERACTIVE_FORWARD_KEY ('n')
#define INTERACTIVE_BACKWARD_KEY ('b')

#define CLEAR_SCREEN ("\033[2J\033[1;1H")

using std::cout;

PCAPOutput::PCAPOutput(const PCAP& pcap, ProgramOpts& opts)
    : m_PCAP(pcap), m_Opts(opts),
    m_FirstPacketSeconds(pcap.GetPackets()[0].GetTimestampSeconds()),
    m_FirstPacketFractions(pcap.GetPackets()[0].GetTimestampFractions())
{}

PCAPOutput::~PCAPOutput() {}

void PCAPOutput::PrintPcapHeader() const
{
    // Don't print the pcap header if the omit flag is set
    if (this->m_Opts.GetOmitHeaderFlag())
    {
        return;
    }

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

void PCAPOutput::PrintPacket() const
{
    unsigned int index = 0;
    if (!this->m_Opts.GetPacketIndexSetFlag() && !this->m_Opts.GetInteractiveModeFlag())
    {
        cout << "Specify a packet to print with the -n flag, or open in interactive mode with -i.\n";
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

    cout << "== Packet " << index << " ==\n";

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
    const int dataLineSize = this->m_Opts.GetDataLineSize();
    if (dataLineSize < 1)
    {
        throw std::runtime_error("Data line size is less than 1.");
    }

    cout << "Packet data:\n";

    auto data = p.GetData();
    for (uint32_t i = 0; i < data.size(); i += dataLineSize)
    {
        std::string printableData = "";
        cout << std::setfill('0') << std::setw(4) << std::hex << i << ": ";
        for (uint8_t j = 0; j < dataLineSize; j++)
        {
            // Avoid going out of bounds
            if (i + j >= data.size())
            {
                // Add padding if the last line is shorter
                for (uint8_t k = 0; k < dataLineSize - j; k++)
                {
                    cout << "   ";
                }
                break;
            }

            int c = data[i + j]; // Read a byte from the data and store in int to print the byte in hex
            cout << std::setfill('0') << std::setw(2) << c << ' '; // Output in hex

            // Save ASCII character, if it's printable
            printableData += std::isprint(c) ? c : '.';
        }
        cout << std::dec << '|' << printableData << "|\n";
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

        cout << CLEAR_SCREEN;
        this->PrintPcapHeader();
        this->PrintPacket();

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
                if (currentIndex - 1 > 0)
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
