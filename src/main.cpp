#include "PCAP.h"
#include "PCAPOutput.h"
#include <iostream>
#include <unistd.h>

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << *argv << " <PCAP file> [Packet index]\n";
        std::cerr << "Flags:\n-d <size> -- Sets the size of the rows when printing packet data.\n";
        return 1;
    }

    // Passing the given path to the PCAP class to read it
    PCAP pcap;
    try
    {
        pcap.ReadPcapFile(argv[1]);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }

    uint32_t dataLineSize = 16; // Default size
    switch (getopt(argc, argv, "d:"))
    {
        case 'd':
        {
            uint32_t newSize = std::stoi(optarg);
            if (newSize < 1)
            {
                std::cerr << "-d argument cannot be smaller than 1.\n";
            }
            else
            {
                dataLineSize = newSize;
            }
            break;
        }

        case -1:
            break;
    }

    PCAPOutput out(pcap, dataLineSize);
    out.PrintPcapHeader();

    if (argc < 3)
    {
        std::cerr << "Specify a packet index to view a packet.\n";
    }
    else
    {
        try
        {
            out.PrintPacket(std::stoi(argv[2]));
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
        }
    }

    return 0;
}
