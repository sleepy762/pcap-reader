#include "PCAP.h"
#include "PCAPOutput.h"
#include <iostream>

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << *argv << " <PCAP file> [Packet index]\n";
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

    PCAPOutput out(pcap);
    out.PrintPcapHeader();

    if (argc < 3)
    {
        std::cerr << "Specify a packet index to view a packet." << '\n';
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
