#include "PCAP.h"
#include "PCAPOutput.h"
#include <iostream>
#include <unistd.h>

void PrintAvailableFlags();

int main(int argc, char** argv)
{
    int32_t dataLineSize = 16; // Default size
    int32_t packetIndex = 0;
    bool packetIndexSet = false;
    bool interactiveMode = false;
    bool omitPcapHeader = false;
    std::string pcapFilePath = "";

    int opt;
    while ((opt = getopt(argc, argv, "f:d:n:ih")) != -1)
    {
        switch (opt)
        {
            case 'f':
                pcapFilePath = optarg;
                break;

            case 'd':
            {
                int32_t newSize = 0;
                try
                {
                    newSize = std::stoi(optarg);
                }
                catch(const std::exception& e)
                {
                    std::cerr << *argv << ": Invalid -d argument.\n";
                    break;
                }
                
                if (newSize < 1)
                {
                    std::cerr << *argv << ": -d argument cannot be smaller than 1.\n";
                }
                else
                {
                    dataLineSize = newSize;
                }
                break;
            }

            case 'n':
                try
                {
                    packetIndex = std::stoi(optarg);
                    packetIndexSet = true;
                }
                catch(const std::exception& e)
                {
                    std::cerr << *argv << ": Invalid -n argument.\n";
                }
                break;

            case 'i':
                interactiveMode = true;
                break;

            case 'h':
                omitPcapHeader = true;
                break;

            case -1:
                break;
        }
    }
    if (pcapFilePath == "")
    {
        PrintAvailableFlags();    
        return 1;
    }

    // Passing the given path to the PCAP class to read it
    PCAP pcap;
    try
    {
        pcap.ReadPcapFile(pcapFilePath);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }

    PCAPOutput out(pcap, dataLineSize);
    if (interactiveMode)
    {

    }
    else
    {
        if (!omitPcapHeader)
        {
            out.PrintPcapHeader();
        }

        if (packetIndexSet)
        {
            try
            {
                out.PrintPacket(packetIndex);
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
            }
        }
        else
        {
            std::cout << "Specify a packet to print with the -n flag, or open in interactive mode with -i.\n";
        }
    }

    return 0;
}

void PrintAvailableFlags()
{
    std::cout << "Required flags:\n\t";
    std::cout << "-f <pcap> -- Specify the path to a pcap file to read.\n";

    std::cout << "Optional flags:\n\t";
    std::cout << "-d <size> -- Sets the size of the rows when printing packet data.\n\t";
    std::cout << "-n <index> -- Start from/print a specific packet at the given index.\n\t";
    std::cout << "-i -- Open the reader in interactive mode.\n\t";
    std::cout << "-h -- Don't print the pcap header.\n";
}
