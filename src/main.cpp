#include "PCAP.h"
#include "PCAPOutput.h"
#include "ProgramOpts.h"
#include <unistd.h>
#include <fmt/core.h>

ProgramOpts ParseProgramOptions(int argc, char** argv);
void PrintAvailableFlags();

int main(int argc, char** argv)
{
    ProgramOpts opts = ParseProgramOptions(argc, argv);
    if (opts.GetPcapPath() == "") // Pcap path is a required argument
    {
        PrintAvailableFlags();    
        return 1;
    }

    // Passing the given path to the PCAP class to read it
    PCAP pcap;
    try
    {
        pcap.ReadPcapFile(opts.GetPcapPath());
    }
    catch(const std::exception& e)
    {
        fmt::print(stderr, "{}\n", e.what());
        return 1;
    }

    PCAPOutput out(pcap, opts);
    try
    {
        out.StartOutput();
    }
    catch(const std::exception& e)
    {
        fmt::print(stderr, "{}\n", e.what());
    }

    return 0;
}

ProgramOpts ParseProgramOptions(int argc, char** argv)
{
    ProgramOpts opts;
    int opt;

    std::string err;
    while ((opt = getopt(argc, argv, "f:d:n:ihr")) != -1)
    {
        switch (opt)
        {
            case 'f':
                opts.SetPcapPath(optarg);
                break;

            case 'd':
                try
                {
                    opts.SetDataLineSize(std::stoi(optarg));
                }
                catch(const std::exception& e)
                {
                    fmt::print(stderr, "{}: Invalid -d argument: {}\n", *argv, e.what());
                }
                break;

            case 'n':
                try
                {
                    opts.SetPacketIndex(std::stoi(optarg));
                }
                catch(const std::exception& e)
                {
                    fmt::print(stderr, "{}: Invalid -n argument: {}\n", *argv, e.what());
                }
                break;

            case 'i':
                opts.SetInteractiveMode(true);
                break;

            case 'h':
                opts.SetOmitHeadersFlag(true);
                break;
            
            case 'r':
                opts.SetRawDataMode(true);
                break;

            case -1:
                break;
        }
    }
    return opts;
}

void PrintAvailableFlags()
{
    fmt::print(
        "Required flags:\n\t"
        "-f <pcap> -- Specify the path to a pcap file to read.\n"

        "Optional flags:\n\t"
        "-d <size> -- Sets the size of the rows when printing packet data.\n\t"
        "-n <index> -- Start from/print a specific packet at the given index.\n\t"
        "-i -- Open the reader in interactive mode.\n\t"
        "-h -- Don't print the pcap and packet headers.\n\t"
        "-r -- Print packet data in raw format.\n");
}
