#include <PCAP.h>
#include <iostream>

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << *argv << " <path to pcap file>\n";
        return 1;
    }

    // Passing the given path to the PCAP class to read it
    PCAP pcap(argv[1]);

    std::cout << "Magic: 0x" << std::hex << pcap.GetMagic() << std::dec << '\n';
    std::cout << "PCAP format version: " << pcap.GetMajorVersion() << '.' << pcap.GetMinorVersion()<< '\n';
    std::cout << "Snap len: " << pcap.GetSnapLen() << '\n';
    std::cout << "Link type: " << pcap.GetLinkType() << '\n';
    std::cout << "FCS: " << (int)pcap.GetFCS() << '\n';
    return 0;
}
