#pragma once
#include <string>

class ProgramOpts
{
public:
    ProgramOpts();
    ~ProgramOpts();

    // Setters
    void SetPcapPath(const std::string path);
    void SetDataLineSize(const int dataLineSize);
    void SetPacketIndex(const int packetIndex);
    void SetInteractiveMode(const bool setting);
    void SetOmitHeadersFlag(const bool setting);
    void SetRawDataMode(const bool setting);

    // Getters
    const std::string& GetPcapPath() const;
    int GetDataLineSize() const;
    bool GetPacketIndexSetFlag() const;
    int GetPacketIndex() const;
    bool GetInteractiveModeFlag() const;
    bool GetOmitHeadersFlag() const;
    bool GetRawDataModeFlag() const;

private:
    std::string m_PcapPath;

    int m_DataLineSize;

    bool m_PacketIndexSetFlag;
    int m_PacketIndex;

    bool m_InteractiveMode;
    
    bool m_OmitHeadersFlag;

    bool m_RawDataMode;
};
