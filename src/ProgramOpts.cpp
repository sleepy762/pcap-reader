#include "ProgramOpts.h"
#include <stdexcept>

ProgramOpts::ProgramOpts()
{
    this->m_DataLineSize = 16; // Default value
    this->m_InteractiveMode = false;
    this->m_OmitHeadersFlag = false;
    this->m_PacketIndex = 0;
    this->m_PacketIndexSetFlag = false;
    this->m_PcapPath = "";
}

ProgramOpts::~ProgramOpts() {}

// Setters
void ProgramOpts::SetPcapPath(const std::string path)
{
    this->m_PcapPath = path;
}

void ProgramOpts::SetDataLineSize(const int dataLineSize)
{
    if (dataLineSize < 1)
    {
        throw std::runtime_error("Data line size cannot be smaller than 1.");
    }
    this->m_DataLineSize = dataLineSize;
}

void ProgramOpts::SetPacketIndex(const int packetIndex)
{
    if (packetIndex < 0)
    {
        throw std::runtime_error("Packet index cannot be negative.");
    }
    this->m_PacketIndex = packetIndex;
    this->m_PacketIndexSetFlag = true;
}

void ProgramOpts::SetInteractiveMode(const bool setting)
{
    this->m_InteractiveMode = setting;
}

void ProgramOpts::SetOmitHeadersFlag(const bool setting)
{
    this->m_OmitHeadersFlag = setting;
}

void ProgramOpts::SetRawDataMode(const bool setting)
{
    this->m_RawDataMode = setting;
}

// Getters
const std::string& ProgramOpts::GetPcapPath() const
{
    return this->m_PcapPath;
}

int ProgramOpts::GetDataLineSize() const
{
    return this->m_DataLineSize;
}

bool ProgramOpts::GetPacketIndexSetFlag() const
{
    return this->m_PacketIndexSetFlag;
}

int ProgramOpts::GetPacketIndex() const
{
    return this->m_PacketIndex;
}

bool ProgramOpts::GetInteractiveModeFlag() const
{
    return this->m_InteractiveMode;
}

bool ProgramOpts::GetOmitHeadersFlag() const
{
    return this->m_OmitHeadersFlag;
}

bool ProgramOpts::GetRawDataModeFlag() const
{
    return this->m_RawDataMode;
}
