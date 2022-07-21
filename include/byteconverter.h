#include <stdexcept>
#include <vector>
#include <cstdint>

template <typename T>
T BytesToInteger(const std::vector<uint8_t>& data, uint32_t offset)
{
    if (offset >= data.size())
    {
        throw std::runtime_error("Offset is greater than data size.");
    }
    else if (offset + sizeof(T) > data.size())
    {
        throw std::runtime_error("Out of bounds read.");
    }

    T integer = 0;
    for (uint32_t i = 0; i < sizeof(T) * 8; i += 8)
    {
        T byte = data[offset];
        integer += byte << i;
        offset++;
    }
    return integer;
}
