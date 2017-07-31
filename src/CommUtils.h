/*
    NoirSocks-core : core library of NoirSocks
    Copyright (C) 2017  NoirSocks

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <cstdlib>
#include <list>
#include <vector>
#include <string>
#include <sstream>
#include <random>
#include <cstdio>
#include <utility>
#include <stdint.h>

#ifdef _WIN32
    #define GET_PID_FUNC GetWindowsPID
    uint64_t GetWindowsPID();
#else
    #include <unistd.h>
    #define GET_PID_FUNC getpid
#endif

namespace NoirSocks
{

namespace CommUtils
{

template<typename T>
inline T strto(const std::string& str)
{
    T ret;
    std::istringstream ss(str);
    ss >> ret;
    return std::move(ret);
}

template<typename T>
inline std::string tostr(const T& value)
{
    std::ostringstream ss;
    ss << value;
    return ss.str();
}

template<typename Iter>
inline std::string tostr(Iter begin, Iter end, const std::string& split = "|")
{
    std::string ret;
    for (Iter curr = begin; curr != end; ++curr)
    {
        if (curr != begin) ret += split;
        ret += tostr(*curr);
    }
    return std::move(ret);
}

template<typename CharIter>
inline std::string tohex(CharIter begin, CharIter end)
{
    std::string ret;
    for (CharIter curr = begin; curr != end; ++curr)
    {
        static char tmp[16];
        snprintf(tmp, 16, "%02X", (uint32_t)(*(unsigned char*)(&(*curr))));
        ret += tmp;
    }
    return std::move(ret);
}

std::vector<std::string> SplitString(const std::string& str, const std::string& delim_chars);

inline uint64_t GetProcessId()
{
    return GET_PID_FUNC();
}

#ifdef _WIN32
inline std::mt19937* GetRandGen()
{
    static std::mt19937 r;
    return &r;
}
#endif

inline void Srand(uint64_t seed)
{
#ifdef _WIN32
    GetRandGen()->seed(seed);
#endif
}

//return a random value in [min, max]
inline uint32_t Rand(uint32_t min, uint32_t max)
{
    if (min >= max) return min;
    std::uniform_int_distribution<uint32_t> dist(min, max);
#ifdef _WIN32
    return dist(*GetRandGen());
#else
    static std::mt19937 engine((std::random_device())());
    return dist(engine);
#endif
}

template<typename Iter>
inline Iter RandomChoice(Iter begin, size_t size)
{
    if (size == 0) return begin;
    size_t rand_idx = Rand(0, size - 1);
    while (rand_idx--) ++begin;
    return begin;
}

bool PatternMatch(const std::string& str, const std::string& pattern);

class RandomRepacker
{
public:
    explicit RandomRepacker(const std::list<std::string>& packets);

    bool RandomRepack();
    std::string GetLastPacket();
private:
    const std::list<std::string>& m_Packets;
    std::vector<size_t> m_Split;
    int m_SplitIdx;
    std::list<std::string>::const_iterator m_ListItr;
    size_t m_StrIdx;
};

#define REPEAT_1(stmt) {stmt}
#define REPEAT_2(stmt) REPEAT_1(stmt) REPEAT_1(stmt)
#define REPEAT_4(stmt) REPEAT_2(stmt) REPEAT_2(stmt)
#define REPEAT_8(stmt) REPEAT_4(stmt) REPEAT_4(stmt)

inline uint16_t read16(const void* net_data)
{
    const uint8_t * p = (const uint8_t*)net_data;
    uint16_t ret = 0;
    REPEAT_2(ret = ret << 8; ret = ret | (*p); ++p;);
    return ret;
}

inline uint32_t read32(const void* net_data)
{
    const uint8_t * p = (const uint8_t*)net_data;
    uint32_t ret = 0;
    REPEAT_4(ret = ret << 8; ret = ret | (*p); ++p;);
    return ret;
}

inline uint64_t read64(const void* net_data)
{
    const uint8_t * p = (const uint8_t*)net_data;
    uint64_t ret = 0;
    REPEAT_8(ret = ret << 8; ret = ret | (*p); ++p;);
    return ret;
}

inline void write16(void* net_data, uint16_t v)
{
    uint8_t * p = ((uint8_t*)net_data) + 2;
    REPEAT_2(--p; *p = (uint8_t)(v & 0xFF); v = v >> 8;);
}

inline void write32(void* net_data, uint32_t v)
{
    uint8_t * p = ((uint8_t*)net_data) + 4;
    REPEAT_4(--p; *p = (uint8_t)(v & 0xFF); v = v >> 8;);
}

inline void write64(void* net_data, uint64_t v)
{
    uint8_t * p = ((uint8_t*)net_data) + 8;
    REPEAT_8(--p; *p = (uint8_t)(v & 0xFF); v = v >> 8;);
}

};

};
