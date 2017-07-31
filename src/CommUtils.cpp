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

#include <vector>
#include <algorithm>
#include <unordered_set>
#include "CommUtils.h"

#ifdef _WIN32
#include <Windows.h>
uint64_t GetWindowsPID()
{
    return GetCurrentProcessId();
}
#endif

namespace NoirSocks
{

namespace CommUtils
{

std::vector<std::string> SplitString(const std::string& str, const std::string& delim_chars)
{
    std::vector<std::string> ret;
    std::unordered_set<char> dc(delim_chars.begin(), delim_chars.end());

    size_t begin = 0;
    size_t end = 0;

    while (true)
    {
        for (begin = end; begin < str.size() && dc.count(str[begin]); ++begin);
        for (end = begin; end < str.size() && dc.count(str[end]) == 0; ++end);
        if (begin >= end) break;
        ret.push_back(str.substr(begin, end - begin));
    }

    return std::move(ret);
}

bool PatternMatch(const std::string& str, const std::string& pattern)
{
    if (str.empty() || pattern.empty())
    {
        return false;
    }

    std::vector<bool> d[2];
    d[0].resize(pattern.size() + 1, false);
    d[1].resize(pattern.size() + 1, false);
    d[0][0] = true;

    for (size_t i = 1; i <= str.size(); ++i)
    {
        char c1 = str[i - 1];
        for (size_t j = 1; j <= pattern.size(); ++j)
        {
            char c2 = pattern[j - 1];
            if (c2 == '*')
            {
                d[i & 1][j] = d[(i - 1) & 1][j] || d[i & 1][j - 1] || d[(i - 1) & 1][j - 1];
                continue;
            }
            if (c2 == '?')
            {
                d[i & 1][j] = d[(i - 1) & 1][j - 1];
                continue;
            }
            d[i & 1][j] = (c1 == c2) && d[(i - 1) & 1][j - 1];
        }
    }

    return d[str.size() & 1][pattern.size()];
}

RandomRepacker::RandomRepacker(const std::list<std::string>& packets)
    : m_Packets(packets), m_SplitIdx(-1), m_ListItr(packets.begin()), m_StrIdx(0)
{
    size_t total_len = 0;
    std::for_each(packets.begin(), packets.end(), [&](const std::string& s) {total_len += s.size();});
    if (total_len == 0)
    {
        return;
    }

    size_t remain_len = total_len;
    int split_times = (total_len >> 1);

    for (int _ = 1; _ < split_times && remain_len > 0; ++_)
    {
        size_t curr_split = Rand(1, total_len);
        curr_split = std::min(curr_split, remain_len);
        remain_len -= curr_split;
        m_Split.push_back(curr_split);
    }

    if (remain_len) m_Split.push_back(remain_len);
}

bool RandomRepacker::RandomRepack()
{
    return (++m_SplitIdx) < (int)(m_Split.size());
}

std::string RandomRepacker::GetLastPacket()
{
    std::string ret;

    if (m_SplitIdx >= (int)(m_Split.size()))
    {
        return "";
    }

    size_t curr_split = m_Split[m_SplitIdx];
    ret.reserve(curr_split);

    while (curr_split > 0 && m_ListItr != m_Packets.end())
    {
        size_t curr_str_len = m_ListItr->size() - m_StrIdx;

        if (curr_str_len > curr_split)
        {
            ret += m_ListItr->substr(m_StrIdx, curr_split);
            m_StrIdx += curr_split;
            curr_split = 0;
            break;
        }

        ret += m_ListItr->substr(m_StrIdx);
        curr_split -= curr_str_len;
        ++m_ListItr;
        m_StrIdx = 0;
    }

    return std::move(ret);
}

}

}
