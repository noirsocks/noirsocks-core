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

#include "Logger.h"
#include "CommUtils.h"
#include "UDP_Prefix.h"

namespace NoirSocks
{

namespace Protocol
{

void UDP_Prefix::FeedUdpReadData(std::string data, const std::string& host, uint16_t port)
{
    if (m_LimitSrc && (host != m_LimitHost || port != m_LimitPort))
    {
        ERROR_LOG("UDP Socket %llu is limited to recieve from [%s:%d], packet from [%s:%d] is ignored",
            m_ID, m_LimitHost.c_str(), (int)m_LimitPort, host.c_str(), (int)port);
        return;
    }

    uint16_t rsv = CommUtils::read16(data.c_str());
    if (rsv)
    {
        ERROR_LOG("UDP Socket %llu : first 2 bytes is not 0x0000 but 0x%04X, packet ignored", m_ID, rsv);
        return;
    }

    char frag = data[2];
    if (frag)
    {
        ERROR_LOG("UDP Socket %llu does not support frag=%d, packet ignored", m_ID, (int)frag);
        return;
    }

    char addr_type = data[3];
    if (addr_type != 1 && addr_type != 3 && addr_type != 4)
    {
        ERROR_LOG("UDP Socket %llu does not support addr_type=%d, packet ignored", m_ID, (int)addr_type);
        return;
    }

    //获取UDP包的发送目标/来源
    std::string dest_host;
    uint16_t dest_port = 0;
    size_t head_len = 0;

    if (addr_type == 1) //IPv4 in binary
    {
        head_len = 10;
        if (data.size() <= head_len)
        {
            ERROR_LOG("UDP Socket %llu got a empty/incomplete packet. ignored.", m_ID);
            return;
        }

        dest_port = CommUtils::read16(data.c_str() + 8);
        const uint8_t* p = (const uint8_t*)(data.c_str() + 4);
        char addr_buf[16];
        snprintf(addr_buf, 16, "%d.%d.%d.%d", (int)(p[0]), (int)(p[1]), (int)(p[2]), (int)(p[3]));
        dest_host = addr_buf;
    }
    else if (addr_type == 3) //Domain name
    {
        size_t addr_len = *(uint8_t*)(data.c_str() + 4);
        head_len = 7 + addr_len;
        if (data.size() <= head_len)
        {
            ERROR_LOG("UDP Socket %llu got a empty/incomplete packet. ignored.", m_ID);
            return;
        }

        dest_host.assign(data.c_str() + 5, addr_len);
        dest_port = CommUtils::read16(data.c_str() + 5 + addr_len);
    }
    else if (addr_type == 4) //IPv6 in binary
    {
        head_len = 22;
        if (data.size() <= head_len)
        {
            ERROR_LOG("UDP Socket %llu got a empty/incomplete packet. ignored.", m_ID);
            return;
        }

        dest_port = CommUtils::read16(data.c_str() + 20);
        const uint8_t* p = (const uint8_t*)(data.c_str() + 4);
        char addr_buf[64];
        snprintf(addr_buf, 64, "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
            (uint32_t)(p[0]), (uint32_t)(p[1]), (uint32_t)(p[2]), (uint32_t)(p[3]),
            (uint32_t)(p[4]), (uint32_t)(p[5]), (uint32_t)(p[6]), (uint32_t)(p[7]),
            (uint32_t)(p[8]), (uint32_t)(p[9]), (uint32_t)(p[10]), (uint32_t)(p[11]),
            (uint32_t)(p[12]), (uint32_t)(p[13]), (uint32_t)(p[14]), (uint32_t)(p[15]));
        dest_host = addr_buf;
    }

    if (dest_host.size() > 255)
    {
        ERROR_LOG("UDP Socket %llu does not support dest_host longer than 255 bytes, packet ignored", m_ID);
        return;
    }

    //重新封装成隧道内格式
    uint16_t data_len = (uint16_t)(data.size() - head_len);

    uint8_t b1 = (uint8_t)(dest_host.size());
    uint8_t b2[4];
    CommUtils::write16(b2, dest_port);
    CommUtils::write16(b2 + 2, data_len);

    m_CBRead(std::string((char*)&b1, 1) + dest_host + std::string((char*)b2, 4) + data.substr(head_len, data_len));
}

}

}