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

#include <cstdio>
#include "Logger.h"
#include "CommUtils.h"

#include "Socks4Server.h"

namespace NoirSocks
{

namespace Protocol
{

void Socks4Server::FeedReadData(std::string data)
{
    if (!m_ConnReqGot)
    {
        m_Buf += data;
        if (TryGenerateConnReq())
        {
            m_CBRead(std::move(m_Buf));
        }
        else if (m_Buf.size() > BUF_CAPA)
        {
            throw ProtocolError(-4001, "Socks 4 handshake too big");
        }
    }
    else
    {
        m_CBRead(std::move(data));
    }
}

void Socks4Server::FeedWriteData(std::string data)
{
    m_CBWrite(std::move(data));
}

void Socks4Server::FeedConnRsp(int result, const std::string& host, uint16_t port)
{
    std::string rsp((size_t)8, (char)0);
    if (result == 0) rsp[1] = 0x5A;
    else rsp[1] = 0x5B;
    m_CBWrite(std::move(rsp));
}

bool Socks4Server::TryGenerateConnReq()
{
    if (m_Buf.size() < 8) return false;
    if (m_Buf[1] != 1) //socks4只支持connect请求
    {
        std::string rsp((size_t)8, (char)0);
        rsp[1] = 0x5B;
        m_CBWrite(std::move(rsp));
        throw ProtocolError(4101, "Socks4 server only supports CONNECT requests");
    }

    uint16_t port = CommUtils::read16(m_Buf.c_str() + 2);
    uint32_t ip = CommUtils::read32(m_Buf.c_str() + 4);
    bool is_socks4a = (ip < 0x100);

    DEBUG_LOG("Socket %llu socks4 server get connect request. ip=%08x port=%d is_socks4a=%d", m_ID, ip, int(port), (int)is_socks4a);

    if (port == 0)
    {
        throw ProtocolError(-4002, "port cannot be 0");
    }

    //跳过用户ID
    auto it = m_Buf.begin() + 8;
    for (; it != m_Buf.end(); ++it)
    {
        if (*it == 0)
        {
            break;
        }
    }
    if (it == m_Buf.end()) //用户ID未结束
    {
        return false;
    }

    if (!is_socks4a)
    {
        std::string tmp(++it, m_Buf.end());
        m_Buf = std::move(tmp);

        char ip_str[16] = {0};
        const uint8_t* ip = (const uint8_t*)(m_Buf.c_str() + 4);
        snprintf(ip_str, 16, "%d.%d.%d.%d", (int)(ip[0]), (int)(ip[1]), (int)(ip[2]), (int)(ip[3]));
        if (m_CBConnReq(ip_str, port, CONN_TYPE_CONNECT))
        {
            throw ProtocolError(4003, "Socket handle conn_req failed.");
        }
        m_ConnReqGot = true;

        return true;
    }

    //尝试取出host_name
    auto it_host_name_start = ++it;
    for (; it != m_Buf.end(); ++it)
    {
        if (*it == 0)
        {
            break;
        }
    }
    if (it == m_Buf.end()) //host_name未结束
    {
        return false;
    }

    std::string host(it_host_name_start, it);
    std::string tmp(++it, m_Buf.end());
    m_Buf = std::move(tmp);
    if (m_CBConnReq(std::move(host), port, CONN_TYPE_CONNECT))
    {
        throw ProtocolError(4003, "Socket handle conn_req failed.");
    }
    m_ConnReqGot = true;

    return true;
}

};

};
