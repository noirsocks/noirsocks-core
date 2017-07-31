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

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <cstdio>
#include "Logger.h"
#include "CommUtils.h"

#include "Socks5Server.h"
#include "UDP_Prefix.h"

#include <boost/asio.hpp>

namespace NoirSocks
{

namespace Protocol
{

void Socks5Server::FeedReadData(std::string data)
{
    if (m_Stage == 1)
    {
        m_ReadBuf += data;
        ReadData_Stage1();
        return;
    }
    if (m_Stage == 2)
    {
        m_ReadBuf += data;
        ReadData_Stage2();
        return;
    }
    if (!m_UdpWrite) m_CBRead(std::move(data));
}

void Socks5Server::FeedWriteData(std::string data)
{
    if (!m_UdpWrite)
    {
        m_CBWrite(std::move(data));
        return;
    }

    //UDP模式写回调
    if (!m_CBUdpWrite)
    {
        SetUdpWriteCallback(m_Father->GetUdpWriteCallback());
    }
    if (!m_CBUdpWrite)
    {
        throw ProtocolError(-5005, "UDP write callback not set");
    }

    m_WriteBuf += data;

    //UDP packet in tunnel : [1 Byte addr_len] [addr] [2 Bytes port] [2 Bytes data_len] [data]

    uint8_t* p = (uint8_t*)(m_WriteBuf.c_str());
    uint8_t addr_len = p[0];

    if (m_WriteBuf.size() < (5 + addr_len)) return;

    uint16_t data_len = CommUtils::read16(m_WriteBuf.c_str() + addr_len + 3);
    if (m_WriteBuf.size() < (5 + addr_len + data_len)) return;

    std::string addr(m_WriteBuf.c_str() + 1, (size_t)addr_len);
    uint16_t port = CommUtils::read16(m_WriteBuf.c_str() + addr_len + 1);
    std::string packet(m_WriteBuf.c_str() + 5 + addr_len, (size_t)data_len);

    DEBUG_LOG("Socket %llu got a %u bytes packet from [%s:%d]", m_ID, (uint32_t)(packet.size()), addr.c_str(), (int)port);

    m_WriteBuf = m_WriteBuf.substr(5 + addr_len + data_len);

    //to client packet format : 0 0 0 [addr_type] [addr] [port] data
    m_CBUdpWrite(GenSocks5RspHead(addr, port, 0) + packet, m_RemoteHost, m_ConnPort);
}

void Socks5Server::FeedConnRsp(int result, const std::string& host, uint16_t port)
{
    if (result)
    {
        char rsp[10] = {5, 1, 0, 1, 0, 0, 0, 0, 0, 0};
        m_CBWrite(std::string(rsp, 10));
        return;
    }

    if (!m_UdpWrite)
    {
        m_CBWrite(GenSocks5RspHead(host, port, 5));
        return;
    }

    m_UdpBindPort = m_Father->GetConf().socks_udp_bind_port;
    if (m_UdpBindPort == 0)
    {
        m_UdpBindPort = m_LocalPort;
    }
    m_UdpBindPort += CommUtils::Rand(1, 91);

    DEBUG_LOG("Socket %llu try to create udp socket. host=%s base_port=%d", m_LocalHost.c_str(), (int)m_UdpBindPort);

    m_UdpBindPort = m_CBCreateUdp(m_LocalHost, m_UdpBindPort, std::make_shared<UDP_Prefix>(true, m_RemoteHost, m_ConnPort));

    if (m_UdpBindPort == 0) //UDP socket创建失败
    {
        throw ProtocolError(-5004, "Socket UDP bind failed");
    }

    m_CBWrite(GenSocks5RspHead(m_LocalHost, m_UdpBindPort, 5));
}

void Socks5Server::ReadData_Stage1()
{
    if (m_ReadBuf.size() < 2) return;
    if (m_ReadBuf.size() < (size_t)(2 + m_ReadBuf[1])) return;
    bool found = false;
    for (size_t idx = 2; idx < (size_t)(2 + m_ReadBuf[1]); ++idx)
    {
        if (m_ReadBuf[idx] == 0)
        {
            found = true;
            break;
        }
    }
    if (!found)
    {
        throw ProtocolError(-5001, "No supported auth methods");
    }
    m_Stage = 2;
    m_ReadBuf = m_ReadBuf.substr((size_t)(2 + m_ReadBuf[1]));
    char rsp[2] = {5, 0};
    m_CBWrite(std::string(rsp, 2));
}

void Socks5Server::ReadData_Stage2()
{
    if (m_ReadBuf.size() < 5) return;
    if (m_ReadBuf[1] < 1 && m_ReadBuf[1] > 3)
    {
        std::string rsp((size_t)10, (char)0);
        rsp[0] = 5; rsp[1] = 7; rsp[3] = 1;
        m_CBWrite(std::move(rsp));
        throw ProtocolError(5002, "Invalid request type: " + CommUtils::tostr<int>(m_ReadBuf[1]));
    }

    int addr_type = m_ReadBuf[3];
    size_t stage_2_len = 0;
    char addr_buf[64];

    if (addr_type == 1) //IPv4 in binary
    {
        stage_2_len = 10;
        if (m_ReadBuf.size() < stage_2_len) return;

        m_ConnPort = CommUtils::read16(m_ReadBuf.c_str() + 8);
        const uint8_t* p = (const uint8_t*)(m_ReadBuf.c_str() + 4);
        snprintf(addr_buf, 16, "%d.%d.%d.%d", (int)(p[0]), (int)(p[1]), (int)(p[2]), (int)(p[3]));
        m_ConnAddr = addr_buf;
    }
    else if (addr_type == 3) //Domain name
    {
        size_t addr_len = *(uint8_t*)(m_ReadBuf.c_str() + 4);
        stage_2_len = addr_len + 7;
        if (m_ReadBuf.size() < stage_2_len) return;
        m_ConnAddr.assign(m_ReadBuf.c_str() + 5, addr_len);
        m_ConnPort = CommUtils::read16(m_ReadBuf.c_str() + 5 + addr_len);
    }
    else if (addr_type == 4) //IPv6 in binary
    {
        stage_2_len = 22;
        if (m_ReadBuf.size() < stage_2_len) return;

        m_ConnPort = CommUtils::read16(m_ReadBuf.c_str() + 20);
        const uint8_t* p = (const uint8_t*)(m_ReadBuf.c_str() + 4);
        snprintf(addr_buf, 64, "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
            (uint32_t)(p[0]), (uint32_t)(p[1]), (uint32_t)(p[2]), (uint32_t)(p[3]),
            (uint32_t)(p[4]), (uint32_t)(p[5]), (uint32_t)(p[6]), (uint32_t)(p[7]),
            (uint32_t)(p[8]), (uint32_t)(p[9]), (uint32_t)(p[10]), (uint32_t)(p[11]),
            (uint32_t)(p[12]), (uint32_t)(p[13]), (uint32_t)(p[14]), (uint32_t)(p[15]));
        m_ConnAddr = addr_buf;
    }
    else
    {
        throw ProtocolError(-5003, "Invalid addr_type: " + CommUtils::tostr<int>(addr_type));
    }

    m_ConnType = m_ReadBuf[1];
    m_Stage = 3;
    m_UdpWrite = (m_ConnType == CONN_TYPE_UDP_ASSOCIATE);

    DEBUG_LOG("Socket %llu socks5 server get a request. ip=%s port=%d conn_type=%d", m_ID, m_ConnAddr.c_str(), int(m_ConnPort), m_ConnType);

    if (m_UdpWrite)
    {
        m_ReadBuf.clear();
    }
    else
    {
        m_ReadBuf = m_ReadBuf.substr(stage_2_len);
    }

    if (m_CBConnReq(std::move(m_ConnAddr), m_UdpWrite ? 0 : m_ConnPort, m_ConnType))
    {
        throw ProtocolError(5003, "Socket handle conn_req failed.");
    }

    if (m_ReadBuf.size())
    {
        m_CBRead(std::move(m_ReadBuf));
    }
}

std::string Socks5Server::GenSocks5RspHead(const std::string& host, uint16_t port, uint8_t first_byte)
{
    std::string ret;
    auto addr_obj = boost::asio::ip::address::from_string(host);
    if (addr_obj.is_v4())
    {
        auto binary_addr = addr_obj.to_v4().to_bytes();
        uint8_t rsp[10] = {first_byte, 0, 0, 1, 0, 0, 0, 0, 0, 0};

        rsp[4] = binary_addr[0];
        rsp[5] = binary_addr[1];
        rsp[6] = binary_addr[2];
        rsp[7] = binary_addr[3];

        CommUtils::write16(rsp + 8, port);

        ret.assign((char*)rsp, 10);
    }
    else if (addr_obj.is_v6())
    {
        auto binary_addr = addr_obj.to_v6().to_bytes();
        uint8_t rsp[22] = {0}; rsp[0] = first_byte; rsp[3] = 4;

        rsp[4]  = binary_addr[0];   rsp[5] = binary_addr[1];   rsp[6] = binary_addr[2];   rsp[7] = binary_addr[3];
        rsp[8]  = binary_addr[4];   rsp[9] = binary_addr[5];  rsp[10] = binary_addr[6];  rsp[11] = binary_addr[7];
        rsp[12] = binary_addr[8];  rsp[13] = binary_addr[9];  rsp[14] = binary_addr[10]; rsp[15] = binary_addr[11];
        rsp[16] = binary_addr[12]; rsp[17] = binary_addr[13]; rsp[18] = binary_addr[14]; rsp[19] = binary_addr[15];
        CommUtils::write16(rsp + 20, port);

        ret.assign((char*)rsp, 22);
    }
    else
    {
        uint8_t rsp[5] = {first_byte, 0, 0, 3, (uint8_t)(host.size() & 0xFF)};
        char ps[2];
        CommUtils::write16(ps, port);

        ret.assign((char*)rsp, 5);
        ret += host;
        ret.append(ps, 2);
    }
    return std::move(ret);
}

};

};
