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

#include "CommUtils.h"

#include "TunnelExit_UDP.h"
#include "UDP_NoPrefix.h"

namespace NoirSocks
{

namespace Protocol
{

void TunnelExit_UDP::FeedWriteData(std::string data)
{
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

    m_WriteBuf = m_WriteBuf.substr(5 + addr_len + data_len);

    m_CBUdpWrite(std::move(packet), addr, port);
}

void TunnelExit_UDP::FeedConnReq(const std::string& host, uint16_t port, int conn_type)
{
    m_BindPort = m_CBCreateUdp(m_BindHost, m_BindPort, std::make_shared<UDP_NoPrefix>());
    m_CBConnRsp(m_BindPort == 0 ? 233001 : 0, "", 0); //隧道出口的节点在创建UDP Socket失败时使用非0conn_rsp来传出失败
}

};

};
