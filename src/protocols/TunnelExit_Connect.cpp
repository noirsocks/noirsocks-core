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

#include "TunnelExit_Connect.h"

namespace NoirSocks
{

namespace Protocol
{

void TunnelExit_Connect::FeedReadData(std::string data)
{
    if (!m_ConnRspSent)
    {
        m_Buf += std::move(data);
        return;
    }
    m_CBRead(std::move(data));
}

void TunnelExit_Connect::FeedWriteData(std::string data)
{
    m_CBWrite(std::move(data));
}

void TunnelExit_Connect::FeedConnReq(const std::string& host, uint16_t port, int conn_type)
{
    std::string rsp_host = m_LocalHost;
    m_CBConnRsp(0, std::move(rsp_host), m_LocalPort);
    m_ConnRspSent = true;
    m_CBRead(std::move(m_Buf));
}

};

};
