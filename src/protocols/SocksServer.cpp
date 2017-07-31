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

#include "SocksServer.h"
#include "Socks4Server.h"
#include "Socks5Server.h"

namespace NoirSocks
{

namespace Protocol
{

bool SocksServer::CheckProtocolConf(const LocalService& service, std::string& err_msg)
{
    if (service.host.empty())
    {
        err_msg = "host not configured";
        return false;
    }
    if (service.port == 0)
    {
        err_msg = "port not configured";
        return false;
    }
    return true;
}

ProtocolPtr SocksServer::CreateProtocol(const LocalService& service)
{
    return std::make_shared<SocksServer>(service);
}

void SocksServer::FeedReadData(std::string data)
{
    if (data.empty()) return;
    if (!m_Imp)
    {
        char version = data[0];
        if (version == 4)
        {
            INFO_LOG("Socket %llu running at socks4 server mode", m_ID);
            m_Imp = std::make_shared<Socks4Server>();
        }
        else if (version == 5)
        {
            INFO_LOG("Socket %llu running at socks5 server mode", m_ID);
            m_Imp = std::make_shared<Socks5Server>(this);
        }
        else
        {
            throw ProtocolError(-1001, "invalid protocol version: " + CommUtils::tostr((int)version));
        }
        Inherit();
    }
    m_Imp->FeedReadData(std::move(data));
}

void SocksServer::FeedWriteData(std::string data)
{
    if (!m_Imp)
    {
        ERROR_LOG("Socket %llu socks server protocol not initialized", m_ID);
        return;
    }
    m_Imp->FeedWriteData(std::move(data));
}

void SocksServer::FeedConnRsp(int result, const std::string& host, uint16_t port)
{
    if (!m_Imp)
    {
        ERROR_LOG("Socket %llu socks server protocol not initialized", m_ID);
        return;
    }
    m_Imp->FeedConnRsp(result, host, port);
}

void SocksServer::Inherit()
{
    m_Imp->SetID(m_ID);
    m_Imp->SetLocalAddr(m_LocalHost, m_LocalPort);
    m_Imp->SetRemoteAddr(m_RemoteHost, m_RemotePort);

    m_Imp->SetReadCallback(m_CBRead);
    m_Imp->SetWriteCallback(m_CBWrite);
    m_Imp->SetCreateUdpCallback(m_CBCreateUdp);
    m_Imp->SetConnReqCallback(m_CBConnReq);
    m_Imp->SetConnRspCallback(m_CBConnRsp);
}

};

};
