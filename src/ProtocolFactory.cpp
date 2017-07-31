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

#include <map>
#include "ProtocolFactory.h"
#include "Logger.h"

#include "protocols/SocksServer.h"
#include "protocols/TunnelExit_Connect.h"
#include "protocols/TunnelExit_Bind.h"
#include "protocols/TunnelExit_UDP.h"
#include "protocols/DynecTunnelClient.h"
#include "protocols/DynecTunnelServer.h"
#include "protocols/HttpProxyServer.h"

namespace NoirSocks
{

typedef std::function<ProtocolPtr(const NextNode&)> ProtocolCreator_Node;
typedef std::function<ProtocolPtr(const LocalService&)> ProtocolCreator_Svc;

ProtocolPtr CreateProtocol(const NextNode& node)
{
    static bool init = false;
    static std::map<std::string, ProtocolCreator_Node> func_map;
    if (!init)
    {
        init = true;
        func_map["dynec_tunnel"] = Protocol::DynecTunnelClient::CreateProtocol;
    }

    if (func_map.find(node.protocol) != func_map.end())
    {
        return func_map[node.protocol](node);
    }

    ERROR_LOG("CreateProtocol by node failed. unknown protocol: %s", node.protocol.c_str());
    return nullptr;
}

ProtocolPtr CreateProtocol(const LocalService& service)
{
    static bool init = false;
    static std::map<std::string, ProtocolCreator_Svc> func_map;
    if (!init)
    {
        init = true;
        func_map["socks"] = Protocol::SocksServer::CreateProtocol;
        func_map["dynec_tunnel"] = Protocol::DynecTunnelServer::CreateProtocol;
        func_map["http"] = Protocol::HttpProxyServer::CreateProtocol;
    }

    if (func_map.find(service.protocol) != func_map.end())
    {
        return func_map[service.protocol](service);
    }

    ERROR_LOG("CreateProtocol by service failed. unknown protocol: %s", service.protocol.c_str());
    return nullptr;
}

ProtocolPtr CreateTunnelExitProtocol(const std::string& bind_host, uint16_t bind_port, int conn_type)
{
    if (conn_type == CONN_TYPE_CONNECT) return std::make_shared<Protocol::TunnelExit_Connect>();
    if (conn_type == CONN_TYPE_TCP_BIND) return std::make_shared<Protocol::TunnelExit_Bind>();
    if (conn_type == CONN_TYPE_UDP_ASSOCIATE) return std::make_shared<Protocol::TunnelExit_UDP>(bind_host, bind_port);
    return nullptr;
}

};
