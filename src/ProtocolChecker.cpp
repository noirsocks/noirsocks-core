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
#include "ProtocolChecker.h"

#include "protocols/SocksServer.h"
#include "protocols/DynecTunnelClient.h"
#include "protocols/DynecTunnelServer.h"
#include "protocols/HttpProxyServer.h"

namespace NoirSocks
{

typedef std::function<bool(const NextNode&, std::string&)> ProtocolChecker_Node;
typedef std::function<bool(const LocalService&, std::string&)> ProtocolChecker_Svc;

bool CheckProtocolConf(const NextNode& node, std::string& err_msg)
{
    static bool init = false;
    static std::map<std::string, ProtocolChecker_Node> func_map;
    if (!init)
    {
        init = true;
        func_map["dynec_tunnel"] = Protocol::DynecTunnelClient::CheckProtocolConf;
    }

    if (func_map.find(node.protocol) != func_map.end())
    {
        return func_map[node.protocol](node, std::ref(err_msg));
    }

    err_msg = "unkwown protocol : " + node.protocol;
    return false;
}

bool CheckProtocolConf(const LocalService& service, std::string& err_msg)
{
    static bool init = false;
    static std::map<std::string, ProtocolChecker_Svc> func_map;
    if (!init)
    {
        init = true;
        func_map["socks"] = Protocol::SocksServer::CheckProtocolConf;
        func_map["dynec_tunnel"] = Protocol::DynecTunnelServer::CheckProtocolConf;
        func_map["http"] = Protocol::HttpProxyServer::CheckProtocolConf;
    }

    if (func_map.find(service.protocol) != func_map.end())
    {
        return func_map[service.protocol](service, std::ref(err_msg));
    }

    err_msg = "unkwown protocol : " + service.protocol;
    return false;
}

};
