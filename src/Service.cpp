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

#include <utility>
#include <functional>
#include "Logger.h"
#include "Service.h"
#include "ProtocolFactory.h"
#include "ServerImp.h"
#include "CommUtils.h"

namespace NoirSocks
{

int Service::Run()
{
    INFO_LOG("Local service %s start running...", m_Conf.name.c_str());
    DoAccept();
    return 0;
}

void Service::AddSocket(SocketPtr ptr)
{
    m_Sockets.insert(ptr);
}

void Service::DropSocket(SocketPtr ptr)
{
    m_Sockets.erase(ptr);
}

const Route& Service::GetRouteByHost(const std::string target_host)
{
    for (auto it = m_Conf.rules.begin(); it != m_Conf.rules.end(); ++it)
    {
        if (CommUtils::PatternMatch(target_host, it->host_pattern))
        {
            return *it;
        }
    }
    if (m_Conf.has_def_route)
    {
        return m_Conf.def_route;
    }
    const GlobalConfig& global_conf = GetServerInstance()->GetConf();
    for (auto it = global_conf.rules.begin(); it != global_conf.rules.end(); ++it)
    {
        if (CommUtils::PatternMatch(target_host, it->host_pattern))
        {
            return *it;
        }
    }
    return global_conf.def_route;
}

void Service::DoAccept()
{
    m_Acceptor.async_accept(m_IncomingSocket, [this](boost::system::error_code ec)
    {
        if (!ec)
        {
            auto remote_endpoint = m_IncomingSocket.remote_endpoint();
            const std::string& remote_host = remote_endpoint.address().to_string();
            uint64_t id_for_socket = GetServerImpInstance()->GetId();
            INFO_LOG("New connetion from %s:%d . local service : %s socket_id : %llu",
                remote_host.c_str(), (int)(remote_endpoint.port()), m_Conf.name.c_str(), id_for_socket);

            if (GetServerImpInstance()->IsRemoteHostBanned(remote_host))
            {
                ERROR_LOG("Remote host %s banned, socket_id : %llu", remote_host.c_str(), id_for_socket);
                boost::asio::ip::tcp::socket tmp_socket = std::move(m_IncomingSocket);
                tmp_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
                DoAccept();
                return;
            }

            ProtocolPtr protocol = CreateProtocol(m_Conf);
            if (protocol == nullptr)
            {
                ERROR_LOG("Local service %s cannot start protocol. shutdown connection. socket_id : %llu",
                    m_Conf.name.c_str(), id_for_socket);
                boost::asio::ip::tcp::socket tmp_socket = std::move(m_IncomingSocket);
                tmp_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
                DoAccept();
                return;
            }

            SocketPtr socket = std::make_shared<Socket>(id_for_socket, m_IoService, std::move(m_IncomingSocket), protocol,
                std::bind(&Service::AddSocket, this, std::placeholders::_1),
                std::bind(&Service::DropSocket, this, std::placeholders::_1),
                std::bind(&Service::GetRouteByHost, this, std::placeholders::_1));

            AddSocket(socket);
            socket->Run();
        }
        DoAccept();
    });
}

};
