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

#pragma once

#include <set>
#include "Socket.h"
#include "Config.h"

namespace NoirSocks
{

class Service
{
public:
    Service(const LocalService& conf, boost::asio::io_service& service)
        : m_Conf(conf), m_Acceptor(service, {boost::asio::ip::address::from_string(conf.host), conf.port})
        , m_IncomingSocket(service), m_IoService(service)
    {}
    int Run();

    void AddSocket(SocketPtr ptr);
    void DropSocket(SocketPtr ptr);

    const Route& GetRouteByHost(const std::string target_host);

private:
    void DoAccept();

private:
    std::set<SocketPtr> m_Sockets;
    const LocalService& m_Conf;
    boost::asio::ip::tcp::acceptor m_Acceptor;
    boost::asio::ip::tcp::socket m_IncomingSocket;
    boost::asio::io_service& m_IoService;

private:
    Service(const Service& svc)
        : m_Conf(svc.m_Conf), m_Acceptor(svc.m_IoService, {boost::asio::ip::address::from_string(svc.m_Conf.host), svc.m_Conf.port})
        , m_IncomingSocket(svc.m_IoService), m_IoService(svc.m_IoService)
    {}
};

typedef std::shared_ptr<Service> ServicePtr;

};
