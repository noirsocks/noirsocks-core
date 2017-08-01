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

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <memory>
#include <utility>
#include <list>
#include <string>
#include <functional>
#include <stdint.h>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include "ProtocolBase.h"
#include "Config.h"

namespace NoirSocks
{

class Socket;
class SocketUdp;

typedef std::shared_ptr<Socket> SocketPtr;
typedef std::function<void(SocketPtr)> SocketMngFunc;
typedef std::function<const Route&(const std::string&)> RouteFunc;

class Socket : public std::enable_shared_from_this<Socket>
{
public:
    Socket(uint64_t id, boost::asio::io_service& service,
            boost::asio::ip::tcp::socket socket, ProtocolPtr protocol,
            SocketMngFunc add_func, SocketMngFunc drop_func, RouteFunc route_func)
        : m_ID(id), m_IoService(service), m_Socket(std::move(socket)), m_ConnTemp(service)
        , m_CloseWhenWriteDone(false), m_Dns(service), m_Protocol(protocol)
        , m_AddFunc(add_func), m_DropFunc(drop_func), m_RouteFunc(route_func)
    {}
    virtual ~Socket(){}

    virtual void Run();
    virtual void Stop();
    void PostStop();

    void PostConnReq(const std::string& host, uint16_t port, int conn_type);
    void PostConnRsp(int result, const std::string& host, uint16_t port);
    void PostPackage(std::string data);

    void SelfConnRsp(int result, const std::string& host, uint16_t port);

    void InheritPairSocket(SocketPtr ptr);

protected:
    void BindProtocolCallbacks();
    void OnDataArrival(std::string&& data);
    void OnDataWrite(std::string&& data);
    int OnConnReqGot(std::string&& host, uint16_t port, int conn_type);
    int OnConnRspGot(int result, std::string&& host, uint16_t port);
    uint16_t OnCreateUdp(const std::string& host, uint16_t base_port, ProtocolPtr protocol);
    void OnSetTimer(uint64_t milli_secs, std::string&& msg);
    void OnCancelTimer();

protected:
    void DoAsyncRead();
    void DoAsyncWrite();
    void EndSession();
    void SetCloseWhenDone(bool value);
    void PostCloseWhenDone(bool value);
    void OnFatalError(boost::system::error_code ec);
    void OnFatalError(const ProtocolError& ec);
    void RepackWriteQueue();

protected:
    int CreatePairSocket(const std::string& bind_host, uint16_t bind_port, int conn_type, const std::string& remote_host, uint16_t remote_port);
    void CreatePairSocket(boost::asio::ip::tcp::resolver::iterator target);
    void CreatePairSocket(ProtocolPtr protocol, boost::asio::ip::tcp::resolver::iterator target, const std::string& remote_host, uint16_t remote_port, int conn_type);
    void SetPairSocket(SocketPtr pair, const std::string& remote_host, uint16_t remote_port, int conn_type);

protected:
    uint64_t m_ID;
    boost::asio::io_service& m_IoService;
    boost::asio::ip::tcp::socket m_Socket;
    boost::asio::ip::tcp::socket m_ConnTemp;

    bool m_CloseWhenWriteDone;

    boost::asio::ip::tcp::resolver m_Dns;

    std::weak_ptr<Socket> m_PairSocket;
    std::list<std::string> m_WriteQueue; //准备发送的协议数据流
    std::list<std::string> m_ReadQueue; //暂时缓存的原始数据流

    ProtocolPtr m_Protocol; //这个socket运行的协议
    SocketMngFunc m_AddFunc;
    SocketMngFunc m_DropFunc;
    RouteFunc m_RouteFunc;

    std::shared_ptr<SocketUdp> m_SubUdpSocket;

    std::shared_ptr<boost::asio::deadline_timer> m_Timer;

    enum {BUFFER_SIZE = 1<<14};
    char m_Buffer[BUFFER_SIZE];

    uint8_t m_RepackFlag;
};

class SocketListen : public Socket
{
public:
    SocketListen(uint64_t id, boost::asio::io_service& service,
            boost::asio::ip::tcp::socket socket, ProtocolPtr protocol,
            SocketMngFunc add_func, SocketMngFunc drop_func, RouteFunc route_func,
            std::string bind_host, uint16_t bind_port)
        : Socket(id, service, std::move(socket), protocol, add_func, drop_func, route_func)
        , m_BindHost(std::move(bind_host)), m_BindPort(bind_port), m_IncomingSocket(service)
    {}

    virtual void Run();
    virtual void Stop();

private:
    std::string m_BindHost;
    uint16_t m_BindPort;
    boost::asio::ip::tcp::socket m_IncomingSocket;
    std::shared_ptr<boost::asio::ip::tcp::acceptor> m_AcceptorPtr;
};

class SocketUdp : public std::enable_shared_from_this<SocketUdp>
{
    friend class Socket;
public:
    SocketUdp(boost::asio::io_service& service, boost::asio::ip::udp::socket socket, ProtocolPtr protocol)
        : m_Socket(std::move(socket)), m_Protocol(protocol)
    {}

    void Run();
    void Stop();

private:
    void OnDataArrival(std::string&& data);
    void OnUdpWrite(std::string&& data, const std::string& host, uint16_t port);

    void DoUdpAsyncRead();
    void DoUdpAsyncWrite();

private:
    boost::asio::ip::udp::socket m_Socket;
    boost::asio::ip::udp::endpoint m_RemoteEP;
    ProtocolPtr m_Protocol; //这个socket运行的协议
    std::weak_ptr<Socket> m_PairSocket;

    enum {BUFFER_SIZE = ((1<<16) + (1<<10))};
    char m_Buffer[BUFFER_SIZE];

    int64_t m_ID;

    struct UdpPacket
    {
        std::string data;
        std::string host;
        uint16_t port;

        UdpPacket(UdpPacket&& rhs) : data(std::move(rhs.data)), host(std::move(rhs.host)), port(rhs.port) {}
        UdpPacket(std::string&& data_, const std::string& host_, uint16_t port_) : data(std::move(data_)), host(host_), port(port_) {}
    };
    std::list<UdpPacket> m_WriteQueue;
};

};
