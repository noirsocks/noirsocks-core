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

#include "Socket.h"
#include "ServerImp.h"
#include "Logger.h"
#include "ErrorCodes.h"
#include "CommUtils.h"
#include "ProtocolFactory.h"

namespace NoirSocks
{

void Socket::Run()
{
    BindProtocolCallbacks();
    m_Protocol->SetLocalAddr(m_Socket.local_endpoint().address().to_string(), m_Socket.local_endpoint().port());
    m_Protocol->SetRemoteAddr(m_Socket.remote_endpoint().address().to_string(), m_Socket.remote_endpoint().port());
    m_RepackFlag = 0;
    INFO_LOG("Socket %llu start...", m_ID);
    DoAsyncRead();
}

void Socket::Stop()
{
    INFO_LOG("Socket %llu stop...", m_ID);
    auto self(shared_from_this());
    OnCancelTimer();
    try
    {
        m_Socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
    }
    catch (...) {}
    try
    {
        m_ConnTemp.cancel();
    }
    catch (...) {}
    if (m_SubUdpSocket)
    {
        m_SubUdpSocket->Stop();
    }
    m_DropFunc(self);
}

void Socket::PostStop()
{
    auto self(shared_from_this());
    m_IoService.post([self](){self->Stop();});
}

void Socket::PostConnReq(const std::string& host, uint16_t port, int conn_type)
{
    auto self(shared_from_this());
    std::shared_ptr<std::string> ptr_host = std::make_shared<std::string>(host);
    m_IoService.post([this, self, ptr_host, port, conn_type]()
        {
            self->m_Protocol->FeedConnReq(*ptr_host, port, conn_type);
        });
}

void Socket::PostConnRsp(int result, const std::string& host, uint16_t port)
{
    auto self(shared_from_this());
    std::shared_ptr<std::string> ptr_host = std::make_shared<std::string>(host);
    m_IoService.post([this, self, ptr_host, port, result]()
        {
            INFO_LOG("Socket %llu connection result : ret=%d host=%s port=%d", m_ID, result, ptr_host->c_str(), (int)port);
            try
            {
                self->m_Protocol->FeedConnRsp(result, *ptr_host, port);
            }
            catch (ProtocolError& err)
            {
                ERROR_LOG("Socket %llu Protocol error : error_code=%d err_msg=%s", m_ID, err.error_code, err.error_msg.c_str());
                if (err.error_code > 0) EndSession();
                else OnFatalError(err);
            }
        });
}

void Socket::PostPackage(std::string data)
{
    auto self(shared_from_this());
    std::shared_ptr<std::string> ptr_data = std::make_shared<std::string>(std::move(data));
    m_IoService.post([this, self, ptr_data]()
        {
            self->m_Protocol->FeedWriteData(std::move(*ptr_data));
        });
}

void Socket::InheritPairSocket(SocketPtr pair)
{
    auto self(shared_from_this());
    pair->m_PairSocket = self;
    m_PairSocket = pair;
}

void Socket::SelfConnRsp(int result, const std::string& host, uint16_t port)
{
    INFO_LOG("Socket %llu connection result : ret=%d host=%s port=%d", m_ID, result, host.c_str(), (int)port);
    try
    {
        m_Protocol->FeedConnRsp(result, host, port);
    }
    catch (ProtocolError& err)
    {
        ERROR_LOG("Socket %llu Protocol error : error_code=%d err_msg=%s", m_ID, err.error_code, err.error_msg.c_str());
        if (err.error_code > 0) EndSession();
        else OnFatalError(err);
    }
}

void Socket::BindProtocolCallbacks()
{
    using namespace std::placeholders;
    m_Protocol->SetReadCallback(std::bind(&Socket::OnDataArrival, this, _1));
    m_Protocol->SetWriteCallback(std::bind(&Socket::OnDataWrite, this, _1));
    m_Protocol->SetCreateUdpCallback(std::bind(&Socket::OnCreateUdp, this, _1, _2, _3));
    m_Protocol->SetConnReqCallback(std::bind(&Socket::OnConnReqGot, this, _1, _2, _3));
    m_Protocol->SetConnRspCallback(std::bind(&Socket::OnConnRspGot, this, _1, _2, _3));
    m_Protocol->SetTimerCallback(std::bind(&Socket::OnSetTimer, this, _1, _2));
    m_Protocol->SetTimerCancleCallback(std::bind(&Socket::OnCancelTimer, this));
    m_Protocol->SetID(m_ID);
}

void Socket::OnDataArrival(std::string&& data)
{
    if (data.empty()) return;
    if (auto pair = m_PairSocket.lock())
    {
        pair->PostPackage(std::move(data));
    }
    else
    {
        m_ReadQueue.push_back(std::move(data));
    }
}

void Socket::OnDataWrite(std::string&& data)
{
    if (data.empty()) return;
    bool writing = !(m_WriteQueue.empty()); //当前发送队列非空表示还有正在发送的数据
    m_WriteQueue.push_back(std::move(data));
    if (!writing) DoAsyncWrite();
}

int Socket::OnConnReqGot(std::string&& host, uint16_t port, int conn_type)
{
    std::string host_str = std::move(host);

    INFO_LOG("Socket %llu got a connect request to %s:%d with conn_type=%d", m_ID, host_str.c_str(), (int)port, conn_type);

    if (conn_type != CONN_TYPE_CONNECT && conn_type != CONN_TYPE_TCP_BIND && conn_type != CONN_TYPE_UDP_ASSOCIATE)
    {
        ERROR_LOG("Socket %llu got a invalid conn_type %d", m_ID, conn_type);
        SelfConnRsp(EC_CONN_TYPE_INVALID, "", 0);
        SetCloseWhenDone(true);
        return 1000;
    }

    //先根据目标主机名获取路由
    const Route& route = m_RouteFunc(std::cref(host_str));

    DEBUG_LOG("Socket %llu route to %s:%d result: is_tunnel_exit=%d bind_addr=%s bind_port=%d next_nodes=%s",
        m_ID, host_str.c_str(), (int)port, (int)(route.is_tunnel_exit), route.bind_addr.c_str(), (int)(route.bind_port),
        CommUtils::tostr(route.next_nodes.begin(), route.next_nodes.end()).c_str());

    if (route.is_tunnel_exit)
    {
        bool only_support_connect = (route.bind_addr.empty() || route.bind_port == 0);
        if (only_support_connect && conn_type != CONN_TYPE_CONNECT)
        {
            ERROR_LOG("Socket %llu do not support conn_type=%d request, because bind_addr or bind_port not configured", m_ID, conn_type);
            SelfConnRsp(EC_CONN_TYPE_NOT_SUPPORTED, "", 0);
            SetCloseWhenDone(true);
            return 1011;
        }

        if (conn_type == CONN_TYPE_TCP_BIND || conn_type == CONN_TYPE_UDP_ASSOCIATE)
        {
            return CreatePairSocket(route.bind_addr, route.bind_port, conn_type, host_str, port);
        }

        //CONNECT
        auto self(shared_from_this());
        m_Dns.async_resolve({host_str, CommUtils::tostr(port)}, [this, self, host_str, port]
            (boost::system::error_code ec, boost::asio::ip::tcp::resolver::iterator target)
            {
                if (!ec)
                {
                    DEBUG_LOG("Socket %llu dns resolved : [%s:%d] ==> [%s:%d]", m_ID, host_str.c_str(), (int)port,
                        target->endpoint().address().to_string().c_str(), (int)(target->endpoint().port()));
                    self->CreatePairSocket(target);
                }
                else
                {
                    ERROR_LOG("Socket %llu dns resolve [%s:%d] failed. error_code=%d error_msg=%s",
                        m_ID, host_str.c_str(), (int)port, ec.value(), ec.message().c_str());
                    self->SelfConnRsp(EC_DNS_RESOLVE_FAILED, "", 0);
                    SetCloseWhenDone(true);
                }
            });
    }
    else // not tunnel exit
    {
        //随机选择节点
        std::map<std::string, boost::asio::ip::tcp::resolver::iterator> target_map;
        for (auto it = route.next_nodes.begin(); it != route.next_nodes.end(); ++it)
        {
            if (target_map.find(*it) != target_map.end())
            {
                continue;
            }
            boost::asio::ip::tcp::resolver::iterator target;
            if (GetServerImpInstance()->GetNextNodeAddress(*it, target))
            {
                target_map[*it] = target;
            }
        }
        if (target_map.empty())
        {
            ERROR_LOG("Socket %llu have no route available.", m_ID);
            SelfConnRsp(EC_NO_ROUTE_AVAILABLE, "", 0);
            SetCloseWhenDone(true);
            return 1021;
        }

        auto rnd_node = CommUtils::RandomChoice(target_map.begin(), target_map.size());
        DEBUG_LOG("Socket %llu choose [%s] as next node", m_ID, rnd_node->first.c_str());

        //根据节点名称获取配置
        auto node_info = GetServerImpInstance()->GetConf().next_nodes.find(rnd_node->first);
        if (node_info == GetServerImpInstance()->GetConf().next_nodes.end())
        {
            ERROR_LOG("Socket %llu cannot find next node [%s]'s configure.", m_ID, rnd_node->first.c_str());
            SelfConnRsp(EC_NO_ROUTE_AVAILABLE, "", 0);
            SetCloseWhenDone(true);
            return 1022;
        }

        //根据配置创建协议
        ProtocolPtr protocol = CreateProtocol(node_info->second);
        if (protocol == nullptr)
        {
            ERROR_LOG("Socket %llu CreateProtocol failed. node=%s", m_ID, rnd_node->first.c_str());
            SelfConnRsp(EC_CONN_TYPE_NOT_SUPPORTED, "", 0);
            SetCloseWhenDone(true);
            return 1023;
        }

        //创建对端socket
        CreatePairSocket(protocol, rnd_node->second, host_str, port, conn_type);
    }

    return 0;
}

int Socket::OnConnRspGot(int result, std::string&& host, uint16_t port)
{
    if (auto pair = m_PairSocket.lock())
    {
        pair->PostConnRsp(result, std::move(host), port);
        if (result)
        {
            ERROR_LOG("Socket %llu protocol says connection is failed. result=%d", m_ID, result);
            EndSession();
        }
        return 0;
    }
    else
    {
        ERROR_LOG("Socket %llu got a conn_rsp, but pair socket has gone", m_ID);
        Stop();
        return 233;
    }
    return 0;
}

uint16_t Socket::OnCreateUdp(const std::string& host, uint16_t base_port, ProtocolPtr protocol)
{
    //尝试建立udp socket
    auto addr = boost::asio::ip::address::from_string(host);
    std::shared_ptr<boost::asio::ip::udp::socket> tmp_socket;
    int try_count = 10;
    uint16_t base_inc = 10;
    while (try_count--)
    {
        try
        {
            DEBUG_LOG("Socket %llu try to bind UDP at [%s:%d]...", m_ID, host.c_str(), base_port);
            tmp_socket = std::make_shared<boost::asio::ip::udp::socket>(m_IoService, boost::asio::ip::udp::endpoint(addr, base_port));
            DEBUG_LOG("Socket %llu successfully bind UDP at [%s:%d]...", m_ID, host.c_str(), base_port);
            break;
        }
        catch(...)
        {
            base_port += CommUtils::Rand(1, base_inc);
            base_inc *= 2;
            while (base_port < 1024) base_port += CommUtils::Rand(1, base_inc);
            tmp_socket = nullptr;
        }
    }

    if (tmp_socket == nullptr)
    {
        ERROR_LOG("Socket %llu cannot bind UDP", m_ID); //这里的错误回包由协议对象产生
        return 0;
    }

    using namespace std::placeholders;
    m_SubUdpSocket = std::make_shared<SocketUdp>(m_IoService, std::move(*tmp_socket), protocol);
    m_SubUdpSocket->m_PairSocket = m_PairSocket;
    m_Protocol->SetUdpWriteCallback(std::bind(&SocketUdp::OnUdpWrite, m_SubUdpSocket, _1, _2, _3));
    m_SubUdpSocket->Run();

    return base_port;
}

void Socket::OnSetTimer(uint64_t milli_secs, std::string&& msg)
{
    if (m_Timer) OnCancelTimer();
    if (milli_secs == 0) return;

    auto self(shared_from_this());
    std::shared_ptr<std::string> ptr_msg = std::make_shared<std::string>(std::move(msg));
    m_Timer = std::make_shared<boost::asio::deadline_timer>(m_IoService);
    m_Timer->expires_from_now(boost::posix_time::millisec(milli_secs));
    m_Timer->async_wait([self, ptr_msg](const boost::system::error_code& ec)
        {
            if (!ec)
            {
                try
                {
                    self->m_Protocol->OnTimer(std::move(*ptr_msg));
                }
                catch (ProtocolError& err)
                {
                    ERROR_LOG("Socket %llu Protocol error : error_code=%d err_msg=%s", self->m_ID, err.error_code, err.error_msg.c_str());
                    if (err.error_code > 0) self->EndSession();
                    else self->OnFatalError(err);
                }
            }
        });
}

void Socket::OnCancelTimer()
{
    if (m_Timer)
    {
        boost::system::error_code ec;
        m_Timer->cancel(ec);
        if (ec)
        {
            ERROR_LOG("Socket %llu cancel timer failed. ec=%d msg=%s", m_ID, ec.value(), ec.message().c_str());
        }
        m_Timer = nullptr;
    }
}

void Socket::DoAsyncRead()
{
    auto self(shared_from_this());
    m_Socket.async_read_some(boost::asio::buffer(m_Buffer, BUFFER_SIZE),
        [this, self](boost::system::error_code ec, std::size_t length)
        {
            if (!ec || (ec.value() == boost::asio::error::eof && length != 0))
            {
                if (length == 0)
                {
                    EndSession();
                }
                else
                {
                    DEBUG_LOG("Socket %llu read %u bytes", m_ID, length);
                    try
                    {
                        m_Protocol->FeedReadData(std::string(m_Buffer, length));
                        self->DoAsyncRead();
                    }
                    catch (ProtocolError& err)
                    {
                        ERROR_LOG("Socket %llu Protocol error : error_code=%d err_msg=%s", m_ID, err.error_code, err.error_msg.c_str());
                        if (err.error_code > 0) EndSession();
                        else OnFatalError(err);
                    }
                }
            }
            else if (ec.value() == boost::asio::error::eof)
            {
                EndSession();
            }
            else
            {
                OnFatalError(ec);
            }
        });
}

void Socket::DoAsyncWrite()
{
    auto self(shared_from_this());

    //随机打散、重组数据包
    RepackWriteQueue();

    boost::asio::async_write(m_Socket, boost::asio::buffer(m_WriteQueue.front()),
        [this, self](boost::system::error_code ec, std::size_t length)
        {
            if (!ec)
            {
                DEBUG_LOG("Socket %llu write %u bytes", m_ID, m_WriteQueue.front().size());
                m_WriteQueue.pop_front();
                if (!m_WriteQueue.empty())
                {
                    self->DoAsyncWrite();
                }
                else if (m_CloseWhenWriteDone)
                {
                    Stop();
                }
            }
            else
            {
                OnFatalError(ec);
            }
        });
}

void Socket::EndSession()
{
    if (auto pair = m_PairSocket.lock())
    {
        pair->PostCloseWhenDone(true);
    }
    SetCloseWhenDone(true);
}

void Socket::SetCloseWhenDone(bool value)
{
    m_CloseWhenWriteDone = value;
    if (value && m_WriteQueue.empty())
    {
        Stop();
    }
}

void Socket::PostCloseWhenDone(bool value)
{
    auto self(shared_from_this());
    m_IoService.post([self, value](){self->SetCloseWhenDone(value);});
}

void Socket::OnFatalError(boost::system::error_code ec)
{
    ERROR_LOG("Socket %llu fatal error : error_code=%d error_msg=%s", m_ID, ec.value(), ec.message().c_str());
    if (auto pair = m_PairSocket.lock())
    {
        pair->PostStop();
    }
    Stop();
}

void Socket::OnFatalError(const ProtocolError& ec)
{
    if (auto pair = m_PairSocket.lock())
    {
        pair->PostStop();
    }
    Stop();
}

void Socket::RepackWriteQueue()
{
    m_RepackFlag = ((m_RepackFlag + 1) & 3);
    if (m_RepackFlag != 1) return;

    DEBUG_LOG("Socket %llu start repacking packets", m_ID);
    CommUtils::RandomRepacker repack(m_WriteQueue);
    std::list<std::string> nq;

    while (repack.RandomRepack())
    {
        nq.push_back(repack.GetLastPacket());
    }

    m_WriteQueue.swap(nq);

    DEBUG_LOG("Socket %llu random repacked packets", m_ID);
}

int Socket::CreatePairSocket(const std::string& bind_host, uint16_t bind_port, int conn_type, const std::string& remote_host, uint16_t remote_port)
{
    ProtocolPtr protocol = CreateTunnelExitProtocol(bind_host, bind_port, conn_type);
    if (protocol == nullptr)
    {
        ERROR_LOG("Socket %llu CreateTunnelExitProtocol failed. bind_host=%s bind_port=%d conn_type=%d",
            m_ID, bind_host.c_str(), (int)bind_port, conn_type);
        SelfConnRsp(EC_CONN_TYPE_NOT_SUPPORTED, "", 0);
        SetCloseWhenDone(true);
        return EC_CONN_TYPE_NOT_SUPPORTED;
    }

    SocketPtr pair;
    boost::asio::ip::tcp::socket tmp_socket(m_IoService);

    if (conn_type == CONN_TYPE_TCP_BIND)
    {
        pair = std::make_shared<SocketListen>(GetServerImpInstance()->GetId(), m_IoService, std::move(tmp_socket), protocol,
            m_AddFunc, m_DropFunc, m_RouteFunc, bind_host, bind_port);
    }
    else //UDP ASSOCIATE
    {
        pair = std::make_shared<Socket>(GetServerImpInstance()->GetId(), m_IoService, std::move(tmp_socket), protocol,
            m_AddFunc, m_DropFunc, m_RouteFunc);
    }

    SetPairSocket(pair, remote_host, remote_port, conn_type);
    return 0;
}

void Socket::CreatePairSocket(boost::asio::ip::tcp::resolver::iterator target)
{
    std::string remote_host = target->endpoint().address().to_string();
    uint16_t remote_port = target->endpoint().port();
    ProtocolPtr protocol = CreateTunnelExitProtocol("", 0, CONN_TYPE_CONNECT);
    if (protocol == nullptr)
    {
        ERROR_LOG("Socket %llu CreateTunnelExitProtocol failed.", m_ID);
        SelfConnRsp(EC_CONN_TYPE_NOT_SUPPORTED, "", 0);
        SetCloseWhenDone(true);
        return;
    }

    CreatePairSocket(protocol, target, remote_host, remote_port, CONN_TYPE_CONNECT);
}

void Socket::CreatePairSocket(ProtocolPtr protocol, boost::asio::ip::tcp::resolver::iterator target, const std::string& remote_host, uint16_t remote_port, int conn_type)
{
    std::string remote_host_s = remote_host;

    auto self(shared_from_this());

    boost::asio::async_connect(m_ConnTemp, target, [this, self, protocol, remote_host_s, remote_port, conn_type]
        (boost::system::error_code ec, boost::asio::ip::tcp::resolver::iterator ct)
        {
            if (!ec)
            {
                SocketPtr pair = std::make_shared<Socket>(GetServerImpInstance()->GetId(), m_IoService, std::move(m_ConnTemp), protocol,
                    m_AddFunc, m_DropFunc, m_RouteFunc);
                self->SetPairSocket(pair, remote_host_s, remote_port, conn_type);
            }
            else
            {
                ERROR_LOG("Socket %llu connect to [%s:%d] failed. error_code=%d error_msg=%s",
                    m_ID, remote_host_s.c_str(), (int)remote_port, ec.value(), ec.message().c_str());
                SelfConnRsp(EC_CONNECT_FAILED, "", 0);
                SetCloseWhenDone(true);
            }
        });
}

void Socket::SetPairSocket(SocketPtr pair, const std::string& remote_host, uint16_t remote_port, int conn_type)
{
    auto self(shared_from_this());
    m_PairSocket = pair;
    pair->m_PairSocket = self;

    m_AddFunc(pair);
    pair->Run();
    pair->PostConnReq(remote_host, remote_port, conn_type);

    if (m_ReadQueue.size())
    {
        for (std::list<std::string>::iterator it = m_ReadQueue.begin(); it != m_ReadQueue.end(); ++it)
        {
            pair->PostPackage(std::move(*it));
        }
        m_ReadQueue.clear();
    }
}

void SocketListen::Run()
{
    BindProtocolCallbacks();
    INFO_LOG("Socket %llu start...", m_ID);

    //尝试创建监听socket
    auto addr = boost::asio::ip::address::from_string(m_BindHost);
    int try_count = 10;
    uint16_t base_inc = 10;
    while (try_count--)
    {
        try
        {
            boost::asio::ip::tcp::endpoint ep(addr, m_BindPort);
            DEBUG_LOG("Socket %llu try to bind TCP at [%s:%d]...", m_ID, m_BindHost.c_str(), m_BindPort);
            m_AcceptorPtr = std::make_shared<boost::asio::ip::tcp::acceptor>(m_IoService);
            DEBUG_LOG("Socket %llu successfully bind TCP at [%s:%d]...", m_ID, m_BindHost.c_str(), m_BindPort);
        }
        catch (...)
        {
            m_BindPort += CommUtils::Rand(1, base_inc);
            base_inc *= 2;
            while (m_BindPort < 1024) m_BindPort += CommUtils::Rand(1, base_inc);
            m_AcceptorPtr = nullptr;
        }
    }

    if (m_AcceptorPtr == nullptr)
    {
        ERROR_LOG("Socket %llu bind TCP failed.", m_ID);
        if (auto pair = m_PairSocket.lock())
        {
            pair->PostConnRsp(EC_TCP_BIND_FAILED, "", 0);
        }
        EndSession();
        return;
    }

    //建立监听以后就发回一个连接结果包
    if (auto pair = m_PairSocket.lock())
    {
        pair->PostConnRsp(0, m_BindHost, m_BindPort);
    }
    else
    {
        ERROR_LOG("Socket %llu successfully bind TCP port. but pair socket has gone", m_ID);
        Stop();
        return;
    }

    //开始监听，并且只接受一个连接
    auto self(shared_from_this());
    m_AcceptorPtr->async_accept(m_IncomingSocket, [this, self](boost::system::error_code ec)
    {
        if (!ec)
        {
            auto remote_endpoint = m_IncomingSocket.remote_endpoint();
            const std::string& remote_host = remote_endpoint.address().to_string();
            INFO_LOG("Socket %llu got a incoming socket from [%s:%d]", m_ID, remote_host.c_str(), (int)(remote_endpoint.port()));

            //创建新socket使用的协议
            ProtocolPtr protocol = CreateTunnelExitProtocol("", 0, CONN_TYPE_CONNECT);
            if (protocol == nullptr)
            {
                ERROR_LOG("Socket %llu CreateTunnelExitProtocol for new socket failed.", m_ID);
                EndSession();
                return;
            }

            //通过协议发回socks5 tcp bind的第二步回包
            m_Protocol->FeedIncomingConn(remote_host, remote_endpoint.port());

            //创建新的socket替代自己
            if (auto pair = m_PairSocket.lock())
            {
                INFO_LOG("Socket %llu start to create new socket to replace itself", m_ID);
                SocketPtr tmp_socket = std::make_shared<Socket>(m_ID, m_IoService, std::move(m_IncomingSocket), protocol, m_AddFunc, m_DropFunc, m_RouteFunc);
                m_AddFunc(tmp_socket);
                tmp_socket->InheritPairSocket(pair);
                tmp_socket->Run();
            }
            else
            {
                ERROR_LOG("Socket %llu successfully bind TCP port. but pair socket has gone", m_ID);
            }
            INFO_LOG("Socket %llu (before inherit) ready to stop itself", m_ID);
            Stop();
        }
        else
        {
            OnFatalError(ec);
        }
    });
}

void SocketListen::Stop()
{
    INFO_LOG("Socket %llu (before inherit) stop...", m_ID);
    auto self(shared_from_this());
    if (m_AcceptorPtr)
    {
        try
        {
            m_AcceptorPtr->cancel();
        }
        catch(...) {}
    }
    m_DropFunc(self);
}

void SocketUdp::Run()
{
    using namespace std::placeholders;
    m_ID = GetServerImpInstance()->GetId();
    m_Protocol->SetReadCallback(std::bind(&SocketUdp::OnDataArrival, this, _1));
    m_Protocol->SetID(m_ID);
    INFO_LOG("UDP Socket %llu start...", m_ID);
    DoUdpAsyncRead();
}

void SocketUdp::Stop()
{
    try
    {
        m_Socket.cancel();
    }
    catch(...) {}
    INFO_LOG("UDP Socket %llu stop...", m_ID);
}

void SocketUdp::OnDataArrival(std::string&& data)
{
    if (auto pair = m_PairSocket.lock())
    {
        pair->PostPackage(std::move(data));
    }
    else
    {
        ERROR_LOG("UDP Socket %llu send data to pair socket failed.", m_ID);
    }
}

void SocketUdp::OnUdpWrite(std::string&& data, const std::string& host, uint16_t port)
{
    bool writing = !(m_WriteQueue.empty());
    m_WriteQueue.emplace_back(std::move(data), host, port);
    if (!writing) DoUdpAsyncWrite();
}

void SocketUdp::DoUdpAsyncRead()
{
    auto self(shared_from_this());
    m_Socket.async_receive_from(boost::asio::buffer(m_Buffer, BUFFER_SIZE), m_RemoteEP,
        [this, self](boost::system::error_code ec, std::size_t length)
        {
            if (!ec || (ec.value() == boost::asio::error::eof && length != 0))
            {
                if (length)
                {
                    const std::string& remote_host = m_RemoteEP.address().to_string();
                    INFO_LOG("UDP Socket %llu read %u bytes from [%s:%d]", m_ID, length, remote_host.c_str(), (int)(m_RemoteEP.port()));
                    m_Protocol->FeedUdpReadData(std::string(m_Buffer, length), remote_host, m_RemoteEP.port());
                }
                self->DoUdpAsyncRead();
            }
        });
}

void SocketUdp::DoUdpAsyncWrite()
{
    auto self(shared_from_this());
    m_RemoteEP = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(m_WriteQueue.front().host), m_WriteQueue.front().port);
    m_Socket.async_send_to(boost::asio::buffer(m_WriteQueue.front().data), m_RemoteEP,
        [this, self](boost::system::error_code ec, std::size_t length)
        {
            if (!ec)
            {
                INFO_LOG("UDP Socket %llu sent %u bytes to [%s:%d]", m_ID,
                    m_WriteQueue.front().data.size(), m_WriteQueue.front().host.c_str(), (int)(m_WriteQueue.front().port));
                m_WriteQueue.pop_front();
                if (!m_WriteQueue.empty()) self->DoUdpAsyncWrite();
            }
        });
}

};