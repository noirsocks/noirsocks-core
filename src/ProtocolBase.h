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

#include <functional>
#include <utility>
#include <memory>
#include <string>
#include <stdint.h>

namespace NoirSocks
{

class ProtocolBase;

typedef std::shared_ptr<ProtocolBase> ProtocolPtr;

//Protocol callback definitions
typedef std::function<void(std::string&&)> PCB_OnData; //收发数据的回调函数
typedef std::function<void(std::string&&, const std::string&, uint16_t)> PCB_OnUdpData; //发送UDP数据的回调函数
typedef std::function<int(std::string&&, uint16_t, int)> PCB_OnConnReqGot; //从协议流里解析出了一个连接请求
typedef std::function<int(int, std::string&&, uint16_t)> PCB_OnConnRspGot; //从协议流里解析出了一个连接结果
typedef std::function<uint16_t(const std::string&, uint16_t, ProtocolPtr)> PCB_CreateSubUdpSocket; //根据指定IP与协议创建UDP Socket并且返回端口号

enum CONN_TYPE
{
    CONN_TYPE_CONNECT = 1,
    CONN_TYPE_TCP_BIND = 2,
    CONN_TYPE_UDP_ASSOCIATE = 3
};

class ProtocolError
{
public:
    int error_code; //错误码，负数表示严重错误，正数表示“较轻”的错误
    std::string error_msg;

    ProtocolError(int ec, const std::string& msg) : error_code(ec), error_msg(msg) {}
    ProtocolError(int ec, std::string&& msg) : error_code(ec), error_msg(std::move(msg)) {}
};

class ProtocolBase
{
public:
    ProtocolBase() {}
    virtual ~ProtocolBase() {}

    void SetID(uint64_t id) {m_ID = id;}
    void SetLocalAddr(const std::string& local_host, uint16_t local_port) {m_LocalHost = local_host; m_LocalPort = local_port;}
    void SetRemoteAddr(const std::string& remote_host, uint16_t remote_port) {m_RemoteHost = remote_host; m_RemotePort = remote_port;}

    void SetReadCallback(PCB_OnData cb) {m_CBRead = cb;}
    void SetWriteCallback(PCB_OnData cb) {m_CBWrite = cb;}

    void SetUdpWriteCallback(PCB_OnUdpData cb) {m_CBUdpWrite = cb;}
    void SetCreateUdpCallback(PCB_CreateSubUdpSocket cb) {m_CBCreateUdp = cb;}

    void SetConnReqCallback(PCB_OnConnReqGot cb) {m_CBConnReq = cb;}
    void SetConnRspCallback(PCB_OnConnRspGot cb) {m_CBConnRsp = cb;}

    virtual void FeedReadData(std::string data) = 0; //把直接读取的数据传递给协议进行解析
    virtual void FeedWriteData(std::string data) = 0; //把需要发送出去的原始数据传递给协议进行封包

    virtual void FeedUdpReadData(std::string data, const std::string& host, uint16_t port) = 0; //把UDP直接读取的数据传递给协议进行解析

    virtual void FeedConnReq(const std::string& host, uint16_t port, int conn_type) = 0; //让协议生成一个连接请求包
    virtual void FeedConnRsp(int result, const std::string& host, uint16_t port) = 0; //让协议生成一个连接结果包
    virtual void FeedIncomingConn(const std::string& host, uint16_t port) = 0; //TCP.BIND时，告诉协议此时来了一个客户端

protected:
    PCB_OnData m_CBRead; //读取数据回调
    PCB_OnData m_CBWrite; //发送数据回调
    PCB_OnUdpData m_CBUdpWrite; //发送UDP数据回调
    PCB_CreateSubUdpSocket m_CBCreateUdp;
    PCB_OnConnReqGot m_CBConnReq;
    PCB_OnConnRspGot m_CBConnRsp;
    uint64_t m_ID;
    std::string m_LocalHost;
    uint16_t m_LocalPort;
    std::string m_RemoteHost;
    uint16_t m_RemotePort;
};

};
