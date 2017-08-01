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

#include "ProtocolBase.h"

namespace NoirSocks
{

namespace Protocol
{

class UDP_Prefix : public ProtocolBase
{
public:
    UDP_Prefix() : m_LimitSrc(false), m_LimitPort(0) {}
    UDP_Prefix(bool limit_src, const std::string& limit_host, uint16_t limit_port)
        : m_LimitSrc(limit_src), m_LimitHost(limit_host), m_LimitPort(limit_port)
    {}

    virtual void OnTimer(std::string msg){} //定时器成功结束

    virtual void FeedReadData(std::string data){} //把直接读取的数据传递给协议进行解析
    virtual void FeedWriteData(std::string data){} //把需要发送出去的原始数据传递给协议进行封包

    virtual void FeedUdpReadData(std::string data, const std::string& host, uint16_t port); //把UDP直接读取的数据传递给协议进行解析

    virtual void FeedConnReq(const std::string& host, uint16_t port, int conn_type){} //让协议生成一个连接请求包
    virtual void FeedConnRsp(int result, const std::string& host, uint16_t port){} //让协议生成一个连接结果包
    virtual void FeedIncomingConn(const std::string& host, uint16_t port){} //TCP.BIND时，告诉协议此时来了一个客户端

private:
    bool m_LimitSrc;
    std::string m_LimitHost;
    uint16_t m_LimitPort;
};

};

};
