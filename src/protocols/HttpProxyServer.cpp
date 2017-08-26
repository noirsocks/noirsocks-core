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

#include <cstring>
#include "Logger.h"
#include "CommUtils.h"
#include "HttpProxyServer.h"
#include "Http_Utils.h"

namespace NoirSocks
{

namespace Protocol
{

bool HttpProxyServer::CheckProtocolConf(const LocalService& service, std::string& err_msg)
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

ProtocolPtr HttpProxyServer::CreateProtocol(const LocalService& service)
{
    return std::make_shared<HttpProxyServer>(service);
}

void HttpProxyServer::FeedReadData(std::string data)
{
    if (m_ConnReqGot && !m_AllowPipelining) //不允许pipelining的命令 直接透传数据
    {
        m_CBRead(std::move(data));
        return;
    }

    m_Buf += std::move(data);
    size_t head_len = 0;
    while ((head_len = m_Buf.find("\r\n\r\n")) != std::string::npos)
    {
        head_len += 4;
        DEBUG_LOG("Socket %llu got a %llu bytes http request header", m_ID, (uint64_t)head_len);
        Http::HttpHeaderParser http;
        if (!http.ParseReqHeader(m_Buf))
        {
            ERROR_LOG("Socket %llu got a corrupt http request package.", m_ID);
            m_CBWrite("HTTP 400 Bad Request\r\n\r\n");
            throw ProtocolError(2001, "corrupt http request package");
        }

        DEBUG_LOG("Socket %llu got a http request. method=[%s] target=[%s]", m_ID, http.GetMethod().c_str(), http.GetTarget().c_str());

        m_AllowPipelining = (http.GetMethod() == "GET" || http.GetMethod() == "HEAD");
        DEBUG_LOG("Socket %llu allow_pipelining: %s", m_ID, m_AllowPipelining ? "TRUE" : "FALSE");

        DEBUG_LOG("Socket %llu start parsing target %s", m_ID, http.GetTarget().c_str());

        Http::HttpUriParser uri;
        bool uri_parse = http.GetMethod() == "CONNECT" ? uri.ParseHostPort(http.GetTarget()) : uri.ParseUri(http.GetTarget());
        if (!uri_parse || uri.host.empty() || uri.port == 0)
        {
            ERROR_LOG("Socket %llu parse target %s failed.", m_ID, http.GetTarget().c_str());
            m_CBWrite("HTTP 400 Bad Request\r\n\r\n");
            throw ProtocolError(2002, "corrupt http request target");
        }

        DEBUG_LOG("Socket %llu http request target: host=[%s] port=[%d] path=[%s]", m_ID, uri.host.c_str(), (int)uri.port, uri.path.c_str());

        if (!m_ConnReqGot)
        {
            std::string host = uri.host;
            m_CBConnReq(std::move(host), uri.port, CONN_TYPE_CONNECT);
            m_ConnReqGot = true;
        }

        if (http.GetMethod() == "CONNECT")
        {
            m_IsConnect = true;
            m_Buf = m_Buf.substr(head_len);
            m_CBRead(std::move(m_Buf));
            break;
        }

        //改写header
        if (!m_AllowPipelining)
        {
            http.SetHeaderField("Connection", "close");
        }
        if (http.GetHeaderField("Connection").empty())
        {
            http.SetHeaderField("Connection", http.GetHeaderField("Proxy-Connection"));
        }
        http.EraseHeaderField([](const std::string& key){return key.size() > 5 && memcmp(key.c_str(), "Proxy", 5) == 0;});
        http.SetTarget(uri.path.empty() ? "/" : uri.path);

        //返回重组的header
        m_CBRead(http.RepackHeader());
        m_Buf = m_Buf.substr(head_len);

        //如果是不允许pipelineing的命令字，就把剩下的数据当作透传流量返回
        if (!m_AllowPipelining)
        {
            m_CBRead(std::move(m_Buf));
            break;
        }
    }
}

void HttpProxyServer::FeedWriteData(std::string data)
{
    m_CBWrite(std::move(data));
}

void HttpProxyServer::FeedConnRsp(int result, const std::string& host, uint16_t port)
{
    if (result)
    {
        std::string msg = "<html><body><p>Proxy server failed to connect " + m_TargetHost + ":" + CommUtils::tostr(m_TargetPort) + "</p></body></html>";
        m_CBWrite("HTTP/1.1 504 Connection failed\r\nContent-length: " + CommUtils::tostr(msg.size()) + "\r\n\r\n" + msg);
        return;
    }
    if (m_IsConnect)
    {
        m_CBWrite("HTTP/1.1 200 Connection established\r\n\r\n");
    }
}

};

};
