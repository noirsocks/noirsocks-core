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

#include "Http_Utils.h"
#include "CommUtils.h"

namespace NoirSocks
{

namespace Http
{

bool HttpHeaderParser::ParseReqHeader(const std::string& header)
{
    //first line
    auto line = GetLineFromHeader(header, 0);

    if (line.first >= line.second) return false;

    auto secs = CommUtils::SplitString(header.substr(line.first, line.second - line.first), " \t\r\n");

    if (secs.size() != 3) return false;
    m_ReqMethod = std::move(secs[0]);
    m_ReqTarget = std::move(secs[1]);
    m_ReqVer = std::move(secs[2]);

    //other lines
    ParseHeaderFields(header, line.second + 2);

    return true;
}

const std::string& HttpHeaderParser::GetHeaderField(const std::string& key)
{
    auto map_it = m_Header.find(key);
    if (map_it != m_Header.end())
    {
        return map_it->second;
    }
    static std::string empty;
    return empty;
}

void HttpHeaderParser::SetHeaderField(const std::string& key, const std::string& value)
{
    auto map_it = m_Header.find(key);
    if (map_it != m_Header.end())
    {
        map_it->second = value;
        return;
    }
    m_Header[key] = value;
    m_HeaderKeys.push_back(key);
}

void HttpHeaderParser::EraseHeaderField(HttpHeaderParser::EraseCondition cond)
{
    for (auto it = m_HeaderKeys.begin(); it != m_HeaderKeys.end(); )
    {
        if (cond(*it))
        {
            it = m_HeaderKeys.erase(it);
            m_Header.erase(*it);
        }
        else
        {
            ++it;
        }
    }
}

std::string HttpHeaderParser::RepackHeader()
{
    std::string ret = m_ReqMethod + " " + m_ReqTarget + " " + m_ReqVer + "\r\n";
    for (auto it = m_HeaderKeys.begin(); it != m_HeaderKeys.end(); ++it)
    {
        auto map_it = m_Header.find(*it);
        if (map_it != m_Header.end())
        {
            ret += *it + ": " + map_it->second + "\r\n";
        }
    }
    ret += "\r\n";
    return std::move(ret);
}

void HttpHeaderParser::ParseHeaderFields(const std::string& header, size_t pos)
{
    while (true)
    {
        auto line = GetLineFromHeader(header, pos);
        if (line.first >= line.second) return;
        pos = line.second + 2;

        size_t colon_pos = line.first;
        for (; colon_pos + 1 < line.second && !(header[colon_pos] == ':' && header[colon_pos + 1] == ' '); ++colon_pos);
        if (colon_pos + 1 >= line.second) continue;

        SetHeaderField(header.substr(line.first, colon_pos - line.first), header.substr(colon_pos + 2, line.second - (colon_pos + 2)));
    }
}

std::pair<size_t, size_t> HttpHeaderParser::GetLineFromHeader(const std::string& header, size_t pos)
{
    size_t begin = pos;
    size_t end = pos;
    for (; end + 1 < header.size() && !(header[end] == '\r' && header[end + 1] == '\n'); ++end);
    end = (end + 1 == header.size()) ? header.size() : end;
    return std::make_pair(begin, end);
}

bool HttpUriParser::ParseUri(const std::string& uri)
{
    //find protocol
    auto proto_len = uri.find("://");
    if (proto_len == std::string::npos) return false;

    this->protocol = uri.substr(0, proto_len);

    //find path
    auto addr_start = proto_len + 3;
    auto path_start = uri.find("/", addr_start);
    path_start = (path_start == std::string::npos) ? uri.size() : path_start;

    this->path = (path_start == uri.size()) ? "/" : uri.substr(path_start);

    if (path_start == addr_start) return false;

    if (uri[addr_start] == '[') return ParseHostPort(uri.substr(addr_start, path_start - addr_start));

    //find user:pass@
    auto at_pos = addr_start;
    for (; at_pos < path_start && uri[at_pos] != '@'; ++at_pos);
    if (at_pos < path_start)
    {
        auto colon_pos = addr_start;
        for (; colon_pos < at_pos && uri[colon_pos] != ':'; ++colon_pos);
        if (colon_pos < at_pos)
        {
            this->user = uri.substr(addr_start, colon_pos - addr_start);
            this->pass = uri.substr(colon_pos + 1, at_pos - (colon_pos + 1));
        }
        else
        {
            this->user = uri.substr(addr_start, at_pos - addr_start);
        }
        addr_start = at_pos + 1;
    }

    return (path_start == addr_start) ? false : ParseHostPort(uri.substr(addr_start, path_start - addr_start));
}

bool HttpUriParser::ParseHostPort(const std::string& host_port)
{
    if (host_port.empty()) return false;

    if (host_port[0] == '[') //IPv6 or IPvFuture
    {
        size_t bracket_r = host_port.size() - 1;
        for (; bracket_r > 0 && host_port[bracket_r] != ']'; --bracket_r);
        if (bracket_r == 0) return false;

        this->host = host_port.substr(1, bracket_r - 1);
        size_t colon_pos = bracket_r + 1;
        for (; colon_pos < host_port.size() && host_port[colon_pos] != ':'; ++colon_pos);
        if (colon_pos + 1 < host_port.size())
        {
            this->port = CommUtils::strto<uint16_t>(host_port.substr(colon_pos + 1));
        }
    }
    else
    {
        size_t colon_pos = 0;
        for (; colon_pos < host_port.size() && host_port[colon_pos] != ':'; ++colon_pos);
        if (colon_pos + 1 < host_port.size())
        {
            this->port = CommUtils::strto<uint16_t>(host_port.substr(colon_pos + 1));
        }
        this->host = host_port.substr(0, colon_pos);
    }

    if (this->port == 0 && this->protocol == "http")
    {
        this->port = 80;
    }

    return true;
}

};

};
