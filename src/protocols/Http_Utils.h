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

#include <string>
#include <map>
#include <list>
#include <stdint.h>
#include <functional>

namespace NoirSocks
{

namespace Http
{

class HttpHeaderParser
{
public:
    bool ParseReqHeader(const std::string& header);

    const std::string& GetMethod() {return m_ReqMethod;}
    const std::string& GetTarget() {return m_ReqTarget;}

    void SetTarget(const std::string& target) {m_ReqTarget = target;}

    const std::string& GetHeaderField(const std::string& key);
    void SetHeaderField(const std::string& key, const std::string& value);

    typedef std::function<bool(const std::string&)> EraseCondition;
    void EraseHeaderField(EraseCondition cond);

    std::string RepackHeader();

private:
    void ParseHeaderFields(const std::string& header, size_t pos);
    std::pair<size_t, size_t> GetLineFromHeader(const std::string& header, size_t pos);

private:
    std::string m_ReqMethod;
    std::string m_ReqTarget;
    std::string m_ReqVer;

    std::list<std::string> m_HeaderKeys;
    std::map<std::string, std::string> m_Header;
};

class HttpUriParser
{
public:
    HttpUriParser() : port(0) {}

    bool ParseUri(const std::string& uri);
    bool ParseHostPort(const std::string& host_port);

    std::string protocol;
    std::string user;
    std::string pass;
    std::string host;
    uint16_t port;
    std::string path;
};

};

};
