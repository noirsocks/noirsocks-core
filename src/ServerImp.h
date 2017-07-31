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

#include <set>
#include <string>
#include <deque>
#include <map>
#include <stdint.h>
#include <boost/asio.hpp>
#include "ServerBase.h"

namespace NoirSocks
{

class ServerImp : public ServerBase
{
public:
    virtual int Run(const GlobalConfig& conf);
    virtual void Stop();

    virtual const GlobalConfig& GetConf() {return *m_ConfigPtr;}

    bool GetNextNodeAddress(const std::string& name, boost::asio::ip::tcp::resolver::iterator& node);

    bool IsRemoteHostBanned(const std::string& host);
    void ReportRemoteHostBadRequest(const std::string& host);

    void LoadBannedHostList(const std::string& file);
    void SaveBannedHostList(const std::string& file);

    uint64_t GetId();

private:
    std::shared_ptr<boost::asio::io_service> m_IoService;

    std::map<std::string, boost::asio::ip::tcp::resolver::iterator> m_NextNodeDns;

    const GlobalConfig* m_ConfigPtr;

    std::set<std::string> m_BannedHosts;
    std::map<std::string, std::deque<uint64_t> > m_BadReqReports;

    uint64_t m_ID;
};

std::shared_ptr<ServerImp> GetServerImpInstance();

};
