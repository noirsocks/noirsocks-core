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

#include <algorithm>
#include <ctime>
#include <cstdio>
#include <fstream>
#include "ServerImp.h"
#include "Service.h"
#include "Logger.h"
#include "CommUtils.h"

namespace NoirSocks
{

std::shared_ptr<ServerImp> GetServerImpInstance()
{
    static std::shared_ptr<ServerImp> g_Instance = std::make_shared<ServerImp>();
    return g_Instance;
}

std::shared_ptr<ServerBase> GetServerInstance()
{
    return GetServerImpInstance();
}

int ServerImp::Run(const GlobalConfig& conf)
{
    //准备启动服务
    Stop();
    m_IoService = std::make_shared<boost::asio::io_service>();
    m_ConfigPtr = &conf;
    CommUtils::Srand(time(0) + CommUtils::GetProcessId());
    m_ID = 0;

    INFO_LOG("Server initialization start");

    //加载ban IP列表
    LoadBannedHostList(conf.ban_list_file);

    //UNIX信号处理
    boost::asio::signal_set signals(*m_IoService, SIGINT, SIGTERM);
    signals.async_wait([&](const boost::system::error_code& error, int signal_number) { Stop(); });

    //远端节点DNS解析
    INFO_LOG("Start dns resolve for next nodes...");
    boost::asio::ip::tcp::resolver dns(*m_IoService);
    for (auto it = conf.next_nodes.begin(); it != conf.next_nodes.end(); ++it)
    {
        DEBUG_LOG("Start doing dns resolve for next node %s ...", it->first.c_str());
        try
        {
            boost::asio::ip::tcp::resolver::iterator dns_result = dns.resolve({it->second.host, CommUtils::tostr(it->second.port)});
            m_NextNodeDns[it->first] = dns_result;
            DEBUG_LOG("DNS query for next node %s [%s:%d] done.", it->first.c_str(), it->second.host.c_str(), (int)(it->second.port));
        }
        catch(...)
        {
            ERROR_LOG("DNS query for next node %s [%s:%d] failed.", it->first.c_str(), it->second.host.c_str(), (int)(it->second.port));
        }
    }
    INFO_LOG("DNS resolve for next nodes done.");
    if (m_NextNodeDns.empty())
    {
        INFO_LOG("No next nodes successfully resolved.");
    }

    //创建服务
    INFO_LOG("Start creating local services...");
    std::vector<ServicePtr> local_services;
    for (auto it = conf.local_services.begin(); it != conf.local_services.end(); ++it)
    {
        local_services.push_back(std::make_shared<Service>(it->second, *m_IoService));
    }

    //启动所有服务
    std::for_each(local_services.begin(), local_services.end(), [](ServicePtr ptr){ptr->Run();});
    INFO_LOG("Local services created, server start running...");
    m_IoService->run();

    //保存ban IP列表
    SaveBannedHostList(conf.ban_list_file);

    INFO_LOG("Server stopped");

    return 0;
}

void ServerImp::Stop()
{
    if (m_IoService)
    {
        m_IoService->stop();
    }
}

bool ServerImp::GetNextNodeAddress(const std::string& name, boost::asio::ip::tcp::resolver::iterator& node)
{
    if (m_NextNodeDns.find(name) == m_NextNodeDns.end())
    {
        ERROR_LOG("Next node address for name %s not found.", name.c_str());
        return false;
    }
    node = m_NextNodeDns[name];
    return true;
}

bool ServerImp::IsRemoteHostBanned(const std::string& host)
{
    return m_BannedHosts.count(host) != 0;
}

void ServerImp::ReportRemoteHostBadRequest(const std::string& host)
{
    time_t tm_now = time(0);
    std::deque<uint64_t>& hq = m_BadReqReports[host];

    while (hq.size() && hq.front() < tm_now - m_ConfigPtr->ban_stat_secs)
    {
        hq.pop_front();
    }
    hq.push_back(tm_now);

    bool ban = (hq.size() >= m_ConfigPtr->ban_req_limit);

    INFO_LOG("Remote host %s post %u bad requests in past %d seconds %s",
        host.c_str(), hq.size(), m_ConfigPtr->ban_stat_secs, ban ? "MARK AS BANNED" : "...");

    if (ban)
    {
        m_BannedHosts.insert(host);
    }
}

void ServerImp::LoadBannedHostList(const std::string& file)
{
    if (file.empty())
    {
        ERROR_LOG("ban_list_file not configured, banned hosts will not be loaded.");
        return;
    }

    std::ifstream ff(file.c_str());
    if (!ff)
    {
        ERROR_LOG("Cannot open ban_list_file %s, banned hosts will not be loaded.", file.c_str());
        return;
    }

    std::string host;
    while (ff >> host)
    {
        m_BannedHosts.insert(host);
    }

    INFO_LOG("%u banned hosts loaded.", m_BannedHosts.size());
}

void ServerImp::SaveBannedHostList(const std::string& file)
{
    if (file.empty())
    {
        ERROR_LOG("ban_list_file not configured, banned hosts will not be saved.");
        return;
    }

    FILE* ff = fopen(file.c_str(), "w");
    if (ff == NULL)
    {
        ERROR_LOG("Cannot open ban_list_file %s, banned hosts will not be saved.", file.c_str());
        return;
    }

    for (auto it = m_BannedHosts.begin(); it != m_BannedHosts.end(); ++it)
    {
        fprintf(ff, "%s\n", it->c_str());
    }

    fclose(ff);

    INFO_LOG("%u banned hosts saved.", m_BannedHosts.size());
}

uint64_t ServerImp::GetId()
{
    return ++m_ID;
}

};
