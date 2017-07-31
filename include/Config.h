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
#include <vector>
#include <map>
#include <stdint.h>

namespace NoirSocks
{

enum LOG_LEVEL
{
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_ERROR = 2,
    LOG_LEVEL_NONE = 3
};

struct NextNode
{
    std::string name;
    std::string host;
    uint16_t port;
    std::string protocol;

    std::string psk;
    int dynamic_iv_interval;

    NextNode() : port(0), dynamic_iv_interval(0) {}
};

struct Route
{
    std::string host_pattern;

    std::vector<std::string> next_nodes;

    bool is_tunnel_exit;
    std::string bind_addr;
    uint16_t bind_port;

    Route() : is_tunnel_exit(false), bind_port(0) {}
};

struct LocalService
{
    std::string name;
    std::string host;
    uint16_t port;
    std::string protocol;

    uint16_t socks_udp_bind_port;

    std::string psk;
    int dynamic_iv_interval;

    std::vector<Route> rules;
    Route def_route;
    bool has_def_route;

    LocalService() : port(0), socks_udp_bind_port(0), dynamic_iv_interval(0), has_def_route(false) {}
};

struct GlobalConfig
{
    std::string id;
    int log_level;
    std::string log_file;

    std::string ban_list_file;
    int ban_stat_secs;
    int ban_req_limit;

    std::map<std::string, NextNode> next_nodes;

    std::vector<Route> rules;
    Route def_route;
    bool has_def_route;

    std::map<std::string, LocalService> local_services;

    GlobalConfig() : log_level(LOG_LEVEL_NONE), ban_stat_secs(0), ban_req_limit(0) {}
};

};
