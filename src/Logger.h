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

#include <ctime>
#include <cstdio>
#include "ServerBase.h"
#include "CommUtils.h"

namespace NoirSocks
{

void DoLog(const std::string& log_file, const char* format, ...);

#define LOG_BY_LEVEL(level, format, level_str, ...) {\
    const GlobalConfig& __gcfsb = GetServerInstance()->GetConf();\
    if (__gcfsb.log_level <= level && __gcfsb.log_file.size()){\
        time_t tm_now = time(0); struct tm* pt = localtime(&tm_now);\
        char log_file_suffix[16] = {0}; snprintf(log_file_suffix, 15, ".%d%02d%02d", pt->tm_year + 1900, pt->tm_mon + 1, pt->tm_mday);\
        DoLog(__gcfsb.log_file + std::string(log_file_suffix), level_str "[%02d:%02d:%02d][PID=%llu] " format "\n",\
        pt->tm_hour, pt->tm_min, pt->tm_sec, CommUtils::GetProcessId(), ##__VA_ARGS__);}}

#define DEBUG_LOG(format, ...) LOG_BY_LEVEL(LOG_LEVEL_DEBUG, format, "[DEBUG]", ##__VA_ARGS__)
#define INFO_LOG(format, ...)  LOG_BY_LEVEL(LOG_LEVEL_INFO,  format, "[INFO]" , ##__VA_ARGS__)
#define ERROR_LOG(format, ...) LOG_BY_LEVEL(LOG_LEVEL_ERROR, format, "[ERROR]", ##__VA_ARGS__)

};
