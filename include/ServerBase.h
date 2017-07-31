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

#include <memory>
#include "Config.h"

namespace NoirSocks
{

class ServerBase
{
public:
    virtual ~ServerBase() {}
    virtual int Run(const GlobalConfig& conf) = 0;
    virtual void Stop() = 0;

    virtual const GlobalConfig& GetConf() = 0;
};

std::shared_ptr<ServerBase> GetServerInstance();

};
