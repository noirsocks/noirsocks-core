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

#include "Config.h"
#include "ProtocolBase.h"

namespace NoirSocks
{

ProtocolPtr CreateProtocol(const NextNode& node);
ProtocolPtr CreateProtocol(const LocalService& service);
ProtocolPtr CreateTunnelExitProtocol(const std::string& bind_host, uint16_t bind_port, int conn_type);

};
