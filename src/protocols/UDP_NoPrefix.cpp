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

#include "Logger.h"
#include "CommUtils.h"
#include "UDP_NoPrefix.h"

namespace NoirSocks
{

namespace Protocol
{

void UDP_NoPrefix::FeedUdpReadData(std::string data, const std::string& host, uint16_t port)
{
    //重新封装成隧道内格式
    if (host.size() > 255)
    {
        ERROR_LOG("UDP Socket %llu does not support host longer than 255 bytes, packet ignored", m_ID);
        return;
    }
    uint16_t data_len = (uint16_t)(data.size());

    if (data_len != data.size())
    {
        ERROR_LOG("UDP Socket %llu does not support data longer than 65535 bytes, packet ignored", m_ID);
        return;
    }

    uint8_t b1 = (uint8_t)(host.size());
    uint8_t b2[4];
    CommUtils::write16(b2, port);
    CommUtils::write16(b2 + 2, data_len);

    m_CBRead(std::string((char*)&b1, 1) + host + std::string((char*)b2, 4) + data);
}

}

}
