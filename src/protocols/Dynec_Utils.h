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

#include <stdint.h>
#include <map>
#include <set>
#include <string>
#include <cstring>
#include <ctime>
#include <algorithm>

#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "Logger.h"
#include "CommUtils.h"

namespace NoirSocks
{

class Dynec_Utils
{
public:
    static Dynec_Utils& GetInstance()
    {
        static Dynec_Utils ins;
        return ins;
    }

    struct iv_t
    {
        unsigned char ivec[16];
    };

    const iv_t& GetDynIV(const std::string& psk, uint64_t ts)
    {
        return GetDynIVImp(psk, ts);
    }

    const AES_KEY* GetEncryptKey(const std::string& psk)
    {
        return GetKeyWithCache(psk, m_EncKeys, AES_set_encrypt_key);
    }
    const AES_KEY* GetDecryptKey(const std::string& psk)
    {
        return GetKeyWithCache(psk, m_DecKeys, AES_set_decrypt_key);
    }

    uint64_t NormalizeTs(uint64_t ts, uint64_t gap)
    {
        return ts - ts % gap;
    }

    void GetSessionIV(const std::string& session_key, const unsigned char* dyn_iv, unsigned char* iv_out)
    {
        unsigned int tmp_len = 0;
        HMAC(EVP_md5(), dyn_iv, 16, (const unsigned char*)session_key.c_str(), session_key.size(), iv_out, &tmp_len);
    }

    uint64_t GetUUID(const std::string& local_host)
    {
        static uint64_t low_bits = 0;
        ++low_bits;
        uint64_t high_bits = 0;
        for (const char& ch : local_host)
        {
            high_bits *= 131;
            high_bits += (uint64_t)((*(const unsigned char*)(&ch))) * 131;
        }
        uint64_t pid_part = CommUtils::GetProcessId() & 0xFFFF;
        return (high_bits << 32) | (pid_part << 16) | (low_bits & 0xFFFF);
    }

    bool CheckUUIDRepeat(uint64_t uuid, uint64_t expire_ts)
    {
        ClearExpiredUUID();
        if (m_UUID.count(uuid))
        {
            return true;
        }
        m_UUID.insert(uuid);
        m_Time_2_UUID[expire_ts].insert(uuid);
        return false;
    }

private:
    Dynec_Utils() {}

    std::map< std::string, std::map<uint64_t, iv_t> > m_DynIVec;
    std::map<std::string, AES_KEY> m_EncKeys;
    std::map<std::string, AES_KEY> m_DecKeys;

    std::set<uint64_t> m_UUID;
    std::map< uint64_t, std::set<uint64_t> > m_Time_2_UUID;

    template<typename GenKeyFunc>
    const AES_KEY* GetKeyWithCache(const std::string& psk, std::map<std::string, AES_KEY>& cache, GenKeyFunc func)
    {
        auto it = cache.find(psk);
        if (it != cache.end())
        {
            return &(it->second);
        }
        unsigned char md[32];
        SHA256((const unsigned char*)psk.c_str(), psk.size(), md);
        func(md, 128, &(cache[psk]));
        return &(cache[psk]);
    }

    const iv_t& GetDynIVImp(const std::string& psk, uint64_t ts)
    {
        std::map<uint64_t, iv_t>& cache = m_DynIVec[psk];
        auto it = cache.find(ts);
        if (it != cache.end())
        {
            return it->second;
        }
        if (cache.size() > 3)
        {
            cache.erase(cache.begin());
        }
        iv_t& iv = cache[ts];

        unsigned char* tmp = new unsigned char[psk.size() + 8];
        memcpy(tmp, psk.c_str(), psk.size());
        CommUtils::write64(tmp + psk.size(), ts);
        unsigned int tmp_len;
        HMAC(EVP_md5(), psk.c_str(), psk.size(), tmp, psk.size() + 8, iv.ivec, &tmp_len);
        delete[] tmp;

        return iv;
    }

    void ClearExpiredUUID()
    {
        uint64_t ts = time(0);
        for (auto it = m_Time_2_UUID.begin(); it != m_Time_2_UUID.end(); )
        {
            if (it->first > ts)
            {
                break;
            }
            std::for_each(it->second.begin(), it->second.end(), [&](const uint64_t& uuid){m_UUID.erase(uuid);});
            m_Time_2_UUID.erase(it++);
        }
    }
};

}
