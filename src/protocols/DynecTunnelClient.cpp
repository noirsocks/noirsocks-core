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

#include <cstdio>
#include <ctime>
#include "ErrorCodes.h"
#include "Logger.h"
#include "CommUtils.h"
#include "DynecTunnelClient.h"
#include "Dynec_Utils.h"
#include "ServerBase.h"

namespace NoirSocks
{

namespace Protocol
{

bool DynecTunnelClient::CheckProtocolConf(const NextNode& node, std::string& err_msg)
{
    if (node.psk.empty())
    {
        err_msg = "no psk";
        return false;
    }
    if (node.dynamic_iv_interval <= 0)
    {
        err_msg = "dynamic_iv_interval not configured";
        return false;
    }
    return true;
}

ProtocolPtr DynecTunnelClient::CreateProtocol(const NextNode& node)
{
    return std::make_shared<DynecTunnelClient>(node);
}

void DynecTunnelClient::FeedReadData(std::string data)
{
    if (m_Stage < 3)
    {
        m_Buf += std::move(DecryptData(std::move(data)));
    }
    if (m_Stage == 1) //还未获取rsp_head_block
    {
        if (m_Buf.size() >= 20)
        {
            unsigned char hash[16];
            unsigned int tmp_len;
            HMAC(EVP_md5(), m_SessionIV, 16, (const unsigned char*)(m_Buf.c_str() + 16), 4, hash, &tmp_len);

            if (memcmp(m_Buf.c_str(), hash, 16))
            {
                ERROR_LOG("Socket %llu first rsp head block corrupt", m_ID);
                throw ProtocolError(-11001, "first rsp head block corrupt");
            }

            m_RspHeadLen = CommUtils::read32(m_Buf.c_str() + 16) & 0xFFFF;
            DEBUG_LOG("Socket %llu rsp head len = %u", m_ID, m_RspHeadLen);
            m_Stage = 2;
        }
    }
    if (m_Stage == 2) //获取了rsp_head_block，但是还没有收完第一个rsp包
    {
        if (m_Buf.size() >= m_RspHeadLen + 20 + 32)
        {
            unsigned char hash[32];
            unsigned int tmp_len;
            HMAC(EVP_sha256(), m_SessionIV, 16, (const unsigned char*)(m_Buf.c_str()), m_RspHeadLen + 20, hash, &tmp_len);

            if (memcmp(m_Buf.c_str() + m_RspHeadLen + 20, hash, 32))
            {
                ERROR_LOG("Socket %llu first rsp head data corrupt", m_ID);
                throw ProtocolError(-11001, "first rsp head data corrupt");
            }

            //读取conn_rsp
            const unsigned char* head_data = (const unsigned char*)(m_Buf.c_str() + 20);
            unsigned char padding_len = *head_data; ++head_data;
            head_data += padding_len;

            uint16_t conn_ret_raw = CommUtils::read16(head_data); head_data += 2;
            int16_t conn_ret = *(int16_t*)(&conn_ret_raw);
            uint16_t exit_port = CommUtils::read16(head_data); head_data += 2;
            std::string exit_addr((const char*)head_data, (size_t)(m_RspHeadLen - padding_len - 5));

            DEBUG_LOG("Socket %llu got a conn_rsp. ret=%d port=%u addr=%s", m_ID, (int32_t)conn_ret, (uint32_t)exit_port, exit_addr.c_str());
            m_CBConnRsp(conn_ret, std::move(exit_addr), exit_port);

            if (m_Buf.size() > m_RspHeadLen + 20 + 32)
            {
                m_CBRead(m_Buf.substr(m_RspHeadLen + 20 + 32));
            }
            m_Buf.clear();
            m_Stage = 3;
        }
    }
    else if (m_Stage == 3) //已经获取了第一个rsp包，进入正常转发状态
    {
        m_CBRead(DecryptData(std::move(data)));
    }
}

std::string DynecTunnelClient::DecryptData(std::string data)
{
    unsigned char* dec = new unsigned char[data.size()];
    AES_cfb128_encrypt((const unsigned char*)data.c_str(), dec, data.size(), &m_SessionKey, m_ReadIV, &m_ReadN, AES_DECRYPT);
    std::string dec_data((char*)dec, data.size());
    delete[] dec;

    return std::move(dec_data);
}

void DynecTunnelClient::FeedWriteData(std::string data)
{
    unsigned char* enc = new unsigned char[data.size()];
    AES_cfb128_encrypt((const unsigned char*)data.c_str(), enc, data.size(), &m_SessionKey, m_WriteIV, &m_WriteN, AES_ENCRYPT);
    std::string enc_data((char*)enc, data.size());
    delete[] enc;

    m_CBWrite(std::move(enc_data));
}

void DynecTunnelClient::FeedConnReq(const std::string& host, uint16_t port, int conn_type)
{
    uint64_t n_ts = Dynec_Utils::GetInstance().NormalizeTs(time(0), m_Conf.dynamic_iv_interval);
    DEBUG_LOG("Socket %llu getting dyn_iv psk=%s n_ts=%llu", m_ID, m_Conf.psk.c_str(), n_ts);

    unsigned char dyn_iv[16];
    memcpy(dyn_iv, Dynec_Utils::GetInstance().GetDynIV(m_Conf.psk, n_ts).ivec, 16);

    //生成session_key & session_iv
    size_t session_key_len = CommUtils::Rand(32, 255);

    std::string session_key;
    session_key.reserve(session_key_len);

    for (size_t i = 0; i < session_key_len; ++i)
    {
        session_key.push_back(CommUtils::Rand(0, 0xFF));
    }

    Dynec_Utils::GetInstance().GetSessionIV(session_key, dyn_iv, m_SessionIV);
    memcpy(m_ReadIV, m_SessionIV, 16);
    memcpy(m_WriteIV, m_SessionIV, 16);

    unsigned char md_skey[32];
    SHA256((const unsigned char*)session_key.c_str(), session_key.size(), md_skey);
    AES_set_encrypt_key(md_skey, 128, &m_SessionKey);

    DEBUG_LOG("Socket %llu session_key_len=%u", m_ID, (uint32_t)session_key_len);

    //计算各个大小
    uint32_t head_data_len = 8 /*uuid*/ + 1 /*key len*/ + session_key_len + 3 /*conn_type + port*/ + host.size();
    size_t conn_req_len = head_data_len + 20 /*head block*/ + 32 /*tail hash*/;

    if (head_data_len > 0xFFFF)
    {
        ERROR_LOG("Socket %llu head_data_len too long : %u bytes", m_ID, head_data_len);
        m_CBConnRsp(EC_DYNEC_HEAD_TOO_LONG, "", 0);
        return;
    }

    //计算uuid
    uint64_t uuid = Dynec_Utils::GetInstance().GetUUID(GetServerInstance()->GetConf().id);
    DEBUG_LOG("Socket %llu uuid=%llX", m_ID, uuid);

    //分配临时内存
    unsigned char* raw_req = new unsigned char[conn_req_len];

    //生成head block
    unsigned int tmp_len = 0;
    uint32_t head_len_with_salt = (CommUtils::Rand(0x0101, 0xFFFF) << 16) | head_data_len;
    CommUtils::write32(raw_req + 16, head_len_with_salt);
    HMAC(EVP_md5(), dyn_iv, 16, raw_req + 16, 4, raw_req, &tmp_len);

    //填充head data
    unsigned char* head_data = raw_req + 20;
    CommUtils::write64(head_data, uuid); head_data += 8;
    *head_data = session_key_len; ++head_data;
    memcpy(head_data, session_key.c_str(), session_key_len); head_data += session_key_len;
    *head_data = conn_type; ++head_data;
    CommUtils::write16(head_data, port); head_data += 2;
    memcpy(head_data, host.c_str(), host.size());

    //计算tail hash
    HMAC(EVP_sha256(), dyn_iv, 16, raw_req, head_data_len + 20, raw_req + head_data_len + 20, &tmp_len);

    //整体加密
    const AES_KEY* key = Dynec_Utils::GetInstance().GetEncryptKey(m_Conf.psk);
    unsigned char* enc_req = new unsigned char[conn_req_len];
    int num = 0;
    AES_cfb128_encrypt(raw_req, enc_req, conn_req_len, key, dyn_iv, &num, AES_ENCRYPT);
    delete[] raw_req;

    //回收临时内存&回调写数据
    std::string conn_req((char*)enc_req, conn_req_len);
    delete[] enc_req;

    m_CBWrite(std::move(conn_req));
}

};

};
