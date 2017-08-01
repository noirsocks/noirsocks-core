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
#include "ServerImp.h"
#include "DynecTunnelServer.h"
#include "Dynec_Utils.h"

namespace NoirSocks
{

namespace Protocol
{

bool DynecTunnelServer::CheckProtocolConf(const LocalService& svc, std::string& err_msg)
{
    if (svc.psk.empty())
    {
        err_msg = "no psk";
        return false;
    }
    if (svc.dynamic_iv_interval <= 0)
    {
        err_msg = "dynamic_iv_interval not configured";
        return false;
    }
    return true;
}

ProtocolPtr DynecTunnelServer::CreateProtocol(const LocalService& svc)
{
    return std::make_shared<DynecTunnelServer>(svc);
}

void DynecTunnelServer::OnTimer(std::string msg)
{
    uint64_t average_rsp_size = Dynec_Utils::GetInstance().GetAverageHandshakeRspSize();

    average_rsp_size = std::max<uint64_t>(average_rsp_size, 10) - 10;
    average_rsp_size += CommUtils::Rand(1, 20);

    DEBUG_LOG("Socket %llu ready to send %llu bytes of random data", m_ID, average_rsp_size);

    std::string random_data;
    random_data.reserve(average_rsp_size);

    for (size_t i = 0; i < average_rsp_size; ++i)
    {
        unsigned char ch = CommUtils::Rand(0, 255);
        random_data.push_back(*(char*)(&ch));
    }

    m_CBWrite(std::move(random_data));

    throw ProtocolError(12000, std::move(msg));
}

void DynecTunnelServer::FeedReadData(std::string data)
{
    if (m_GotBadRequest) return;
    if (m_Stage < 3)
    {
        m_Buf += data;
    }
    if (m_Stage == 1) //需要尝试正确的dyn_iv以及获取客户端握手包长度
    {
        if (m_Buf.size() >= 20)
        {
            uint64_t ts_1 = Dynec_Utils::GetInstance().NormalizeTs(time(0), m_Conf.dynamic_iv_interval);
            uint64_t ts_2 = ts_1 - m_Conf.dynamic_iv_interval;
            uint64_t ts_3 = ts_1 + m_Conf.dynamic_iv_interval;

            if (!TryGetDynIV(ts_1) && !TryGetDynIV(ts_2) && !TryGetDynIV(ts_3))
            {
                ERROR_LOG("Socket %llu get dyn_iv failed. bad request from client %s:%u", m_ID, m_RemoteHost.c_str(), (uint32_t)m_RemotePort);
                GetServerImpInstance()->ReportRemoteHostBadRequest(m_RemoteHost);
                m_CBSetTimer(Dynec_Utils::GetInstance().GetAverageHandshakeCostMs(), "get dyn_iv failed");
                m_GotBadRequest = true;
                return;
            }

            m_Stage = 2;
        }
    }
    if (m_Stage == 2) //已经获得了头部大小和dyn_iv，需要获取连接目标和session_key
    {
        size_t req_packet_len = m_ReqHeadLen + 20 + 32;
        if (m_Buf.size() >= req_packet_len)
        {
            //解密
            const AES_KEY* key = Dynec_Utils::GetInstance().GetEncryptKey(m_Conf.psk);
            unsigned char iv_enc[16];
            memcpy(iv_enc, m_DynIV, 16);
            unsigned char* dec_buf = new unsigned char[req_packet_len];
            int n = 0;
            AES_cfb128_encrypt((const unsigned char*)m_Buf.c_str(), dec_buf, req_packet_len, key, iv_enc, &n, AES_DECRYPT);

            //整体hash
            unsigned char hash[32];
            unsigned int tmp_len = 0;
            HMAC(EVP_sha256(), m_DynIV, 16, dec_buf, m_ReqHeadLen + 20, hash, &tmp_len);

            if (memcmp(dec_buf + m_ReqHeadLen + 20, hash, 32))
            {
                ERROR_LOG("Socket %llu first request data corrupt. bad request from client %s:%u", m_ID, m_RemoteHost.c_str(), (uint32_t)m_RemotePort);
                GetServerImpInstance()->ReportRemoteHostBadRequest(m_RemoteHost);
                delete[] dec_buf;
                m_CBSetTimer(Dynec_Utils::GetInstance().GetAverageHandshakeCostMs(), "client req hash failed");
                m_GotBadRequest = true;
                return;
            }

            //检查是否有足够的空间读取UUID
            if (m_ReqHeadLen <= 8)
            {
                ERROR_LOG("Socket %llu req head len too small : %u . bad request from client %s:%u",
                    m_ID, m_ReqHeadLen, m_RemoteHost.c_str(), (uint32_t)m_RemotePort);
                GetServerImpInstance()->ReportRemoteHostBadRequest(m_RemoteHost);
                delete[] dec_buf;
                m_CBSetTimer(Dynec_Utils::GetInstance().GetAverageHandshakeCostMs(), "client req uuid repeat");
                m_GotBadRequest = true;
                return;
            }

            //读取并检查uuid，防止重放
            unsigned char* head_data = dec_buf + 20;
            uint64_t uuid = CommUtils::read64(head_data); head_data += 8;

            DEBUG_LOG("Socket %llu got a request with uuid=%llx", m_ID, uuid);

            if (Dynec_Utils::GetInstance().CheckUUIDRepeat(uuid, m_UUID_Ts + m_Conf.dynamic_iv_interval * 2))
            {
                ERROR_LOG("Socket %llu uuid %llx repeat. bad request from client %s:%u", m_ID, uuid, m_RemoteHost.c_str(), (uint32_t)m_RemotePort);
                GetServerImpInstance()->ReportRemoteHostBadRequest(m_RemoteHost);
                delete[] dec_buf;
                m_CBSetTimer(Dynec_Utils::GetInstance().GetAverageHandshakeCostMs(), "client req uuid repeat");
                m_GotBadRequest = true;
                return;
            }

            //读取session key和conn_req
            unsigned char session_key_len = *head_data; ++head_data;

            if (m_ReqHeadLen <= session_key_len + 12)
            {
                ERROR_LOG("Socket %llu req head len too small : %u . bad request from client %s:%u",
                    m_ID, m_ReqHeadLen, m_RemoteHost.c_str(), (uint32_t)m_RemotePort);
                GetServerImpInstance()->ReportRemoteHostBadRequest(m_RemoteHost);
                delete[] dec_buf;
                m_CBSetTimer(Dynec_Utils::GetInstance().GetAverageHandshakeCostMs(), "client req uuid repeat");
                m_GotBadRequest = true;
                return;
            }

            std::string session_key((const char*)head_data, (size_t)session_key_len);
            head_data += session_key_len;
            unsigned char conn_type = *head_data; ++head_data;
            uint16_t port = CommUtils::read16(head_data); head_data += 2;
            std::string host((const char*)head_data, (size_t)(m_ReqHeadLen - session_key_len - 12));

            DEBUG_LOG("Socket %llu got a conn_req to %s:%u type=%d session_key_len=%u", m_ID, host.c_str(), (uint32_t)port, (int)conn_type, (uint32_t)session_key_len);

            //计算session_iv
            Dynec_Utils::GetInstance().GetSessionIV(session_key, m_DynIV, m_SessionIV);
            memcpy(m_ReadIV, m_SessionIV, 16);
            memcpy(m_WriteIV, m_SessionIV, 16);

            unsigned char md_skey[32];
            SHA256((const unsigned char*)session_key.c_str(), session_key.size(), md_skey);
            AES_set_encrypt_key(md_skey, 128, &m_SessionKey);

            delete[] dec_buf;

            m_ConnReqTs = ClockType::now();

            m_CBConnReq(std::move(host), port, conn_type);

            if (m_Buf.size() > req_packet_len)
            {
                m_CBRead(DecryptData(m_Buf.substr(req_packet_len)));
            }
            m_Buf.clear();
            m_Stage = 3;
        }
    }
    else if (m_Stage == 3)
    {
        m_CBRead(DecryptData(std::move(data)));
    }
}

bool DynecTunnelServer::TryGetDynIV(uint64_t ts)
{
    DEBUG_LOG("Socket %llu trying ts %llu to get dyn_iv ...", m_ID, ts);

    unsigned char iv[16];
    unsigned char iv_enc[16];

    memcpy(iv, Dynec_Utils::GetInstance().GetDynIV(m_Conf.psk, ts).ivec, 16);
    memcpy(iv_enc, iv, 16);

    const AES_KEY* key = Dynec_Utils::GetInstance().GetEncryptKey(m_Conf.psk);
    unsigned char dec_buf[20];
    int n = 0;
    AES_cfb128_encrypt((const unsigned char*)m_Buf.c_str(), dec_buf, 20, key, iv_enc, &n, AES_DECRYPT);

    unsigned char hash[16];
    unsigned int tmp_len = 0;
    HMAC(EVP_md5(), iv, 16, dec_buf + 16, 4, hash, &tmp_len);

    bool match = (memcmp(hash, dec_buf, 16) == 0);

    if (match)
    {
        m_UUID_Ts = ts;
        m_ReqHeadLen = CommUtils::read32(dec_buf + 16) & 0xFFFF;
        memcpy(m_DynIV, iv, 16);
        DEBUG_LOG("Socket %llu successfully matched dyn_iv with ts=%llu req_head_len=%u", m_ID, ts, m_ReqHeadLen);
    }
    else
    {
        DEBUG_LOG("Socket %llu failed to match dyn_iv with ts=%llu", m_ID, ts);
    }

    return match;
}

std::string DynecTunnelServer::DecryptData(std::string data)
{
    unsigned char* dec = new unsigned char[data.size()];
    AES_cfb128_encrypt((const unsigned char*)data.c_str(), dec, data.size(), &m_SessionKey, m_ReadIV, &m_ReadN, AES_DECRYPT);
    std::string dec_data((char*)dec, data.size());
    delete[] dec;

    return std::move(dec_data);
}

void DynecTunnelServer::FeedWriteData(std::string data)
{
    if (m_Stage <= 2) return;

    unsigned char* enc = new unsigned char[data.size()];
    AES_cfb128_encrypt((const unsigned char*)data.c_str(), enc, data.size(), &m_SessionKey, m_WriteIV, &m_WriteN, AES_ENCRYPT);
    std::string enc_data((char*)enc, data.size());
    delete[] enc;

    m_CBWrite(std::move(enc_data));
}

void DynecTunnelServer::FeedConnRsp(int result, const std::string& host, uint16_t port)
{
    if (m_Stage <= 2)
    {
        ERROR_LOG("Socket %llu FeedConnRsp before get session key from client", m_ID);
        throw ProtocolError(-12101, "session_key expected before FeedConnRsp");
    }

    //计算各个大小
    size_t padding_len = CommUtils::Rand(32, 255);
    uint32_t head_data_len = 1 + padding_len + 4 + host.size();
    size_t packet_len = 20 + head_data_len + 32;

    Dynec_Utils::GetInstance().ReportHandshakeCostMs(std::chrono::duration_cast<std::chrono::milliseconds>(ClockType::now() - m_ConnReqTs).count());
    Dynec_Utils::GetInstance().ReportHandshakeRspSize(packet_len);

    unsigned char* raw_rsp = new unsigned char[packet_len];

    //填充head_block
    unsigned int tmp_len = 0;
    uint32_t head_len_with_salt = (CommUtils::Rand(0x0101, 0xFFFF) << 16) | (head_data_len & 0xFFFF);
    CommUtils::write32(raw_rsp + 16, head_len_with_salt);
    HMAC(EVP_md5(), m_SessionIV, 16, raw_rsp + 16, 4, raw_rsp, &tmp_len);

    //填充head_data
    unsigned char* head_data = raw_rsp + 20;
    *head_data = padding_len & 0xFF; ++head_data;
    while (padding_len--)
    {
        *head_data = CommUtils::Rand(0, 0xFF);
        ++head_data;
    }
    int16_t result_16 = result;
    CommUtils::write16(head_data, *(uint16_t*)(&result_16)); head_data += 2;
    CommUtils::write16(head_data, port); head_data += 2;
    memcpy(head_data, host.c_str(), host.size());

    //整体hash
    HMAC(EVP_sha256(), m_SessionIV, 16, raw_rsp, head_data_len + 20, raw_rsp + head_data_len + 20, &tmp_len);

    //整体加密
    unsigned char* enc = new unsigned char[packet_len];
    AES_cfb128_encrypt(raw_rsp, enc, packet_len, &m_SessionKey, m_WriteIV, &m_WriteN, AES_ENCRYPT);
    std::string enc_data((char*)enc, packet_len);
    delete[] enc;
    delete[] raw_rsp;

    m_CBWrite(std::move(enc_data));
}

}

}
