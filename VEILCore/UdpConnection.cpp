//	Copyright (c) 2018, TecSec, Inc.
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are met:
//	
//		* Redistributions of source code must retain the above copyright
//		  notice, this list of conditions and the following disclaimer.
//		* Redistributions in binary form must reproduce the above copyright
//		  notice, this list of conditions and the following disclaimer in the
//		  documentation and/or other materials provided with the distribution.
//		* Neither the name of TecSec nor the names of the contributors may be
//		  used to endorse or promote products derived from this software 
//		  without specific prior written permission.
//		 
//	ALTERNATIVELY, provided that this notice is retained in full, this product
//	may be distributed under the terms of the GNU General Public License (GPL),
//	in which case the provisions of the GPL apply INSTEAD OF those given above.
//		 
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
//	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Written by Roger Butler

#include "stdafx.h"

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif // MIN
#pragma region support functions
extern const char *resolveSocketError(uint32_t error);
#pragma endregion

UdpConnection::UdpConnection() :
    m_WSAinitialized(false),
    m_isConnected(false),
    m_socket(0),
    m_server("127.0.0.1"),
    m_port(80)
{
    memset(&m_serverInfo, 0, sizeof(struct sockaddr_in));
}
UdpConnection::~UdpConnection(void)
{
    if (m_WSAinitialized)
    {
        Disconnect();
#ifdef _WIN32
        WSACleanup();
#endif
        m_WSAinitialized = false;
    }
}

const tscrypto::tsCryptoString &UdpConnection::Server() const
{
    return m_server;
}
void UdpConnection::Server(const tscrypto::tsCryptoString &setTo)
{
    if (tsStriCmp(m_server.c_str(), setTo.c_str()) != 0)
    {
#ifdef _WIN32
        closesocket(m_socket);
        m_socket = 0;
#else
        if (m_socket != SOCKET::invalid())
            close((int)m_socket);
        m_socket = SOCKET::invalid();
#endif
        m_isConnected = false;
        m_server = setTo;
    }
}

unsigned short UdpConnection::Port() const
{
    return m_port;
}
void UdpConnection::Port(unsigned short setTo)
{
    if (m_port != setTo)
    {
#ifdef _WIN32
        closesocket(m_socket);
        m_socket = 0;
#else
        if (m_socket != SOCKET::invalid())
            close((int)m_socket);
        m_socket = SOCKET::invalid();
#endif
        m_isConnected = false;
        m_port = setTo;
    }
}

tscrypto::tsCryptoString UdpConnection::Errors() const
{
    return m_errors;
}
void UdpConnection::ClearErrors()
{
    m_errors.clear();
}
bool UdpConnection::SendTo(const tscrypto::tsCryptoData& data, const struct sockaddr_storage& To, int toLen)
{
    //	int64_t start = GetTicks();
    //sockaddr_storage toAddr;
    //int len;

#ifdef _WIN32
    if (sendto(m_socket, (const char *)data.c_str(), (int)data.size(), 0, (const sockaddr*)&To, toLen) == SOCKET_ERROR)
#else
    if (sendto((int)m_socket, (const char *)data.c_str(), (int)data.size(), 0, (const sockaddr*)&To, toLen) == SOCKET_ERROR)
#endif
    {
#ifdef _WIN32
        switch (WSAGetLastError())
        {
        case WSAENOTSOCK:
        case WSAENOTCONN:
        case WSAECONNRESET:
        case WSAECONNABORTED:
            closesocket(m_socket);
            m_socket = 0;
            m_isConnected = false;
            if (!Connect() ||
                send(m_socket, (const char *)data.c_str(), (int)data.size(), 0) == SOCKET_ERROR)
            {
                m_errors += "Unable to reconnect and send the request\n";
                return false;
            }
            break;
        default:
            m_errors += "Error ";
            m_errors << WSAGetLastError();
            m_errors += " occurred while attempting to send the request\n";
            return false;
        }
#else
        switch (errno)
        {
        case ENOTSOCK:
        case ENOTCONN:
        case ECONNRESET:
        case ECONNABORTED:
#ifdef _WIN32
            closesocket(m_socket);
            m_socket = 0;
#else
            if (m_socket != SOCKET::invalid())
                close((int)m_socket);
            m_socket = SOCKET::invalid();
#endif
            m_isConnected = false;
#ifdef _WIN32
            if (!Connect() ||
                send(m_socket, data.c_str(), data.size(), 0) == SOCKET_ERROR)
#else
            if (!Connect() ||
                send((int)m_socket, data.c_str(), data.size(), 0) == SOCKET_ERROR)
#endif // _WIN32
            {
                m_errors += "Unable to reconnect and send the request\n";
                //_errorSignals.Fire(this, m_errors);
                return false;
            }

            LOG(httpData, "Raw Sent:" << tscrypto::endl << data.ToHexDump());

            break;
        default:
            m_errors += "Error ";
            m_errors << errno;
            m_errors += " occurred while attempting to send the request\n";
            //_errorSignals.Fire(this, m_errors);
            return false;
        }
#endif
    }

    //LOG(httpLog, "Send in " << (GetTicks() - start) / 1000.0 << " ms");
    LOG(httpData, "Raw Sent:" << tscrypto::endl << data.ToHexDump());
    return true;
}
bool UdpConnection::ReadFrom(struct sockaddr_storage& From, int& fromLen, tscrypto::tsCryptoData& data)
{
    int len;
    tscrypto::tsCryptoData buff;
    //int requiredDataLength = 0;
    int targetLength = 5000;

    data.clear();

    buff.resize(targetLength);

    fromLen = sizeof(struct sockaddr_storage);
#ifdef _WIN32
    len = recvfrom(m_socket, (char*)buff.rawData(), targetLength, MSG_PEEK, (sockaddr*)&From, &fromLen);
#else
    socklen_t frmlen = fromLen;
    len = recvfrom((int)m_socket, (char*)buff.rawData(), targetLength, MSG_PEEK, (sockaddr*)&From, &frmlen);
    fromLen = frmlen;
#endif

    //
    // Is there data in the buffer?
    //
    if (len > 0)
    {
        //
        // Get it
        //
#ifdef _WIN32
        len = recvfrom(m_socket, (char*)buff.rawData(), len, 0, (sockaddr*)&From, &fromLen);
#else
        len = recvfrom((int)m_socket, (char*)buff.rawData(), len, 0, (sockaddr*)&From, &frmlen);
        fromLen = frmlen;
#endif
        if (len > 0)
        {
            buff.resize(len);

            LOG(httpData, "recv'd" << tscrypto::endl << buff.ToHexDump());

            if (buff.size() > 0)
            {
                data += buff.ToUtf8String();
            }
            return true;
        }
        else if (len == SOCKET_ERROR)
            return false;
        else
        {
            m_errors += "Unable to read the data from the socket\n";
            //
            // Data retrieval error (should never happen)
            //
            return false;
        }
    }
    else
    {
        return true;
    }
}

bool UdpConnection::isConnected() const
{
    if (!m_isConnected)
        return false;

    if (!isWSAInitialized())
        return false;

#ifdef _WIN32
    if (SOCKET_ERROR == send(m_socket, "", 0, 0))
#else
    if (SOCKET_ERROR == send((int)m_socket, "", 0, 0))
#endif
    {
        m_isConnected = false;
        return false;
    }
    return true;
}
bool UdpConnection::Disconnect()
{
    if (m_isConnected)
    {
#ifdef _WIN32
        if (closesocket(m_socket) == SOCKET_ERROR)
        {
            LOG(FrameworkInfo1, "Unable to close the socket");
            m_errors += "Unable to close the socket\n";
            closesocket(m_socket);
            m_socket = 0;
            m_isConnected = false;
            return false;
        }
#else
        if (m_socket != INVALID_SOCKET)
        {
            if (close((int)m_socket) == SOCKET_ERROR)
            {
                LOG(FrameworkInfo1, "Unable to close the socket");
                m_errors += "Unable to close the socket\n";
                m_socket = INVALID_SOCKET;
                m_isConnected = false;
                return false;
            }
        }
#endif
        m_socket = INVALID_SOCKET;
    }
    m_isConnected = false;
    return true;
}
bool UdpConnection::resolveAddress(const tscrypto::tsCryptoStringBase& address, const tscrypto::tsCryptoStringBase& port, struct sockaddr_storage& sockAddr, int & addrLen, int socketType, int family)
{
    struct addrinfo hints, *res, *p;
    int status;
    const char *addr = nullptr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = socketType;

    hints.ai_family = family;

    if (address.size() > 0 && address != "*")
    {
        addr = address.c_str();
    }
    else
    {
        hints.ai_flags = AI_PASSIVE;
    }
    if ((status = getaddrinfo(addr, port.c_str(), &hints, &res)) != 0)
    {
        return false;
    }
    for (p = res; p != nullptr; p = p->ai_next)
    {
        memcpy(&sockAddr, p->ai_addr, p->ai_addrlen);
        addrLen = (int)p->ai_addrlen;
        freeaddrinfo(res);
        return true;
    }
    freeaddrinfo(res);
    return false;
}

bool UdpConnection::addressToString(const struct sockaddr* addr, int addrlen, tscrypto::tsCryptoString& outString)
{
    char port[NI_MAXSERV] = { 0, };
    char serv[NI_MAXHOST] = { 0, };
    outString.clear();
    if (addr == nullptr)
        return false;

    if (getnameinfo((const struct sockaddr *)addr, addrlen, serv, sizeof(serv), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV) != 0)
    {
        return false;
    }
    outString << serv << ":" << port;
    return true;
}
bool UdpConnection::Connect()
{
    if (m_isConnected)
        return true;

    struct addrinfo hints, *res, *p;
    int status;
    tscrypto::tsCryptoString portStr;
    const char *addr = nullptr;

    if (!WSAInitialize())
        return false;

    if (m_isConnected)
        return true;


    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;

    hints.ai_family = AF_UNSPEC;

    portStr << m_port;

    if (m_server.size() > 0 && m_server != "*")
    {
        addr = m_server.c_str();
    }
    else
    {
        hints.ai_flags = AI_PASSIVE;
    }
    if ((status = getaddrinfo(addr, portStr.c_str(), &hints, &res)) != 0)
    {
        LOG(FrameworkError, "Unable to resolve the specified network address.  " << addr << ":" << portStr);
        m_errors << "An error occurred while attempting to resolve that IP address.\n";
        return false;
    }
    for (p = res; p != nullptr; p = p->ai_next)
    {
        char ipstr[512];

        if (p->ai_family == AF_INET)
        {
            inet_ntop(p->ai_family, (void*)&(((struct sockaddr_in*)p->ai_addr)->sin_addr), ipstr, sizeof(ipstr));
            //addrSize = (int)sizeof(struct sockaddr_in);
        }
        else
        {
            inet_ntop(p->ai_family, (void*)&(((struct sockaddr_in6*)p->ai_addr)->sin6_addr), ipstr, sizeof(ipstr));
            //addrSize = (int)sizeof(struct sockaddr_in6);
        }
#ifdef _WIN32
        m_socket = WSASocketW(p->ai_family, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
#else
        m_socket = (SOCKET)socket(p->ai_family, SOCK_DGRAM, IPPROTO_UDP);
#endif
        if (m_socket == INVALID_SOCKET)
        {
#ifdef _WIN32
            LOG(FrameworkError, "server listener socket() failed on addr " << ipstr << ":" << portStr << " with error '" << resolveSocketError(WSAGetLastError()) << "' [" << WSAGetLastError() << "]");
#else
            LOG(FrameworkError, "server listener socket() failed on addr " << ipstr << ":" << portStr << " with error '" << errno << "'");
#endif
            closesocket(m_socket);
            m_socket = INVALID_SOCKET;
        }
        else
        {
            memcpy(&m_serverInfo, p->ai_addr, p->ai_addrlen);

#ifndef _WIN32
            if (bind((int)m_socket, p->ai_addr, (int)p->ai_addrlen) == SOCKET_ERROR)
#else
            if (bind(m_socket, p->ai_addr, (int)p->ai_addrlen) == SOCKET_ERROR)
#endif
            {
#ifdef _WIN32
                LOG(FrameworkInfo1, "Unable to bind to the socket [" << WSAGetLastError() << " - " << ipstr << ":" << portStr << "]");
#else
                LOG(FrameworkInfo1, "Unable to bind to the socket [" << errno << " - " << m_server << " - " << m_port << "]");
#endif
                if (m_socket != INVALID_SOCKET)
                    closesocket(m_socket);
                m_socket = INVALID_SOCKET;
                continue;
            }
            m_isConnected = true;
            freeaddrinfo(res);
            return true;
        }
    }
    freeaddrinfo(res);
    m_errors += "Unable to resolve IP address\n";
    return false;
}

bool UdpConnection::isWSAInitialized() const
{
    if (m_WSAinitialized)
        return true;

    return false;
}
bool UdpConnection::WSAInitialize()
{
#ifdef _WIN32
    WSADATA wsaData;
#endif

    if (isWSAInitialized())
        return true;

#ifdef _WIN32
    if (WSAStartup(0x202, &wsaData) != 0)
    {
        m_errors += "Unable to start the WSA sockets system\n";
        return false;
    }
#endif
    m_WSAinitialized = true;
    return true;
}
void UdpConnection::flushBuffer()
{
    ////    int len;
    ////    char buff[1024];
    ////
    ////    while ((len = recv(m_socket, buff, sizeof(buff), MSG_PEEK)) > 0)
    ////    {
    ////        if ( recv(m_socket, buff, len, 0) == SOCKET_ERROR )
    ////			return;
    ////    }
}

std::shared_ptr<IUdpConnection> CreateUdpConnection()
{
    return ::TopServiceLocator()->Finish<IUdpConnection>(new UdpConnection());
}
