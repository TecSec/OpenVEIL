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

#ifdef _WIN32
static struct SocketErrors
{
	uint32_t number;
	const char *value;
} gSocketErrors[] =
{
	{ WSAEINTR, "A blocking operation was interrupted by a call to WSACancelBlockingCall." },
	{ WSAEBADF, "The file handle supplied is not valid." },
	{ WSAEACCES, "An attempt was made to access a socket in a way forbidden by its access permissions." },
	{ WSAEFAULT, "The system detected an invalid pointer address in attempting to use a pointer argument in a call." },
	{ WSAEINVAL, " An invalid argument was supplied." },
	{ WSAEMFILE, "Too many open sockets." },

	/*
	* Windows Sockets definitions of regular Berkeley error constants
	*/
	{ WSAEWOULDBLOCK, "A non-blocking socket operation could not be completed immediately." },
	{ WSAEINPROGRESS, "A blocking operation is currently executing." },
	{ WSAEALREADY, "An operation was attempted on a non-blocking socket that already had an operation in progress." },
	{ WSAENOTSOCK, "An operation was attempted on something that is not a socket." },
	{ WSAEDESTADDRREQ, "A required address was omitted from an operation on a socket." },
	{ WSAEMSGSIZE, "A message sent on a datagram socket was larger than the internal message buffer or some other network limit, or the buffer used to receive a datagram into was smaller than the datagram itself." },
	{ WSAEPROTOTYPE, "A protocol was specified in the socket function call that does not support the semantics of the socket type requested." },
	{ WSAENOPROTOOPT, "An unknown, invalid, or unsupported option or level was specified in a getsockopt or setsockopt call." },
	{ WSAEPROTONOSUPPORT, "The requested protocol has not been configured into the system, or no implementation for it exists." },
	{ WSAESOCKTNOSUPPORT, "The support for the specified socket type does not exist in this address family." },
	{ WSAEOPNOTSUPP, "The attempted operation is not supported for the type of object referenced." },
	{ WSAEPFNOSUPPORT, "The protocol family has not been configured into the system or no implementation for it exists." },
	{ WSAEAFNOSUPPORT, "An address incompatible with the requested protocol was used." },
	{ WSAEADDRINUSE, "Only one usage of each socket address (protocol/network address/port) is normally permitted." },
	{ WSAEADDRNOTAVAIL, "The requested address is not valid in its context." },
	{ WSAENETDOWN, "A socket operation encountered a dead network." },
	{ WSAENETUNREACH, "A socket operation was attempted to an unreachable network." },
	{ WSAENETRESET, "The connection has been broken due to keep-alive activity detecting a failure while the operation was in progress." },
	{ WSAECONNABORTED, "An established connection was aborted by the software in your host machine." },
	{ WSAECONNRESET, "An existing connection was forcibly closed by the remote host." },
	{ WSAENOBUFS, "An operation on a socket could not be performed because the system lacked sufficient buffer space or because a queue was full." },
	{ WSAEISCONN, "A connect request was made on an already connected socket." },
	{ WSAENOTCONN, "A request to send or receive data was disallowed because the socket is not connected and (when sending on a datagram socket using a sendto call) no address was supplied." },
	{ WSAESHUTDOWN, "A request to send or receive data was disallowed because the socket had already been shut down in that direction with a previous shutdown call." },
	{ WSAETOOMANYREFS, "Too many references to some kernel object." },
	{ WSAETIMEDOUT, "A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond." },
	{ WSAECONNREFUSED, "No connection could be made because the target machine actively refused it." },
	{ WSAELOOP, "Cannot translate name." },
	{ WSAENAMETOOLONG, "Name component or name was too long." },
	{ WSAEHOSTDOWN, "A socket operation failed because the destination host was down." },
	{ WSAEHOSTUNREACH, "A socket operation was attempted to an unreachable host." },
	{ WSAENOTEMPTY, "Cannot remove a directory that is not empty." },
	{ WSAEPROCLIM, "A Windows Sockets implementation may have a limit on the number of applications that may use it simultaneously." },
	{ WSAEUSERS, "Ran out of quota." },
	{ WSAEDQUOT, "Ran out of disk quota." },
	{ WSAESTALE, "File handle reference is no longer available." },
	{ WSAEREMOTE, "Item is not available locally." },

	/*
	* Extended Windows Sockets error constant definitions
	*/
	{ WSASYSNOTREADY, "WSAStartup cannot function at this time because the underlying system it uses to provide network services is currently unavailable." },
	{ WSAVERNOTSUPPORTED, "The Windows Sockets version requested is not supported." },
	{ WSANOTINITIALISED, "Either the application has not called WSAStartup, or WSAStartup failed." },
	{ WSAEDISCON, "Returned by WSARecv or WSARecvFrom to indicate the remote party has initiated a graceful shutdown sequence." },
	{ WSAENOMORE, "No more results can be returned by WSALookupServiceNext." },
	{ WSAECANCELLED, "A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled." },
	{ WSAEINVALIDPROCTABLE, "The procedure call table is invalid." },
	{ WSAEINVALIDPROVIDER, "The requested service provider is invalid." },
	{ WSAEPROVIDERFAILEDINIT, "The requested service provider could not be loaded or initialized." },
	{ WSASYSCALLFAILURE, "A system call has failed." },
	{ WSASERVICE_NOT_FOUND, "No such service is known. The service cannot be found in the specified name space." },
	{ WSATYPE_NOT_FOUND, "The specified class was not found." },
	{ WSA_E_NO_MORE, "No more results can be returned by WSALookupServiceNext." },
	{ WSA_E_CANCELLED, "A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled." },
	{ WSAEREFUSED, "A database query failed because it was actively refused." },

	/*
	* Error return codes from gethostbyname() and gethostbyaddr()
	* (when using the resolver). Note that these errors are
	* retrieved via WSAGetLastError() and must therefore follow
	* the rules for avoiding clashes with error numbers from
	* specific implementations or language run-time systems.
	* For this reason the codes are based at WSABASEERR+1001.
	* Note also that [WSA]NO_ADDRESS is defined only for
	* compatibility purposes.
	*/

	{ WSAHOST_NOT_FOUND, "Authoritative Answer: Host not found" },
	{ WSATRY_AGAIN, "Non-Authoritative: Host not found, or SERVERFAIL" },
	{ WSANO_RECOVERY, "Non - recoverable errors, FORMERR, REFUSED, NOTIMP" },
	{ WSANO_DATA, "Valid name, no data record of requested type" },

	/*
	* Define QOS related error return codes
	*
	*/
	{ WSA_QOS_RECEIVERS, "at least one Reserve has arrived" },
	{ WSA_QOS_SENDERS, "at least one Path has arrived" },
	{ WSA_QOS_NO_SENDERS, "there are no senders" },
	{ WSA_QOS_NO_RECEIVERS, "there are no receivers" },
	{ WSA_QOS_REQUEST_CONFIRMED, "Reserve has been confirmed" },
	{ WSA_QOS_ADMISSION_FAILURE, "error due to lack of resources" },
	{ WSA_QOS_POLICY_FAILURE, "rejected for administrative reasons - bad credentials" },
	{ WSA_QOS_BAD_STYLE, "unknown or conflicting style" },
	{ WSA_QOS_BAD_OBJECT, "problem with some part of the filterspec or provider specific buffer in general" },
	{ WSA_QOS_TRAFFIC_CTRL_ERROR, "problem with some part of the flowspec" },
	{ WSA_QOS_GENERIC_ERROR, "general error" },
	{ WSA_QOS_ESERVICETYPE, "invalid service type in flowspec" },
	{ WSA_QOS_EFLOWSPEC, "invalid flowspec" },
	{ WSA_QOS_EPROVSPECBUF, "invalid provider specific buffer" },
	{ WSA_QOS_EFILTERSTYLE, "invalid filter style" },
	{ WSA_QOS_EFILTERTYPE, "invalid filter type" },
	{ WSA_QOS_EFILTERCOUNT, "incorrect number of filters" },
	{ WSA_QOS_EOBJLENGTH, "invalid object length" },
	{ WSA_QOS_EFLOWCOUNT, "incorrect number of flows" },
	{ WSA_QOS_EUNKOWNPSOBJ, "unknown object in provider specific buffer" },
	{ WSA_QOS_EPOLICYOBJ, "invalid policy object in provider specific buffer" },
	{ WSA_QOS_EFLOWDESC, "invalid flow descriptor in the list" },
	{ WSA_QOS_EPSFLOWSPEC, "inconsistent flow spec in provider specific buffer" },
	{ WSA_QOS_EPSFILTERSPEC, "invalid filter spec in provider specific buffer" },
	{ WSA_QOS_ESDMODEOBJ, "invalid shape discard mode object in provider specific buffer" },
	{ WSA_QOS_ESHAPERATEOBJ, "invalid shaping rate object in provider specific buffer" },
	{ WSA_QOS_RESERVED_PETYPE, "reserved policy element in provider specific buffer" }
};

const char *resolveSocketError(uint32_t error)
{
	for (int i = 0; i < sizeof(gSocketErrors) / sizeof(gSocketErrors[0]); i++)
	{
		if (gSocketErrors[i].number == error)
			return gSocketErrors[i].value;
	}
	return "unknown socket error";
}
#else
const char *resolveSocketError(uint32_t error)
{
	// TODO:  Implement me
	return "unknown socket error";
}
#endif
#pragma endregion

TcpConnection::TcpConnection() :
	m_WSAinitialized(false),
	m_isConnected(false),
	m_socket(0),
	m_server("127.0.0.1"),
	m_port(80)
{
	memset(&m_serverInfo, 0, sizeof(struct sockaddr_in));
}
TcpConnection::~TcpConnection(void)
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

const tscrypto::tsCryptoString &TcpConnection::Server() const
{
	return m_server;
}
void TcpConnection::Server(const tscrypto::tsCryptoString &setTo)
{
	if (tsStriCmp(m_server.c_str(), setTo.c_str()) != 0)
	{
		if (!!_stack)
		{
			m_receivedDataFromStack.clear();
			_stack.reset();
		}
		else
		{
#ifdef _WIN32
			closesocket(m_socket);
			m_socket = 0;
#else
			if (m_socket != SOCKET::invalid())
				close((int)m_socket);
			m_socket = SOCKET::invalid();
#endif
		}
		m_isConnected = false;
		m_server = setTo;
	}
}

unsigned short TcpConnection::Port() const
{
	return m_port;
}
void TcpConnection::Port(unsigned short setTo)
{
	if (m_port != setTo)
	{
		if (!!_stack)
		{
			m_receivedDataFromStack.clear();
			_stack.reset();
		}
		else
		{
#ifdef _WIN32
			closesocket(m_socket);
			m_socket = 0;
#else
			if (m_socket != SOCKET::invalid())
				close((int)m_socket);
			m_socket = SOCKET::invalid();
#endif
		}
		m_isConnected = false;
		m_port = setTo;
	}
}

tscrypto::tsCryptoString TcpConnection::Errors() const
{
	return m_errors;
}
void TcpConnection::ClearErrors()
{
	m_errors.clear();
}
bool TcpConnection::RawSend(const tscrypto::tsCryptoData& data, ts_bool closeAfterWrite)
{
	//	int64_t start = GetTicks();

	if (!!_stack)
	{
		_stack->QueueReceivedData(data);
	}
	else
	{
#ifdef _WIN32
		if (send(m_socket, (const char *)data.c_str(), (int)data.size(), 0) == SOCKET_ERROR)
#else
		if (send((int)m_socket, (const char *)data.c_str(), (int)data.size(), 0) == SOCKET_ERROR)
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
					_errorSignals.Fire(this, m_errors);
					return false;
				}
				break;
			default:
				m_errors += "Error ";
				m_errors << WSAGetLastError();
				m_errors += " occurred while attempting to send the request\n";
				_errorSignals.Fire(this, m_errors);
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
					_errorSignals.Fire(this, m_errors);
					return false;
				}

				LOG(httpData, "Raw Sent:" << tscrypto::endl << data.ToHexDump());

				break;
			default:
				m_errors += "Error ";
				m_errors << errno;
				m_errors += " occurred while attempting to send the request\n";
				_errorSignals.Fire(this, m_errors);
				return false;
			}
#endif
		}
	}

	//LOG(httpLog, "Send in " << (GetTicks() - start) / 1000.0 << " ms");
	LOG(httpData, "Raw Sent:" << tscrypto::endl << data.ToHexDump());
	return true;
}
bool TcpConnection::RawReceive(tscrypto::tsCryptoData& _data, size_t size)
{
	int len;
	tscrypto::tsCryptoData buff;
	//int requiredDataLength = 0;
	int targetLength = (int)size;

	_data.clear();

	if (!!_stack)
	{
		if (size >= m_receivedDataFromStack.size())
		{
			_data = m_receivedDataFromStack;
			m_receivedDataFromStack.clear();
		}
		else
		{
			_data = m_receivedDataFromStack.substr(0, size);
			m_receivedDataFromStack.erase(0, size);
		}
		return true;
	}
	else
	{
		buff.resize(size);
#ifdef _WIN32
		len = recv(m_socket, (char*)buff.rawData(), targetLength, MSG_PEEK);
#else
		len = recv((int)m_socket, (char*)buff.rawData(), targetLength, MSG_PEEK);
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
			len = recv(m_socket, (char*)buff.rawData(), len, 0);
#else
			len = recv((int)m_socket, (char*)buff.rawData(), len, 0);
#endif
			if (len > 0)
			{
				buff.resize(len);

				LOG(httpData, "recv'd" << tscrypto::endl << buff.ToHexDump());

				if (buff.size() > 0)
				{
					_data += buff.ToUtf8String();
				}
				return true;
			}
			else if (len == SOCKET_ERROR)
				return false;
			else
			{
				m_errors += "Unable to read the data from the socket\n";
				_errorSignals.Fire(this, m_errors);
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
}

bool TcpConnection::isConnected() const
{
	if (!m_isConnected)
		return false;

	if (!!_stack)
	{
		return true;
	}
	else
	{
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
	}
	return true;
}
bool TcpConnection::Disconnect()
{
	if (m_isConnected)
	{
		if (!!_stack)
		{
			_stack->closingConnection();
			_stack->channelShutdown();
			_stack.reset();
		}
		else
		{
#ifdef _WIN32
			if (closesocket(m_socket) == SOCKET_ERROR)
			{
				LOG(FrameworkInfo1, "Unable to close the socket");
				m_errors += "Unable to close the socket\n";
				_errorSignals.Fire(this, m_errors);
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
					_errorSignals.Fire(this, m_errors);
					m_socket = INVALID_SOCKET;
					m_isConnected = false;
					return false;
				}
			}
#endif
			m_socket = INVALID_SOCKET;
		}
		_disconnectSignals.Fire(this);
	}
	m_bufferedData.clear();
	m_isConnected = false;
	return true;
}
bool TcpConnection::Connect()
{
	if (m_isConnected)
		return true;

	if (tsStrniCmp(m_server.c_str(), "local:", 6) == 0)
	{
		tsCryptoString name(m_server);

		name.erase(0, 6);

		_stack = ServiceLocator()->try_get_instance<tsmod::IBaseProtocolStack>(name);
		if (!_stack)
		{
			LOG(FrameworkError, "Unable to resolve the specified local address.  " << m_server);
			m_errors << "An error occurred while attempting to resolve that address.\n";
			_errorSignals.Fire(this, m_errors);
			return false;
		}
		_stack->SetSentDataCallback([this](const tsCryptoData& data) { 
			m_receivedDataFromStack += data; 
		});
		m_server = "localhost";
		m_isConnected = true;
		_connectSignals.Fire(this);
		return true;
	}
	else
	{
		struct addrinfo hints, *res, *p;
		int status;
		tscrypto::tsCryptoString portStr;
		const char *addr = nullptr;

		if (!WSAInitialize())
			return false;

		if (m_isConnected)
			return true;


		m_bufferedData.clear();

		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;

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
			_errorSignals.Fire(this, m_errors);
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
			m_socket = WSASocketW(p->ai_family, p->ai_socktype, p->ai_protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
#else
			m_socket = (SOCKET)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
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

#ifdef _WIN32
				if (connect(m_socket, p->ai_addr /*(sockaddr*)&m_serverInfo*/, (int)p->ai_addrlen) == SOCKET_ERROR)
#else
				if (connect((int)m_socket, p->ai_addr /*(sockaddr*)&m_serverInfo*/, (int)p->ai_addrlen) == SOCKET_ERROR)
#endif
				{
#ifdef _WIN32
					LOG(FrameworkInfo1, "Unable to connect to the socket [" << WSAGetLastError() << " - " << ipstr << ":" << portStr << "]");
#else
					LOG(FrameworkInfo1, "Unable to connect to the socket [" << errno << " - " << m_server << " - " << m_port << "]");
#endif
					if (m_socket != INVALID_SOCKET)
						closesocket(m_socket);
					m_socket = INVALID_SOCKET;
					continue;
				}
				m_isConnected = true;
				freeaddrinfo(res);
				_connectSignals.Fire(this);
				return true;
			}
		}
		freeaddrinfo(res);
		m_errors += "Unable to resolve IP address\n";
		_errorSignals.Fire(this, m_errors);
		return false;
	}
}

bool TcpConnection::isWSAInitialized() const
{
	if (m_WSAinitialized)
		return true;

	return false;
}
bool TcpConnection::WSAInitialize()
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
		_errorSignals.Fire(this, m_errors);
		return false;
	}
#endif
	m_WSAinitialized = true;
	return true;
}
void TcpConnection::flushBuffer()
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

size_t TcpConnection::AddOnConnect(std::function<void(const tsmod::IObject*)> func)
{
	return _connectSignals.Add(func);
}

void TcpConnection::RemoveOnConnect(size_t cookie)
{
	_connectSignals.Remove(cookie);
}

size_t TcpConnection::AddOnError(std::function<void(const tsmod::IObject*, const tscrypto::tsCryptoStringBase&)> func)
{
	return _errorSignals.Add(func);
}

void TcpConnection::RemoveOnError(size_t cookie)
{
	_errorSignals.Remove(cookie);
}

size_t TcpConnection::AddOnDisconnect(std::function<void(const tsmod::IObject*)> func)
{
	return _disconnectSignals.Add(func);
}

void TcpConnection::RemoveOnDisconnect(size_t cookie)
{
	_disconnectSignals.Remove(cookie);
}
