//	Copyright (c) 2016, TecSec, Inc.
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
#ifdef _WIN32
#include "shlwapi.h"
#include "shlobj.h"
#endif // _WIN32
#include "zlib.h"

using namespace BigNum;

static std::shared_ptr<tsmod::IServiceLocator> g_ServiceLocator;
static std::shared_ptr<tsmod::IServiceLocator> g_CryptoServiceLocator;
static std::shared_ptr<tsmod::IServiceLocator> g_CryptoTestServiceLocator;
std::shared_ptr < ICkmChangeMonitor> gChangeMonitor;
static std::vector<std::function<bool()> > gInitializers;
static std::deque<std::function<bool()> > gTerminators;

// from servicelocator.cpp
#ifdef _DEBUG
std::list<std::weak_ptr<tsmod::IObject> > gAllocatedObjects;
tscrypto::AutoCriticalSection gAllocatedObjectsListLock;
#endif

// from tsDebug.cpp
_tsTraceInfoExt *_gTsTraceHeadExt = nullptr;
uint32_t gNextTraceIDExt = 1;
_tsTraceInfoExt *_gTsTraceModuleExt = nullptr;

// from tsSignal.cpp
uint32_t tsStringSignalCookie = 1;

// from xp_sharedLib.cpp
#ifndef _WIN32
const char *gLastDLError = NULL;
#endif // _WIN32


// from EccCurve.cpp
std::vector<std::shared_ptr<BigNum::EccCurve> > gDomains;






extern tsmod::IObject* CreateKeyVEILConnector();

extern tsmod::IObject* CreateResourceLoader();

extern tsmod::IObject* CreateTcpMsgProcessor();

#if defined(HAVE_BSTR) && !defined(MSYS) && !defined(MINGW)
extern tsmod::IObject* CreateSqlServerDatabaseObject();
#endif
extern tsmod::IObject* CreateSqliteDatabaseObject();
extern tsmod::IObject* CreateNotifyPropertyChange();
extern tsmod::IObject* CreatePropertyMap();
#ifdef _WIN32
////////////////////////////////////////////////////////////////////////////////////////////////////
/// \fn BOOL APIENTRY DllMain( HMODULE , DWORD ul_reason_for_call, LPVOID )
///
/// \brief  Dll main.
///
/// \author Rogerb
/// \date   12/4/2010
///
/// \param                      The.
/// \param  ul_reason_for_call  The ul reason for call.
/// \param                      The.
///
/// \return .
////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID /*lpReserved*/
	)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		// TODO:  Need to handle this for Linux
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
#endif

static void DoStartup()
{
	tsLog::DisallowLogs("ADMIN,SMARTCARD,WINSCARD,CKM7,KeyHlpr,HTTPLOG,HTTPSENT,SRVDATA,TUNNEL,AUTH,SERVICE,HTTPDATA,SSLSTATE");
#ifndef _WIN32
	//hDllInstance = (XP_MODULE)(void*)&DoStartup;
#endif // !_WIN32
}

class DllStartup
{
public:
	DllStartup()
	{
		DoStartup();
	}
};

HIDDEN DllStartup gStartup;

std::shared_ptr<tsmod::IServiceLocator> TopServiceLocator()
{
	if (!g_ServiceLocator)
	{
		LOG(FrameworkInfo1, "Initializing the system");
		g_ServiceLocator = tsmod::CreateServiceLocator();
		g_ServiceLocator->SetAsRoot();
		g_ServiceLocator->AddClass("KeyVEILConnector", CreateKeyVEILConnector);

		if (!g_ServiceLocator->CanCreate("/PluginManager"))
		{
			g_ServiceLocator->AddClass("Plugin", tsmod::CreatePluginModule);
			g_ServiceLocator->AddClass("RootedPlugin", tsmod::CreateRootedPluginModule);
			g_ServiceLocator->AddSingletonClass("PluginManager", tsmod::CreatePluginModuleManager);
			std::shared_ptr<tsmod::IPluginModuleManager> mgr = g_ServiceLocator->get_instance<tsmod::IPluginModuleManager>("/PluginManager");
			if (!!mgr)
			{
				mgr->UseRootedPlugins(false);
			}
		}
		g_CryptoServiceLocator = std::dynamic_pointer_cast<tsmod::IServiceLocator>(g_ServiceLocator->newInstance());
		g_ServiceLocator->AddSingletonObject("Crypto", std::dynamic_pointer_cast<tsmod::IObject>(g_CryptoServiceLocator));

		//g_CryptoServiceLocator->AddClass("RSA-OAEP-SHA3", []()->tsmod::IObject* {return CreateRsaOAEP("RSA-OAEP-SHA3"); });

		g_CryptoTestServiceLocator = std::dynamic_pointer_cast<tsmod::IServiceLocator>(g_ServiceLocator->newInstance());
		g_ServiceLocator->AddSingletonObject("CryptoTest", std::dynamic_pointer_cast<tsmod::IObject>(g_CryptoTestServiceLocator));

		g_ServiceLocator->AddClass("ResourceLoader", CreateResourceLoader);
		g_ServiceLocator->AddClass("TcpMessageProcessor", CreateTcpMsgProcessor);

		g_ServiceLocator->AddClass("NotifyPropertyChange", CreateNotifyPropertyChange);
		g_ServiceLocator->AddClass("PropertyMap", CreatePropertyMap);
		g_ServiceLocator->AddSingletonObject("Settings", g_ServiceLocator->FinishConstruction(CreatePropertyMap()));

		AddSystemTerminationFunction([]() ->bool {
			g_ServiceLocator->DeleteClass("AlgorithmListManager");
			g_ServiceLocator->DeleteClass("KeyVEILConnector");
			g_ServiceLocator->DeleteClass("CkmEntropy");
			g_ServiceLocator->DeleteClass("Crypto");
			g_ServiceLocator->DeleteClass("CryptoTest");

			g_CryptoServiceLocator.reset();
			g_CryptoTestServiceLocator.reset();

			std::shared_ptr<tsmod::IPluginModuleManager> mgr = g_ServiceLocator->try_get_instance<tsmod::IPluginModuleManager>("/PluginManager");
			if (!!mgr)
				mgr->TerminateAllPlugins();
			mgr.reset();

			g_ServiceLocator->DeleteClass("Plugin");
			g_ServiceLocator->DeleteClass("RootedPlugin");
			g_ServiceLocator->DeleteClass("PluginManager");
			g_ServiceLocator->DeleteClass("NotifyPropertyChange");
			g_ServiceLocator->DeleteClass("PropertyMap");
			g_ServiceLocator->DeleteClass("Settings");
			g_ServiceLocator->DeleteClass("ResourceLoader");
			g_ServiceLocator->DeleteClass("TcpMessageProcessor");
#ifndef _WIN32
			g_ServiceLocator->DeleteClass("SSM");
#endif
			return true;
		});
		// Now run the crypto self-tests
		tscrypto::CryptoLocator();
		RunInitializers();
	}

	return g_ServiceLocator;
}
std::shared_ptr<tsmod::IServiceLocator> ServiceLocator()
{
	return TopServiceLocator();
}

bool HasServiceLocator()
{
	return !!g_ServiceLocator;
}

static bool Check_CPU_support_AES()
{
#if defined(ANDROID)
	return false;
#elif defined(HAVE_CPUID_H)
	unsigned int vals[4];

	__cpuid(1, vals[0], vals[1], vals[2], vals[3]);

	return (vals[2] & 0x2000000) != 0;
#else
	int vals[4];

	__cpuid(vals, 1);

	return (vals[2] & 0x2000000) != 0;
#endif // HAVE_CPUID_H
}
static bool Check_CPU_support_SSE()
{
#if defined(ANDROID)
	return false;
#elif defined(HAVE_CPUID_H)
	int vals[4];

	__cpuid(1, vals[0], vals[1], vals[2], vals[3]);

	return (vals[3] & 0x2000000) != 0;
#else
	int vals[4];

	__cpuid(vals, 1);

	return (vals[3] & 0x2000000) != 0;
#endif // HAVE_CPUID_H
}
static bool Check_CPU_support_SSE2()
{
#if defined(ANDROID)
	return false;
#elif defined(HAVE_CPUID_H)
	int vals[4];

	__cpuid(1, vals[0], vals[1], vals[2], vals[3]);

	return (vals[3] & 0x4000000) != 0;
#else
	int vals[4];

	__cpuid(vals, 1);

	return (vals[3] & 0x4000000) != 0;
#endif // HAVE_CPUID_H
}

bool gCpuSupportsAES = Check_CPU_support_AES();
bool gCpuSupportsSSE = Check_CPU_support_SSE();
bool gCpuSupportsSSE2 = Check_CPU_support_SSE2();

void XP_Sleep(uint32_t milliseconds)
{
#ifdef _WIN32
	Sleep(milliseconds);
#else
	usleep(milliseconds * 1000);
#endif
}

bool GCM_Encrypt(const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &iv, const tscrypto::tsCryptoData &authHeader,
	tscrypto::tsCryptoData &data, tscrypto::tsCryptoData &tag, const char* algorithm)
{
	std::shared_ptr<CCM_GCM> gcm;

	if (!(gcm = std::dynamic_pointer_cast<CCM_GCM>(CryptoFactory(algorithm))))
		return false;

	if (!gcm->initialize(key) || !gcm->encryptMessage(iv, authHeader, data, 16, tag))
		return false;
	return true;
}

bool GCM_Decrypt(const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &iv, const tscrypto::tsCryptoData &authHeader,
	tscrypto::tsCryptoData &data, const tscrypto::tsCryptoData &tag, const char* algorithm)
{
	std::shared_ptr<CCM_GCM> gcm;

	if (!(gcm = std::dynamic_pointer_cast<CCM_GCM>(CryptoFactory(algorithm))))
		return false;

	if (!gcm->initialize(key) || !gcm->decryptMessage(iv, authHeader, data, tag))
		return false;
	return true;
}

bool xp_CreateGuid(GUID &guid)
{
#ifdef _WIN32
	return SUCCEEDED(CoCreateGuid(&guid)) ? true : false;
#elif defined(HAVE_UUID_UUID_H)
	uuid_generate((unsigned char*)&guid);
	return true;
#else
	tscrypto::tsCryptoData tmp;

	if (!TSGenerateRandom(tmp, sizeof(GUID)))
	{
		return false;
	}
	guid = *(const GUID*)tmp.c_str();
	return true;
#endif
}

//HIDDEN
void TSPatchValueFromXML(const tscrypto::tsCryptoStringBase &value, tscrypto::tsCryptoStringBase &out)
{
	size_t count;
	size_t i;
	char val;

	out.resize(0);
	count = value.size();
	for (i = 0; i < count; i++)
	{
		val = value.c_at(i);
		if (val == '&')
		{
			if (count < i + 4)
				out += val;
			else
			{
				if (value.c_at(i + 1) == 'l' && value.c_at(i + 2) == 't' &&
					value.c_at(i + 3) == ';')
				{
					out += '<';
					i += 3;
				}
				else if (value.c_at(i + 1) == 'g' && value.c_at(i + 2) == 't' &&
					value.c_at(i + 3) == ';')
				{
					out += '>';
					i += 3;
				}
				else if (count < i + 5)
					out += val;
				else {
					if (value.c_at(i + 1) == 'a' && value.c_at(i + 2) == 'm' &&
						value.c_at(i + 3) == 'p' && value.c_at(i + 4) == ';')
					{
						out += '&';
						i += 4;
					}
					else if (count < i + 6)
						out += val;
					else
					{
						if (value.c_at(i + 1) == 'q' && value.c_at(i + 2) == 'u' &&
							value.c_at(i + 3) == 'o' && value.c_at(i + 4) == 't' &&
							value.c_at(i + 5) == ';')
						{
							out += '"';
							i += 5;
						}
						else if (value.c_at(i + 1) == 'a' && value.c_at(i + 2) == 'p' &&
							value.c_at(i + 3) == 'o' && value.c_at(i + 4) == 's' &&
							value.c_at(i + 5) == ';')
						{
							out += '\'';
							i += 5;
						}
						else
							out += val;
					}
				}
			}
		}
		else
			out += val;
	}
}

bool gzipCompress(const uint8_t* src, size_t srcLen, int level, uint8_t* dest, size_t& destLen)
{
	z_stream	m_stream;
	size_t origDestLen = destLen;

	memset(&m_stream, 0, sizeof(m_stream));
	m_stream.zalloc = Z_NULL;
	m_stream.zfree = Z_NULL;
	m_stream.opaque = Z_NULL;
	m_stream.avail_in = 0;
	m_stream.next_in = Z_NULL;

	int ret = deflateInit2(&m_stream, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);

	if (ret != Z_OK)
		return false;

	if (src == nullptr || srcLen == 0 || dest == nullptr || destLen == 0)
		return false;

	destLen = 0;
	m_stream.avail_in = (uInt)srcLen;
	m_stream.next_in = (BYTE*)src;
	m_stream.avail_out = (uInt)origDestLen;
	m_stream.next_out = dest;

	ret = deflate(&m_stream, Z_FINISH);
	destLen = origDestLen - m_stream.avail_out;
	deflateEnd(&m_stream);
	return ret == Z_OK || ret == Z_STREAM_END;
}
bool gzipDecompress(const uint8_t* src, size_t srcLen, uint8_t* dest, size_t& destLen)
{
	z_stream	m_stream;
	size_t origDestLen = destLen;

	memset(&m_stream, 0, sizeof(m_stream));
	m_stream.zalloc = Z_NULL;
	m_stream.zfree = Z_NULL;
	m_stream.opaque = Z_NULL;
	m_stream.avail_in = 0;
	m_stream.next_in = Z_NULL;

	int ret = inflateInit2(&m_stream, 15 + 16);

	if (ret != Z_OK)
		return false;

	if (src == nullptr || srcLen == 0 || dest == nullptr || destLen == 0)
		return false;

	destLen = 0;
	m_stream.avail_in = (uInt)srcLen;
	m_stream.next_in = (BYTE*)src;
	m_stream.avail_out = (uInt)origDestLen;
	m_stream.next_out = dest;

	ret = inflate(&m_stream, Z_FINISH);
	destLen = origDestLen - m_stream.avail_out;
	inflateEnd(&m_stream);
	return ret == Z_OK || ret == Z_STREAM_END;
}
bool gzipDecompress(const uint8_t* src, size_t srcLen, tscrypto::tsCryptoData& outputData)
{
	z_stream	m_stream;
	int outputLength;

	memset(&m_stream, 0, sizeof(m_stream));
	m_stream.zalloc = Z_NULL;
	m_stream.zfree = Z_NULL;
	m_stream.opaque = Z_NULL;
	m_stream.avail_in = 0;
	m_stream.next_in = Z_NULL;

	int ret = inflateInit2(&m_stream, 15 + 16);

	if (ret != Z_OK)
		return false;

	if (src == nullptr || srcLen == 0)
		return false;

	outputData.clear();

	m_stream.avail_in = (uInt)srcLen;
	m_stream.next_in = (BYTE*)src;

	do
	{
		outputLength = (int)outputData.size();
		outputData.resize(outputLength + 16384);

		m_stream.avail_out = 16384;
		m_stream.next_out = &outputData.rawData()[outputLength];

		ret = inflate(&m_stream, Z_NO_FLUSH);
		switch (ret) {
		case Z_NEED_DICT:
			ret = Z_DATA_ERROR;     /* and fall through */
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			if (m_stream.msg != NULL)
			{
				LOG(DebugError, (const char*)m_stream.msg);
			}
			else
			{
				LOG(DebugError, "Undiagnosed decompression error");
			}
			(void)inflateEnd(&m_stream);
			outputData.clear();
			return false;
		}

		outputData.resize(outputLength + 16384 - m_stream.avail_out);
	} while (m_stream.avail_out == 0);
	inflateEnd(&m_stream);
	return ret == Z_OK || ret == Z_STREAM_END;
}

bool raw_zlibCompress(const uint8_t* src, size_t srcLen, int level, uint8_t* dest, size_t& destLen)
{
	z_stream	m_stream;
	size_t origDestLen = destLen;

	memset(&m_stream, 0, sizeof(m_stream));
	m_stream.zalloc = Z_NULL;
	m_stream.zfree = Z_NULL;
	m_stream.opaque = Z_NULL;
	m_stream.avail_in = 0;
	m_stream.next_in = Z_NULL;

	int ret = deflateInit2(&m_stream, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);

	if (ret != Z_OK)
		return false;

	if (src == nullptr || srcLen == 0 || dest == nullptr || destLen == 0)
		return false;

	destLen = 0;
	m_stream.avail_in = (uInt)srcLen;
	m_stream.next_in = (BYTE*)src;
	m_stream.avail_out = (uInt)origDestLen;
	m_stream.next_out = dest;

	ret = deflate(&m_stream, Z_FINISH);
	destLen = origDestLen - m_stream.avail_out;
	deflateEnd(&m_stream);
	return ret == Z_OK || ret == Z_STREAM_END;
}
bool raw_zlibDecompress(const uint8_t* src, size_t srcLen, uint8_t* dest, size_t& destLen)
{
	z_stream	m_stream;
	size_t origDestLen = destLen;

	memset(&m_stream, 0, sizeof(m_stream));
	m_stream.zalloc = Z_NULL;
	m_stream.zfree = Z_NULL;
	m_stream.opaque = Z_NULL;
	m_stream.avail_in = 0;
	m_stream.next_in = Z_NULL;

	int ret = inflateInit2(&m_stream, -15);

	if (ret != Z_OK)
		return false;

	if (src == nullptr || srcLen == 0 || dest == nullptr || destLen == 0)
		return false;

	destLen = 0;
	m_stream.avail_in = (uInt)srcLen;
	m_stream.next_in = (BYTE*)src;
	m_stream.avail_out = (uInt)origDestLen;
	m_stream.next_out = dest;

	ret = inflate(&m_stream, Z_FINISH);
	destLen = origDestLen - m_stream.avail_out;
	inflateEnd(&m_stream);
	return ret == Z_OK || ret == Z_STREAM_END;
}
bool raw_zlibDecompress(const uint8_t* src, size_t srcLen, tscrypto::tsCryptoData& outputData)
{
	z_stream	m_stream;
	int outputLength;

	memset(&m_stream, 0, sizeof(m_stream));
	m_stream.zalloc = Z_NULL;
	m_stream.zfree = Z_NULL;
	m_stream.opaque = Z_NULL;
	m_stream.avail_in = 0;
	m_stream.next_in = Z_NULL;

	int ret = inflateInit2(&m_stream, -15);

	if (ret != Z_OK)
		return false;

	if (src == nullptr || srcLen == 0)
		return false;

	outputData.clear();

	m_stream.avail_in = (uInt)srcLen;
	m_stream.next_in = (BYTE*)src;

	do
	{
		outputLength = (int)outputData.size();
		outputData.resize(outputLength + 16384);

		m_stream.avail_out = 16384;
		m_stream.next_out = &outputData.rawData()[outputLength];

		ret = inflate(&m_stream, Z_NO_FLUSH);
		switch (ret) {
		case Z_NEED_DICT:
			ret = Z_DATA_ERROR;     /* and fall through */
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			if (m_stream.msg != NULL)
			{
				LOG(DebugError, (const char*)m_stream.msg);
			}
			else
			{
				LOG(DebugError, "Undiagnosed decompression error");
			}
			(void)inflateEnd(&m_stream);
			outputData.clear();
			return false;
		}

		outputData.resize(outputLength + 16384 - m_stream.avail_out);
	} while (m_stream.avail_out == 0);
	inflateEnd(&m_stream);
	return ret == Z_OK || ret == Z_STREAM_END;
}

bool zlibCompress(const uint8_t* src, size_t srcLen, int level, uint8_t* dest, size_t& destLen)
{
	z_stream	m_stream;
	size_t origDestLen = destLen;

	memset(&m_stream, 0, sizeof(m_stream));
	m_stream.zalloc = Z_NULL;
	m_stream.zfree = Z_NULL;
	m_stream.opaque = Z_NULL;
	m_stream.avail_in = 0;
	m_stream.next_in = Z_NULL;

	int ret = deflateInit(&m_stream, level);

	if (ret != Z_OK)
		return false;

	if (src == nullptr || srcLen == 0 || dest == nullptr || destLen == 0)
		return false;

	destLen = 0;
	m_stream.avail_in = (uInt)srcLen;
	m_stream.next_in = (BYTE*)src;
	m_stream.avail_out = (uInt)origDestLen;
	m_stream.next_out = dest;

	ret = deflate(&m_stream, Z_FINISH);
	destLen = origDestLen - m_stream.avail_out;
	deflateEnd(&m_stream);
	return ret == Z_OK || ret == Z_STREAM_END;
}
bool zlibDecompress(const uint8_t* src, size_t srcLen, uint8_t* dest, size_t& destLen)
{
	z_stream	m_stream;
	size_t origDestLen = destLen;

	memset(&m_stream, 0, sizeof(m_stream));
	m_stream.zalloc = Z_NULL;
	m_stream.zfree = Z_NULL;
	m_stream.opaque = Z_NULL;
	m_stream.avail_in = 0;
	m_stream.next_in = Z_NULL;

	int ret = inflateInit(&m_stream);

	if (ret != Z_OK)
		return false;

	if (src == nullptr || srcLen == 0 || dest == nullptr || destLen == 0)
		return false;

	destLen = 0;
	m_stream.avail_in = (uInt)srcLen;
	m_stream.next_in = (BYTE*)src;
	m_stream.avail_out = (uInt)origDestLen;
	m_stream.next_out = dest;

	ret = inflate(&m_stream, Z_FINISH);
	destLen = origDestLen - m_stream.avail_out;
	inflateEnd(&m_stream);
	return ret == Z_OK || ret == Z_STREAM_END;
}
bool zlibDecompress(const uint8_t* src, size_t srcLen, tscrypto::tsCryptoData& outputData)
{
	z_stream	m_stream;
	int outputLength;

	memset(&m_stream, 0, sizeof(m_stream));
	m_stream.zalloc = Z_NULL;
	m_stream.zfree = Z_NULL;
	m_stream.opaque = Z_NULL;
	m_stream.avail_in = 0;
	m_stream.next_in = Z_NULL;

	int ret = inflateInit(&m_stream);

	if (ret != Z_OK)
		return false;

	if (src == nullptr || srcLen == 0)
		return false;

	outputData.clear();

	m_stream.avail_in = (uInt)srcLen;
	m_stream.next_in = (BYTE*)src;

	do
	{
		outputLength = (int)outputData.size();
		outputData.resize(outputLength + 16384);

		m_stream.avail_out = 16384;
		m_stream.next_out = &outputData.rawData()[outputLength];

		ret = inflate(&m_stream, Z_NO_FLUSH);
		switch (ret) {
		case Z_NEED_DICT:
			ret = Z_DATA_ERROR;     /* and fall through */
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			if (m_stream.msg != NULL)
			{
				LOG(DebugError, (const char*)m_stream.msg);
			}
			else
			{
				LOG(DebugError, "Undiagnosed decompression error");
			}
			(void)inflateEnd(&m_stream);
			outputData.clear();
			return false;
		}

		outputData.resize(outputLength + 16384 - m_stream.avail_out);
	} while (m_stream.avail_out == 0);
	inflateEnd(&m_stream);
	return ret == Z_OK || ret == Z_STREAM_END;
}

class __ResourceLoader :public tsmod::IResourceLoader, public tsmod::IObject, public tsmod::IAggregatableObject
{
public:
	virtual bool LoadResourceFile(const tscrypto::tsCryptoStringBase& filename) override
	{
		tscrypto::tsCryptoData tmp;
		tscrypto::tsCryptoData part;

		_resources.clear();
		if (!xp_ReadAllBytes(filename, tmp))
		{
			return false;
		}
		part.assign(tmp.c_str(), sizeof(int));
#if (BYTE_ORDER == LITTLE_ENDIAN)
		part.reverse();
#endif
		_resources.resize(*(int*)part.c_str());
		size_t len = _resources.size();
		if (!zlibDecompress(tmp.c_str() + sizeof(int), tmp.size() - sizeof(int), _resources.rawData(), len) || len != _resources.size())
		{
			_resources.clear();
			return false;
		}
		return true;
	}
	virtual bool IsValid() override
	{
		return _resources.size() > 0;
	}
	virtual bool HasResource(const tscrypto::tsCryptoStringBase& resourceName) override
	{
		if (resourceName == nullptr)
			return false;

		tscrypto::tsCryptoString name(resourceName);
		name.ToUpper();
		if (name[0] == '/')
			name.erase(0, 1);

		const TecSecResources::NameEntry* entry = FindName(name.c_str());
		if (entry == nullptr)
		{
			std::shared_ptr<tsmod::IResourceLoader> child = std::dynamic_pointer_cast<tsmod::IResourceLoader>(getContained());

			if (!!child)
				return child->HasResource(resourceName);

			return false;
		}
		return true;
	}
	virtual tscrypto::tsCryptoData LoadResource(const tscrypto::tsCryptoStringBase& resourceName) override
	{
		tscrypto::tsCryptoData data;
		if (resourceName == nullptr)
			return data;

		tscrypto::tsCryptoString name(resourceName);
		name.ToUpper();
		if (name[0] == '/')
			name.erase(0, 1);

		const TecSecResources::NameEntry* entry = FindName(name.c_str());
		if (entry == nullptr)
		{
			std::shared_ptr<tsmod::IResourceLoader> child = std::dynamic_pointer_cast<tsmod::IResourceLoader>(getContained());

			if (!!child)
				return child->LoadResource(resourceName);

			return data;
		}
		data.assign(_resources.c_str() + entry->dataOffset + ((const TecSecResources::ResourceHeader*)_resources.c_str())->DataTable, entry->dataSize);

		const TecSecResources::ResourceHeader* header = (const TecSecResources::ResourceHeader*)_resources.c_str();
		//const TecSecResources::NameEntry* entries = (const TecSecResources::NameEntry*)(header + 1);

		name = (const char *)(_resources.c_str() + header->NameStringTable + entry->nameOffset);
		bool encrypt = (name[0] == '`' || name[0] == '~');
		bool compress = (name[0] == '`' || name[0] == '&');

		if (encrypt)
		{
			if (Key.size() == 0)
			{
				tscrypto::tsCryptoData seed;
				int iterCount = 1000;

				entry = FindName("$$SEED");
				if (entry != nullptr)
				{
					seed.assign(_resources.c_str() + entry->dataOffset + ((const TecSecResources::ResourceHeader*)_resources.c_str())->DataTable, entry->dataSize);

					if (seed.size() != 36)
						seed.clear();
					else
					{
						iterCount = (seed[0] << 24) | (seed[1] << 16) | (seed[2] << 8) || seed[3];
						seed.erase(0, 4);
					}
				}

				if (!TSCreatePBEKey("SHA512", _pin.ToUtf8String(), seed, iterCount, 64, Key))
				{
					return tscrypto::tsCryptoData();
				}
			}

			tscrypto::tsCryptoData iv;
			CryptoContext ctx;

			if (!TSHash(Key.substring(32, 32) + name.ToUTF8Data(), iv, _TS_ALG_ID::TS_ALG_SHA512) ||
				!TSDecryptInit(Key.substring(0, 32), iv.substring(0, 16), ctx, _TS_ALG_ID::TS_ALG_AES_CTR_256) ||
				!TSDecrypt(data, data, ctx))
			{
				return tscrypto::tsCryptoData();
			}
		}
		if (compress)
		{
			tscrypto::tsCryptoData tmp2;
			if (!zlibDecompress(data.c_str(), data.size(), tmp2))
			{
				return tscrypto::tsCryptoData();
			}
			data = tmp2;
		}
		return data;
	}
	virtual void SetResourcePin(const tscrypto::tsCryptoData& pin) override
	{
		_pin = pin;
		Key.clear();
	}

	// Inherited via IAgregatableObject
	virtual std::shared_ptr<tsmod::IObject> getContained() override
	{
		return _contained;
	}
	virtual void setContained(std::shared_ptr<tsmod::IObject> setTo) override
	{
		_contained.reset();
		_contained = setTo;
	}
	virtual std::shared_ptr<tsmod::IObject> getContainer() override
	{
		if (!_container.expired())
			return _container.lock();
		return nullptr;
	}
	virtual void setContainer(std::shared_ptr<tsmod::IObject> setTo) override
	{
		_container.reset();
		_container = setTo;
	}
	virtual std::shared_ptr<tsmod::IObject> findTopContainer() override
	{
		return std::shared_ptr<tsmod::IObject>();
	}
protected:
	tscrypto::tsCryptoData _resources;
	tscrypto::tsCryptoData _pin;
	tscrypto::tsCryptoData Key;
	std::weak_ptr<tsmod::IObject> _container;
	std::shared_ptr<tsmod::IObject> _contained;

	const TecSecResources::NameEntry* FindName(const char *name)
	{
		const TecSecResources::ResourceHeader* header = (const TecSecResources::ResourceHeader*)_resources.c_str();
		const TecSecResources::NameEntry* entries = (const TecSecResources::NameEntry*)(header + 1);

		if (!IsValid())
			return nullptr;
		for (size_t i = 0; i < (size_t)header->EntryCount; i++)
		{
			tscrypto::tsCryptoString tmp = (const char *)(_resources.c_str() + header->NameStringTable + entries[i].nameOffset);

			if (tmp[0] == '`' || tmp[0] == '&' || tmp[0] == '~')
				tmp.DeleteAt(0, 1);
			if (TsStrCmp(name, tmp) == 0)
			{
				return &entries[i];
			}
		}
		return nullptr;
	}
};

tsmod::IObject* CreateResourceLoader()
{
	return dynamic_cast<tsmod::IObject*>(new __ResourceLoader());
}

void RunInitializers()
{
	for (auto func : gInitializers)
	{
		func();
	}
	gInitializers.clear();
}
void AddSystemInitializationFunction(std::function<bool()> func)
{
	gInitializers.push_back(func);
}
void AddSystemTerminationFunction(std::function<bool()> func)
{
	gTerminators.push_back(func);
}
void TerminateVEILSystem()
{
	LOG(FrameworkInfo1, "Terminating the system");
	while (gTerminators.size() > 0)
	{
		std::function<bool()> func = gTerminators.back();
		gTerminators.pop_back();
		func();
	}
	//std::for_each(gTerminators.rbegin(), gTerminators.rend(), [](std::function<bool()>&func){ 
	//	if (!!func) 
	//		func(); 
	//});
	//gTerminators.clear();
	g_CryptoServiceLocator.reset();
	g_CryptoTestServiceLocator.reset();
	if (!!gChangeMonitor)
	{
		gChangeMonitor->StartChangeMonitorThread();
	}
	gChangeMonitor.reset();

	if (!!g_ServiceLocator)
		g_ServiceLocator->clear();
	g_ServiceLocator.reset();
    TerminateCryptoSystem();
	LOG(FrameworkInfo1, "VEIL system terminated");
}

bool ComputeRandomNumber(RsaNumber& num, size_t len, bool predictionResistant, const tscrypto::tsCryptoData &additionalInput)
{
	tscrypto::tsCryptoData rng;

	SetZero(num);

	std::shared_ptr<Random> prng = std::dynamic_pointer_cast<Random>(CryptoFactory("Random"));

	if (!prng || !prng->Initialize(256, true, tscrypto::tsCryptoData(), tscrypto::tsCryptoData()) || !prng->Generate(len, 256, predictionResistant, additionalInput, rng))
		return false;

	SetNum(num, rng);
	if (BitLength(num) > len)
	{
		ShiftRight(num, (unsigned short)(BitLength(num) - len));
	}
	return true;
}

bool GenerateOddNumber(RsaNumber& num, size_t bitLengthRequested, bool predictionResistant, const tscrypto::tsCryptoData &additionalInput)
{
	if (!gFipsState.operational())
		return false;
	tscrypto::tsCryptoData tmp;

	std::shared_ptr<Random> prng = std::dynamic_pointer_cast<Random>(CryptoFactory("Random"));

	if (!prng || !prng->Initialize(256, true, tscrypto::tsCryptoData(), tscrypto::tsCryptoData()) || !prng->Generate(bitLengthRequested, 256, predictionResistant, additionalInput, tmp))
		return false;

	tmp[0] |= 0x80;
	if ((bitLengthRequested & 7) != 0)
	{
		Number t(tmp);
		ShiftRight(t, 8 - (bitLengthRequested & 7));

		tmp = t.toByteArray();
	}
	tmp[tmp.size() - 1] |= 1;

	SetNum(num, tmp);
	return true;
}

bool CryptoOperational()
{
	return gFipsState.operational();
}

void CryptoTestFailed()
{
	gFipsState.testFailed();
}

bool TSGenerateRandom(tscrypto::tsCryptoData& data, size_t lenInBytes)
{
	std::shared_ptr<Random> prng = std::dynamic_pointer_cast<Random>(CryptoFactory("Random"));

	if (!prng || !prng->Initialize(256, true, tscrypto::tsCryptoData(), tscrypto::tsCryptoData()) || !prng->Generate(lenInBytes * 8, 256, true, tscrypto::tsCryptoData(), data))
		return false;
	return true;
}

bool TSGenerateRandom(uint8_t* data, size_t lenInBytes)
{
	std::shared_ptr<Random> prng = std::dynamic_pointer_cast<Random>(CryptoFactory("Random"));
	tscrypto::tsCryptoData tmp;

	if (data == nullptr || !prng || !prng->Initialize(256, true, tscrypto::tsCryptoData(), tscrypto::tsCryptoData()) || !prng->Generate(lenInBytes * 8, 256, true, tscrypto::tsCryptoData(), tmp))
		return false;
	memmove(data, tmp.c_str(), tmp.size());
	return true;
}

bool TSWrap(const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &dataToWrap, tscrypto::tsCryptoData &wrappedData, TS_ALG_ID alg)
{
	std::shared_ptr<KeyTransport> wrapper;

	if (!(wrapper = std::dynamic_pointer_cast<KeyTransport>(CryptoFactory(alg))))
	{
		return false;
	}
	if (!wrapper->initializeWithSymmetricKey(key) || !wrapper->CanWrap(dataToWrap))
		return false;
	if (!wrapper->Wrap(dataToWrap, tscrypto::tsCryptoData(), wrappedData))
		return false;
	return true;
}

bool TSUnwrap(const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &dataToUnwrap, tscrypto::tsCryptoData &unwrappedData, TS_ALG_ID alg)
{
	std::shared_ptr<KeyTransport> wrapper;

	if (!(wrapper = std::dynamic_pointer_cast<KeyTransport>(CryptoFactory(alg))))
	{
		return false;
	}
	if (!wrapper->initializeWithSymmetricKey(key) || !wrapper->CanUnwrap(dataToUnwrap))
		return false;
	if (!wrapper->Unwrap(dataToUnwrap, tscrypto::tsCryptoData(), unwrappedData))
		return false;
	return true;
}
bool TSPad(tscrypto::tsCryptoData& value, int blockSize)
{
	size_t size;
	size_t padNeeded;

	size = value.size();

	padNeeded = blockSize - (size % blockSize);
	if (padNeeded == 0)
		padNeeded = blockSize;

	value.resize(size + padNeeded, (BYTE)padNeeded);
	return true;
}
bool TSUnpad(tscrypto::tsCryptoData& value, int blockSize)
{
	size_t size;

	size = value.size();

	size_t bytesFound;
	size_t i;

	bytesFound = value[size - 1];
	if (bytesFound < 1 || bytesFound >(size_t)blockSize)
		return false;

	const uint8_t *io_buffer = value.c_str();
	//
	// Now verify that all bytesFound bytes are the same value
	//
	for (i = size - bytesFound; i < size; i++)
	{
		if (io_buffer[i] != (unsigned char)bytesFound)
			return false;
	}
	value.resize(size - bytesFound);
	return true;
}

bool TSEncryptInit(const tscrypto::tsCryptoData &Key, const tscrypto::tsCryptoData &IV, CryptoContext &Context, TS_ALG_ID AlgID)
{
	TS_ALG_ID algorithm = _TS_ALG_ID::TS_ALG_INVALID;
	size_t ivSize = 0;
	SymmetricMode mode;

	if (AlgID == 0)
	{
		if (Key.size() < 8)
			return false;
		if (Key.size() < 16)
		{
			algorithm = _TS_ALG_ID::TS_ALG_DES_CBC;
		}
		else if (Key.size() < 24)
		{
			algorithm = _TS_ALG_ID::TS_ALG_DES3_TWOKEY_CBC;
		}
		else
		{
			algorithm = _TS_ALG_ID::TS_ALG_DES3_THREEKEY_CBC;
		}
	}
	else
	{
		algorithm = (TS_ALG_ID)AlgID;
	}

	mode = Alg2Mode(algorithm);

	ivSize = CryptoIVECSize(algorithm);
	if (ivSize > 0 && (IV.size() < (uint32_t)ivSize))
		return false;

	std::shared_ptr<Symmetric> symAlg;

	if (!(symAlg = std::dynamic_pointer_cast<Symmetric>(CryptoFactory(algorithm))))
		return false;

	Context = std::dynamic_pointer_cast<tscrypto::IObject>(symAlg);

	tscrypto::tsCryptoData tmpKey;
	size_t KeySize;

	KeySize = CryptoKeySize(algorithm);
	symAlg->bytesToKey(KeySize, Key, tmpKey);

	if (!symAlg->init(true, mode, tmpKey, IV))
	{
		return false;
	}

	return true;
}

bool TSEncrypt(const tscrypto::tsCryptoData &source, tscrypto::tsCryptoData &dest, CryptoContext &Context)
{
	std::shared_ptr<Symmetric> symAlg;

	symAlg = Context.get<Symmetric>();
	if (!symAlg)
		return false;

	if (!symAlg->update(source, dest))
		return false;

	return true;
}

bool TSDecryptInit(const tscrypto::tsCryptoData &Key, const tscrypto::tsCryptoData &IV, CryptoContext &Context, TS_ALG_ID AlgID)
{
	TS_ALG_ID algorithm = _TS_ALG_ID::TS_ALG_INVALID;
	size_t ivSize = 0;
	SymmetricMode mode;

	if (AlgID == 0)
	{
		if (Key.size() < 8)
			return false;
		if (Key.size() < 16)
		{
			algorithm = _TS_ALG_ID::TS_ALG_DES_CBC;
		}
		else if (Key.size() < 24)
		{
			algorithm = _TS_ALG_ID::TS_ALG_DES3_TWOKEY_CBC;
		}
		else
		{
			algorithm = _TS_ALG_ID::TS_ALG_DES3_THREEKEY_CBC;
		}
	}
	else
	{
		algorithm = (TS_ALG_ID)AlgID;
	}

	mode = Alg2Mode(algorithm);
	ivSize = CryptoIVECSize(algorithm);

	if (ivSize > 0 && (IV.size() < (uint32_t)ivSize))
		return false;

	std::shared_ptr<Symmetric> symAlg;

	if (!(symAlg = std::dynamic_pointer_cast<Symmetric>(CryptoFactory(algorithm))))
		return false;

	Context = std::dynamic_pointer_cast<tscrypto::IObject>(symAlg);

	tscrypto::tsCryptoData tmpKey;
	size_t KeySize;

	KeySize = CryptoKeySize(algorithm);
	symAlg->bytesToKey(KeySize, Key, tmpKey);

	if (!symAlg->init(false, mode, tmpKey, IV))
	{
		return false;
	}

	return true;
}
bool TSDecrypt(const tscrypto::tsCryptoData &source, tscrypto::tsCryptoData &dest, CryptoContext &Context)
{
	return TSEncrypt(source, dest, Context);
}


void FixTDESParityBits(tscrypto::tsCryptoData &value)
{                                    //0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
	static const BYTE testArray[16] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };
	BYTE parity;
	BYTE chr;

	for (int i = 0; i < (int)value.size(); i++)
	{
		chr = value.c_at(i);
		parity = testArray[((chr >> 4) & 0x0f)] + testArray[((chr >> 1) & 0x07)];
		value[i] = (chr & 0xfe) | ((parity & 1) ^ 1);
	}
}

bool CheckTDESParityBits(const tscrypto::tsCryptoData &value)
{                                    //0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
	static const BYTE testArray[16] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };
	BYTE parity;
	BYTE chr;

	if (!gFipsState.operational())
		return false;
	for (int i = 0; i < (int)value.size(); i++)
	{
		chr = value.c_at(i);
		parity = testArray[((chr >> 4) & 0x0f)] + testArray[((chr >> 1) & 0x07)];
		if ((chr & 1) != ((parity & 1) ^ 1))
			return false;
	}
	return true;
}


void TSModExp(const tscrypto::tsCryptoData &prime, const tscrypto::tsCryptoData &y, const tscrypto::tsCryptoData &x, tscrypto::tsCryptoData &result)
{
	Number Y, work1, work2, work3;

	ModExp(Y, Number(y), Number(x), Number(prime), work1, work2, work3);

	result = Y.toByteArray();
}
void TSModAdd(const tscrypto::tsCryptoData &prime, const tscrypto::tsCryptoData &a, const tscrypto::tsCryptoData &b, tscrypto::tsCryptoData &result)
{
	Number left(a), p(prime);

	Add(left, Number(b));
	if (!IsLess(left, p))
		Sub(left, p);

	result = left.toByteArray();
}

void TSModSub(const tscrypto::tsCryptoData &prime, const tscrypto::tsCryptoData &_a, const tscrypto::tsCryptoData &_b, tscrypto::tsCryptoData &result)
{
	Number left(_a);

	Sub(left, Number(_b));
	if (isNegative(left))
		Add(left, Number(prime));

	result = left.toByteArray();
}

void TSModMul(const tscrypto::tsCryptoData &prime, const tscrypto::tsCryptoData &a, const tscrypto::tsCryptoData &b, tscrypto::tsCryptoData &result)
{
	Number left, work1;

	ModMul(left, Number(a), Number(b), Number(prime), work1);

	result = left.toByteArray();
}

void TSAdd(const tscrypto::tsCryptoData &a, const tscrypto::tsCryptoData &b, tscrypto::tsCryptoData &result)
{
	Number left(a);

	Add(left, Number(b));

	result = left.toByteArray();
}

void TSSub(const tscrypto::tsCryptoData &a, const tscrypto::tsCryptoData &b, tscrypto::tsCryptoData &result)
{
	Number left(a);

	Sub(left, Number(b));

	result = left.toByteArray();
}

void TSMul(const tscrypto::tsCryptoData &a, const tscrypto::tsCryptoData &b, tscrypto::tsCryptoData &result)
{
	Number left(a);

	Mul(left, Number(b));

	result = left.toByteArray();
}
void TSDiv(const tscrypto::tsCryptoData &a, const tscrypto::tsCryptoData &b, tscrypto::tsCryptoData &quotient, tscrypto::tsCryptoData& remainder)
{
	Number quot, rem(a);

	Div(quot, rem, Number(b));

	quotient = quot.toByteArray();
	remainder = rem.toByteArray();
}
static bool BuildSymmetricAlg(TS_ALG_ID alg, std::shared_ptr<Symmetric>& sym)
{
	if (!(sym = std::dynamic_pointer_cast<Symmetric>(CryptoFactory(alg))))
	{
		return false;
	}
	return true;
}
//static bool BuildHMACAlg(TS_ALG_ID alg, std::shared_ptr<MessageAuthenticationCode>& mac)
//{
//	if (!(mac = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(alg))))
//	{
//		return false;
//	}
//	return true;
//}
bool TSBytesToKey(const tscrypto::tsCryptoData &Bytes, tscrypto::tsCryptoData &Key, TS_ALG_ID AlgID)
{
	if (AlgID == 0)
	{
		if (Key.size() < 8)
			return false;
		if (Key.size() < 16)
		{
			AlgID = _TS_ALG_ID::TS_ALG_DES_CBC;
		}
		else if (Key.size() < 24)
		{
			AlgID = _TS_ALG_ID::TS_ALG_DES3_TWOKEY_CBC;
		}
		else
		{
			AlgID = _TS_ALG_ID::TS_ALG_DES3_THREEKEY_CBC;
		}
	}

	std::shared_ptr<Symmetric> symAlg;

	if (!BuildSymmetricAlg(AlgID, symAlg))
		return false;

	size_t keySize;
	keySize = CryptoKeySize(AlgID);

	if (!symAlg->bytesToKey(keySize, Bytes, Key))
		return false;

	return true;
}


void xor8(const uint8_t* src, const uint8_t* second, uint8_t* dest)
{
	const uint64_t* a = (const uint64_t*)src;
	const uint64_t* b = (const uint64_t*)second;
	uint64_t* c = (uint64_t*)dest;
	*c = *a ^ *b;
}
void xor16(const uint8_t* src, const uint8_t* second, uint8_t* dest)
{
	const uint64_t* a = (const uint64_t*)src;
	const uint64_t* b = (const uint64_t*)second;
	uint64_t* c = (uint64_t*)dest;
	c[0] = a[0] ^ b[0];
	c[1] = a[1] ^ b[1];
}
void xor32(const uint8_t* src, const uint8_t* second, uint8_t* dest)
{
	const uint64_t* a = (const uint64_t*)src;
	const uint64_t* b = (const uint64_t*)second;
	uint64_t* c = (uint64_t*)dest;
	c[0] = a[0] ^ b[0];
	c[1] = a[1] ^ b[1];
	c[2] = a[2] ^ b[2];
	c[3] = a[3] ^ b[3];
}

HttpAttributeList CreateHttpAttributeList()
{
	return CreateContainer<HttpAttribute>();
}
TSNamedBinarySectionList CreateTSNamedBinarySectionList()
{
	return CreateContainer<TSNamedBinarySection>();
}

tsTraceStream httpData("HTTPDATA", DEBUG_LEVEL_DEBUG);
tsTraceStream httpLog("HTTPLOG", DEBUG_LEVEL_INFORMATION);
tsTraceStream FrameworkError("Error", DEBUG_LEVEL_ERROR);
tsDebugStream FrameworkInfo1("Info1", DEBUG_LEVEL_DEBUG);
tsDebugStream FrameworkInternal("Internal", DEBUG_LEVEL_TRACE);
tsDebugStream FrameworkDevOnly("DevOnly", DEBUG_LEVEL_DEV_ONLY);
tsDebugStream FrameworkLocks("Locks", DEBUG_LEVEL_DEBUG);
tsTraceStream gMetaError("MetaError", DEBUG_LEVEL_ERROR);
tsDebugStream gMetaDebug("MetaDebug", DEBUG_LEVEL_DEBUG);
tsDebugStream gMetaTrace("MetaTrace", DEBUG_LEVEL_TRACE);
tsDebugStream CallTrace("CallTrace", DEBUG_LEVEL_DEBUG);
tsTraceStream gLoaderError("LoadErr", DEBUG_LEVEL_ERROR);
tsDebugStream gLoaderTrace("Loader", DEBUG_LEVEL_TRACE);
tsDebugStream gDebugAuth("AUTH", DEBUG_LEVEL_SENSITIVE);
tsTraceStream gTunnel("TUNNEL", DEBUG_LEVEL_DEV_ONLY);
tsTraceStream gTunnelError("TUNNEL", DEBUG_LEVEL_ERROR);
tsTraceStream CkmError("CkmError", DEBUG_LEVEL_ERROR);
tsDebugStream CkmInfo1("CkmInfo1", DEBUG_LEVEL_DEBUG);
tsDebugStream CkmInfo2("CkmInfo2", DEBUG_LEVEL_DEBUG);
tsDebugStream CkmDevOnly("CkmDevOnly", DEBUG_LEVEL_DEV_ONLY);
tsDebugStream CkmCrypto("CkmCrypto", DEBUG_LEVEL_SENSITIVE);
tsDebugStream DebugInfo1("Info1", DEBUG_LEVEL_DEBUG);
tsDebugStream DebugInfo2("Info2", DEBUG_LEVEL_DEBUG);
tsDebugStream DebugInfo3("Info3", DEBUG_LEVEL_DEBUG);
tsDebugStream DebugConfig("Config", DEBUG_LEVEL_DEBUG);
tsDebugStream DebugToken("Token", DEBUG_LEVEL_DEBUG);
tsDebugStream DebugCrypto("Crypto", DEBUG_LEVEL_SENSITIVE);
tsDebugStream DebugPki("Pki", DEBUG_LEVEL_DEBUG);
tsDebugStream DebugInternal("Internal", DEBUG_LEVEL_DEV_ONLY);
tsDebugStream DebugDevOnly("Dev", DEBUG_LEVEL_DEV_ONLY);
tsDebugStream DebugFile("File", DEBUG_LEVEL_DEBUG);
tsDebugStream DebugNetwork("Network", DEBUG_LEVEL_DEBUG);
tsDebugStream DebugUI("UI", DEBUG_LEVEL_DEBUG);
tsTraceStream DebugError("Error", DEBUG_LEVEL_ERROR);
tsTraceStream DebugFatal("Fatal", DEBUG_LEVEL_FATAL_ERROR);
tsDebugStream DebugLocks("Locks", DEBUG_LEVEL_DEBUG);
tsDebugStream gSql("SQL", DEBUG_LEVEL_INFORMATION);

//tsDebugStream AuditInfo("Info", 1, AUDIT_INFO, false);
//tsDebugStream AuditLoginFailure("Failure", 1, AUDIT_LOGIN, false);
//tsDebugStream AuditLoginSuccess("Success", 1, AUDIT_LOGIN, false);
//tsDebugStream AuditLogout("Success", 1, AUDIT_LOGOUT, false);
//tsDebugStream AuditEncryptFailure("Failure", 1, AUDIT_ENCRYPT, false);
//tsDebugStream AuditEncryptSuccess("Success", 1, AUDIT_ENCRYPT, false);
//tsDebugStream AuditDecryptFailure("Failure", 1, AUDIT_DECRYPT, false);
//tsDebugStream AuditDecryptSuccess("Success", 1, AUDIT_DECRYPT, false);
//tsDebugStream AuditSignFailure("Failure", 1, AUDIT_SIGN, false);
//tsDebugStream AuditSignSuccess("Success", 1, AUDIT_SIGN, false);
//tsDebugStream AuditVerifyFailure("Failure", 1, AUDIT_VERIFY, false);
//tsDebugStream AuditVerifySuccess("Success", 1, AUDIT_VERIFY, false);
//tsDebugStream AuditHashFailure("Failure", 1, AUDIT_HASH, false);
//tsDebugStream AuditHashSuccess("Success", 1, AUDIT_HASH, false);

extern HIDDEN tscrypto::tsCryptoString localGetErrorString(int errorNumber);



//std::shared_ptr<tsmod::IServiceLocator> topServiceLocator()
//{
//	return ServiceLocator();
//}
//
//std::shared_ptr<tsmod::IServiceLocator> rootServiceLocator()
//{
//	std::shared_ptr<tsmod::IServiceLocator> p = ServiceLocator();
//
//	while (p->Creator().use_count() > 0)
//		p = p->Creator();
//	return p;
//}

HIDDEN tscrypto::tsCryptoString localGetErrorString(int errorNumber)
{
	return "%s";
}

tscrypto::tsCryptoString ToXml(const char* src, const char* nullValue)
{
	if (src == nullptr || *src == 0)
		return nullValue;
	tscrypto::tsCryptoString tmp;
	TSPatchValueForXML(tscrypto::tsCryptoString(src), tmp);
	return tmp;
}
tscrypto::tsCryptoString ToXml(const tscrypto::tsCryptoStringBase &src, const char* nullValue)
{
	if (src.size() == 0)
		return nullValue;
	tscrypto::tsCryptoString tmp;
	TSPatchValueForXML(src, tmp);
	return tmp;
}
tscrypto::tsCryptoString ToXml(const GUID &src, const char* nullValue)
{
	if (src == GUID_NULL)
		return nullValue;
	tscrypto::tsCryptoString tmp;
	TSPatchValueForXML(TSGuidToString(src), tmp);
	return tmp;
}
tscrypto::tsCryptoString ToXml(bool src, const char* nullValue)
{
	return ToXml(src ? "true" : "false");
}
tscrypto::tsCryptoString ToXml(int src, const char* nullValue)
{
	tscrypto::tsCryptoString tmp;
	tmp << src;
	return tmp;
}
tscrypto::tsCryptoString ToXml(double src, const char* nullValue)
{
	tscrypto::tsCryptoString tmp;
	tmp.Format("%lf", src);
	return tmp;
}
tscrypto::tsCryptoString ToXml(const tscrypto::tsCryptoDate &src, const char* nullValue)
{
	if (src.GetStatus() != tscrypto::tsCryptoDate::valid)
		return nullValue;
	return ToXml(src.ToString());
}
//tscrypto::tsCryptoString ToXml(bool exists, const char* src, const char* nullValue)
//{
//	if (!exists)
//		return nullValue;
//	return ToXml(src, nullValue);
//}
//tscrypto::tsCryptoString ToXml(bool exists, const tscrypto::tsCryptoStringBase &src, const char* nullValue)
//{
//	if (!exists)
//		return nullValue;
//	return ToXml(src, nullValue);
//}
//tscrypto::tsCryptoString ToXml(bool exists, const GUID &src, const char* nullValue)
//{
//	if (!exists)
//		return nullValue;
//	return ToXml(src, nullValue);
//}
//tscrypto::tsCryptoString ToXml(bool exists, bool src, const char* nullValue)
//{
//	if (!exists)
//		return nullValue;
//	return ToXml(src ? "true" : "false");
//}
//tscrypto::tsCryptoString ToXml(bool exists, int src, const char* nullValue)
//{
//	if (!exists)
//		return nullValue;
//	return ToXml(src, nullValue);
//}
//tscrypto::tsCryptoString ToXml(bool exists, double src, const char* nullValue)
//{
//	if (!exists)
//		return nullValue;
//	return ToXml(src, nullValue);
//}
//tscrypto::tsCryptoString ToXml(bool exists, const tscrypto::tsCryptoDate &src, const char* nullValue)
//{
//	if (!exists)
//		return nullValue;
//	return ToXml(src, nullValue);
//}

/*
* Get User Information
*/
uint32_t xp_GetUserName(tscrypto::tsCryptoStringBase& name)
{
#ifdef _WIN32
	DWORD len = 1024;

	name.resize(len);

	if (0 == GetUserName(name.rawData(), (LPDWORD)&len)) {
		name.clear();
		//Error("iGetUserName: GetUserName can't determine the thread owner!");
		return 0xffffffff;
	}
	name.resize(len - 1);
#else /* UNIX */

	/* This doesn't work under UNIX for the time being.  But since
	we only use the UserName in iCreateTokenPath and under UNIX,
	we use the inode number of the token file instead of a long
	convuluted string, we don't need GetUserName.  For now, anyway.

	But, I'll leave this printf in so if we ever call it in the
	future, we'll have immediage feedback.
	*/

	errno = 0;
	name = getlogin();
	if (name.size() == 0)
	{
		name = "unknown";
	}
#endif
	return 0;
}

uint32_t xp_GetComputerName(tscrypto::tsCryptoStringBase& name)
{
	DWORD len = 1024;

	name.resize(len);

#ifdef _WIN32
	if (0 == GetComputerName(name.rawData(), (LPDWORD)&len)) {
		//Error("iGetUserName: GetComputerName can't determine the thread owner!");
		name.clear();
		return 0xffffffff;
	}
	name.resize(len - 1);
#else /* UNIX */
	int outLen = gethostname(name.rawData(), len);
	if (outLen != 0)
	{
		name.clear();
		return 0xffffffff;
	}
	name.resize(strlen(name.c_str()));
#endif
	return 0;
}
