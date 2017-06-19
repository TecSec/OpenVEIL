//	Copyright (c) 2017, TecSec, Inc.
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
#include "CryptoAsn1.h"

using namespace tscrypto;

#define MAX_DATA_SIZE 16384

typedef struct {
	static void* operator new(std::size_t count) {
		return tscrypto::cryptoNew(count);
	}
	static void* operator new[](std::size_t count) {
		return tscrypto::cryptoNew(count);
	}
		static void operator delete(void* ptr) {
		tscrypto::cryptoDelete(ptr);
	}
	static void operator delete[](void* ptr) {
		tscrypto::cryptoDelete(ptr);
	}

	SSL_HashAlgorithm hash;
	SSL_SignatureAlgorithm sig;
} CertAlg;

typedef struct {
	SSL_EXTENSION type;
	tsCryptoData value;
} ExtensionHolder;

static SSL_CIPHER gDefaultCiphers[] = {
	tsTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tsTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tsTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tsTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tsTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	tsTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tsTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	tsTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	tsTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tsTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tsTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tsTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tsTLS_RSA_WITH_AES_256_GCM_SHA384,
	tsTLS_RSA_WITH_AES_128_GCM_SHA256,
	tsTLS_RSA_WITH_AES_256_CBC_SHA256,
	tsTLS_RSA_WITH_AES_128_CBC_SHA256,
	tsTLS_RSA_WITH_AES_256_CBC_SHA,
	tsTLS_RSA_WITH_AES_128_CBC_SHA,
	//tsTLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	//tsTLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	//tsTLS_RSA_WITH_3DES_EDE_CBC_SHA,
	//tsTLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
	//tsTLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
	//tsTLS_DHE_DSS_WITH_AES_256_CBC_SHA,
	//tsTLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	//tsTLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
	//tsTLS_RSA_WITH_RC4_128_SHA,
	//tsTLS_RSA_WITH_RC4_128_MD5,
};
class SslHandshake_Client : public tscrypto::ICryptoObject, public ISslHandshake_Client, public IClientTunnel
{
public:
	SslHandshake_Client() : _major(3), _minor(3), _allowCompression(false), _initiatingCipherChange(false),
		_cipher(nullptr), 
		_compression(ssl_NoCompression), __state(ssl_conn_ProtocolClosed), _extended_master_secret(false), _useInternalCryptoList(true),
		_lastError(sslalert_no_error), _ctrlChannel(nullptr), _keyHandler(nullptr),
		rlDesc(nullptr)
	{
		_serverCerts = CreateTsCryptoDataList();
		rlDesc = (const TlsRecordLayer_Descriptor*)findCkmAlgorithm("TLS-RECORDLAYER");
		supDesc = (const TlsSupport_Descriptor*)findCkmAlgorithm("TLS-SUPPORT");
	}
	virtual ~SslHandshake_Client() 
	{
		if (rlDesc != nullptr && !rlWork.empty())
			rlDesc->finish(rlDesc, rlWork);
	}

	virtual void OnConstructionFinished() override
	{
	}

	// Inherited via IClientTunnel
	virtual bool GetMessageAuthBitSize(int & pVal) override
	{
		if (TunnelActive())
			return false;

		pVal = (int)_msgKeyBitSize;
		return true;
	}
	virtual bool GetMessageAuth(tsCryptoData & pVal) override
	{
		if (!TunnelActive() || _msgKey.size() == 0)
			return false;

		pVal = _msgKey;
		_msgKey.clear();
		return true;
	}
	virtual bool TunnelActive() override
	{
		return isValid() && __state == ssl_conn_Active;
	}
	virtual bool StartTunnel(const char * username, authenticationInitiatorTunnelKeyHandler * authHandler, authenticationControlDataCommunications * ctrlChannel) override
	{
		if (authHandler == nullptr || ctrlChannel == nullptr || rlDesc == nullptr)
			return false;

		StopTunnel();
		_keyHandler = authHandler;
		_ctrlChannel = ctrlChannel;

		if (rlDesc != nullptr)
			rlWork = rlDesc;

		if (!rlDesc->init(rlDesc, rlWork, &_handshakeDesc, this))
			return false;

		if (!!_packetReceiverFn)
			rlDesc->setOnPacketReceivedCallback(rlDesc, rlWork, _internalPacketReceivedFn, this);

		_username = username;
		__state = ssl_conn_ProtocolReset;
		if (!_sendClientHello())
		{
			StopTunnel();
			return false;
		}
		return true;
	}
	virtual bool StopTunnel() override
	{
		Logout();

		_keyHandler = nullptr;
		_ctrlChannel = nullptr;

		if (rlDesc != nullptr && !rlWork.empty())
			rlDesc->finish(rlDesc, rlWork);
		rlWork.reset();

		__state = ssl_conn_ProtocolReset;
		return true;
	}
	virtual bool Logout() override
	{
		std::shared_ptr<tscrypto::ICryptoObject> keepAlive = _me.lock();

		if (__state == ssl_conn_ProtocolReset || __state == ssl_conn_ProtocolClosed)
			return true;

		if (!changeState(ssl_conn_Logout) || rlDesc == nullptr || rlWork.empty())
			return false;

		if (__state != ssl_conn_ProtocolReset && __state != ssl_conn_ProtocolClosed &&
			__state != ssl_conn_Logout)
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_close_notify);
		}

		rlDesc->reset(rlDesc, rlWork);

		_resetTunnel();
		if (_ctrlChannel != nullptr)
			_ctrlChannel->setCloseAfterTransmit();

		return true;
	}
	virtual bool ReceiveData(const tsCryptoData & src) override
	{
		if (!isValid())
			return false;
		
		rlDesc->dataReceivedFromComms(rlDesc, rlWork, src.c_str(), (uint32_t)src.size());
		_lastError = rlDesc->processData(rlDesc, rlWork);
		
		if (_lastError != sslalert_no_error)
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, _lastError);
			StopTunnel();
			return false;
		}
		return true;
	}
	virtual bool SendData(const tsCryptoData & src) override
	{
		if (!isValid())
			return false;

		if (TunnelActive())
		{
			if (src.size() == 0)
				return false;
			tsCryptoData data;
			size_t posi = 0;
			size_t size;
			size_t outSize;
			uint32_t packetLen;

			while (posi < src.size())
			{
				size = src.size() - posi;
				if (size > MAX_DATA_SIZE)
					size = MAX_DATA_SIZE;

				data.resize(5);
				data[0] = ssl_application_data;
				data[1] = _major;
				data[2] = _minor;
				data[3] = (uint8_t)(size >> 8);
				data[4] = (uint8_t)(size & 0xff);

				data += src.substring(posi, size);

				packetLen = (uint32_t)data.size();
				data.resize(packetLen + 512);
				if (!rlDesc->packBlock(rlDesc, rlWork, data.rawData(), &packetLen, (uint32_t)data.size()))
				{
					Logout();
					return false;
				}
				data.resize(packetLen);

				outSize = data.size();
				if (!!_packetSentFn)
					_packetSentFn(data[0], data.c_str(), (uint32_t)data.size());

				if (_ctrlChannel == nullptr || !_ctrlChannel->sendControlData(data))
				{
					Logout();
					return false;
				}
				posi += size;
			}
			return true;
		}
		else
			return false;
	}
	virtual bool GetMessageEncryptionAlg(tscrypto::_POD_AlgorithmIdentifier & alg) override
	{
		alg = _msgEncAlg;
		return true;
	}
	virtual bool GetMessageHashAlg(tscrypto::_POD_AlgorithmIdentifier & alg) override
	{
		alg = _msgMacAlg;
		return true;
	}
	virtual bool SetOnPacketReceivedCallback(std::function<void(uint8_t packetType, const uint8_t*data, uint32_t dataLen)> func) override
	{
		_packetReceiverFn = func;
		if (rlDesc == nullptr || rlWork.empty())
			return true;
		return rlDesc->setOnPacketReceivedCallback(rlDesc, rlWork, _internalPacketReceivedFn, this);
	}
	virtual bool SetOnPacketSentCallback(std::function<void(uint8_t packetType, const uint8_t*data, uint32_t dataLen)> func) override
	{
		_packetSentFn = func;
		return true;
	}
	virtual bool useCompression() override
	{
		return _allowCompression;
	}
	virtual void useCompression(bool setTo) override
	{
		_allowCompression = setTo;
	}

	// Inherited via ISslHandshake_Client
	virtual void RegisterCertificateVerifier(std::function<SSL_AlertDescription(const tsCryptoDataList& certificate, SSL_CIPHER cipher)> func) override
	{
		certVerifierCB = func;
	}
	virtual void RegisterClientPSK(std::function<bool(const tsCryptoData& serverHint, tsCryptoData& clientHint, tsCryptoData& psk)> func) override
	{
		pskCB = func;
	}
	virtual void RegisterPasswordCallback(std::function<bool(tsCryptoData& password)> setTo) override
	{
		passwordCB = setTo;
	}
	virtual void setCiphersSupported(SSL_CIPHER* list, size_t count) override
	{
		if (list == nullptr || count == 0)
		{
			_useInternalCryptoList = true;

			_cipherList.clear();
		}
		else
		{
			_useInternalCryptoList = false;

			_cipherList.clear();
			_cipherList.reserve(count);
			for (size_t i = 0; i < count; i++)
			{
				_cipherList.push_back(list[i]);
			}
		}
	}

private:
	bool handleServerHello(const tsCryptoData& buffer)
	{
		size_t offset = 0;
		uint8_t serverMajor, serverMinor;
		uint16_t serverCipher;
		uint8_t compressor;
		tsCryptoData extensionData;

		//struct { 
		//	ProtocolVersion server_version;          
		//	Random random;          
		//	SessionID session_id;          
		//	CipherSuite cipher_suite;          
		//	CompressionMethod compression_method;          
		//	select(extensions_present) { 
		//		case false:                  
		//			struct {};              
		//		case true:                  
		//			Extension extensions<0..2 ^ 16 - 1>; 
		//	}; 
		//} ServerHello;

		if (!changeState(ssl_conn_Server_Hello))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}
		_serverRandom.clear();

		if (!getU1(buffer, offset, serverMajor) || !getU1(buffer, offset, serverMinor) ||
			!getFixedBuffer(buffer, offset, 32, _serverRandom) ||
			!getU1Buffer(buffer, offset, _sessionId) ||
			!getU2(buffer, offset, serverCipher) ||
			!getU1(buffer, offset, compressor))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_decode_error);
			StopTunnel();
			return false;
		}
		if (offset < buffer.size())
		{
			if (!getU2Buffer(buffer, offset, extensionData))
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_decode_error);
				StopTunnel();
				return false;
			}
		}
		if (offset != buffer.size())
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_record_overflow);
			StopTunnel();
			return false;
		}


		if (serverMajor != _major || serverMinor < _minor)
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_protocol_version);
			StopTunnel();
			return false;
		}

		// Now extensions
		if (extensionData.size() > 0)
		{
			size_t extensionOffset = 0;

			while (extensionOffset < extensionData.size())
			{
				uint16_t type;
				tsCryptoData value;

				if (!getU2(extensionData, extensionOffset, type) ||
					!getU2Buffer(extensionData, extensionOffset, value))
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_decode_error);
					StopTunnel();
					return false;
				}
				if (type == TLS_EXT_extended_master_secret)
					_extended_master_secret = true;
				else if (type == TLS_EXT_ec_point_formats)
				{
					// TODO:  Handle the points here
				}
				else if (type == TLS_EXT_supported_groups)
				{
					// TODO:  Handle the curves here
				}
				else if (type == TLS_EXT_CkmAuth)
				{
					_POD_CkmAuthTlsExtResponse ckmAuthData;

					_msgEncAlg.clear();
					_msgMacAlg.clear();
					if (ckmAuthData.Decode(value))
					{
						_msgKeyBitSize = ckmAuthData.get_MessageKeySizeInBits();
						if (ckmAuthData.exists_MessageEncryptionAlg())
							_msgEncAlg = *ckmAuthData.get_MessageEncryptionAlg();
						if (ckmAuthData.exists_MessageHashAlg())
							_msgMacAlg = *ckmAuthData.get_MessageHashAlg();
					}
					else if (value.size() == 2)
					{
						_msgKeyBitSize = (value[0] << 8) | (value[1]);
					}
				}
				else if (type == TLS_EXT_srp)
				{
					// TODO:  Handle user names here
				}
				else
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_unsupported_extension);
					StopTunnel();
				}
				//TODO:  Implement additional extensions here
			}
		}

		_cipher = supDesc->getCipherInfo((SSL_CIPHER)serverCipher);
		if (_cipher == nullptr)
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}

		//typedef struct {
		//	uint8_t msgType;
		//	uint8_t length[3];
		//} HandshakeMessageHeader;
		_handshakeData << (uint8_t)ssl_hs_server_hello << (uint8_t)(buffer.size() >> 16) << (uint8_t)(buffer.size() >> 8) << (uint8_t)(buffer.size() & 0xff) << buffer;

		if (serverCipher == tsTLS_NULL_WITH_NULL_NULL)
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}
		return true;
	}
	bool handleServerCertificate(const tsCryptoData& buffer)
	{
		size_t offset = 0;
		tsCryptoData certificateData;
		size_t certOffset = 0;

		//struct { 
		//	ProtocolVersion server_version;          
		//	Random random;          
		//	SessionID session_id;          
		//	CipherSuite cipher_suite;          
		//	CompressionMethod compression_method;          
		//	select(extensions_present) { 
		//		case false:                  
		//			struct {};              
		//		case true:                  
		//			Extension extensions<0..2 ^ 16 - 1>; 
		//	}; 
		//} ServerHello;

		_handshakeData << (uint8_t)ssl_hs_certificate << (uint8_t)(buffer.size() >> 16) << (uint8_t)(buffer.size() >> 8) << (uint8_t)(buffer.size() & 0xff) << buffer;

		if (!changeState(ssl_conn_Server_Certificate))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}
		if (!getU3Buffer(buffer, offset, certificateData))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_decode_error);
			StopTunnel();
			return false;
		}
		if (offset != buffer.size())
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_record_overflow);
			StopTunnel();
			return false;
		}

		while (certOffset < certificateData.size())
		{
			tsCryptoData cert;
			if (!getU3Buffer(certificateData, certOffset, cert))
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_decode_error);
				StopTunnel();
				return false;
			}
			_serverCerts->push_back(cert);
		}

		// TODO:  Validate the ertificates here
		if (!!certVerifierCB)
		{
			_lastError = certVerifierCB(_serverCerts, _cipher->value);
			if (_lastError != sslalert_no_error)
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, _lastError);
				StopTunnel();
				return false;
			}
		}

		tsCertificateParser parser;

		if (_serverCerts->size() == 0 || !parser.LoadCertificate(_serverCerts->at(0)))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_decode_error);
			StopTunnel();
			return false;
		}

		tsCryptoString oid = parser.SignatureAlgorithmOID().ToOIDString();

		if (oid == RSA_SHA1_SIGN_OID)
		{
			_certAlg.hash = sslhash_sha1;
			_certAlg.sig = sslsign_rsa;
		}
		else if (oid == RSA_SHA224_SIGN_OID)
		{
			_certAlg.hash = sslhash_sha224;
			_certAlg.sig = sslsign_rsa;
		}
		else if (oid == RSA_SHA256_SIGN_OID)
		{
			_certAlg.hash = sslhash_sha256;
			_certAlg.sig = sslsign_rsa;
		}
		else if (oid == RSA_SHA384_SIGN_OID)
		{
			_certAlg.hash = sslhash_sha384;
			_certAlg.sig = sslsign_rsa;
		}
		else if (oid == RSA_SHA512_SIGN_OID)
		{
			_certAlg.hash = sslhash_sha512;
			_certAlg.sig = sslsign_rsa;
		}
		else if (oid == ECDSA_SHA1_OID)
		{
			_certAlg.hash = sslhash_sha1;
			_certAlg.sig = sslsign_ecdsa;
		}
		else if (oid == ECDSA_SHA224_OID)
		{
			_certAlg.hash = sslhash_sha224;
			_certAlg.sig = sslsign_ecdsa;
		}
		else if (oid == ECDSA_SHA256_OID)
		{
			_certAlg.hash = sslhash_sha256;
			_certAlg.sig = sslsign_ecdsa;
		}
		else if (oid == ECDSA_SHA384_OID)
		{
			_certAlg.hash = sslhash_sha384;
			_certAlg.sig = sslsign_ecdsa;
		}
		else if (oid == ECDSA_SHA512_OID)
		{
			_certAlg.hash = sslhash_sha512;
			_certAlg.sig = sslsign_ecdsa;
		}
		else if (oid == DSA_SHA1_OID)
		{
			_certAlg.hash = sslhash_sha1;
			_certAlg.sig = sslsign_dsa;
		}
		else if (oid == NIST_DSA_SHA224_OID)
		{
			_certAlg.hash = sslhash_sha224;
			_certAlg.sig = sslsign_dsa;
		}
		else if (oid == NIST_DSA_SHA256_OID)
		{
			_certAlg.hash = sslhash_sha256;
			_certAlg.sig = sslsign_dsa;
		}
		else if (oid == DSA_PARAMETER_SET)
		{
			_certAlg.hash = sslhash_sha1;
			_certAlg.sig = sslsign_dsa;
		}
		else
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_decode_error);
			StopTunnel();
			return false;
		}

		return true;
	}
	bool handleServerHelloDone(const tsCryptoData& buffer)
	{
		uint8_t buff1[1] = { 1 };

		if (!changeState(ssl_conn_Server_Hello_Done))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}

		_handshakeData << (uint8_t)ssl_hs_server_hello_done << (uint8_t)(buffer.size() >> 16) << (uint8_t)(buffer.size() >> 8) << (uint8_t)(buffer.size() & 0xff) << buffer;

		if (!_sendClientKeyExchange())
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}

		if (!changeState(ssl_conn_Client_Send_Change_Cipher_Spec))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}
		if (rlDesc->sendChangeCipherSpec(rlDesc, rlWork, buff1, 1) != sslalert_no_error)
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}



		if (!changeState(ssl_conn_Client_Finished))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}
		if (!_sendClientFinished())
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}


		return true;
	}
	bool handleServerFinished(const tsCryptoData& buffer)
	{
		tsCryptoData hash;

		if (!changeState(ssl_conn_Server_Finished))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}

		if (!TSHash(_handshakeData, hash, _cipher->helloHasher))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}

		tsCryptoData verificationData;
		
		verificationData.resize(_cipher->verify_length);
		if (!supDesc->PRF(_cipher->prfHasher, _master_secret.c_str(), (uint32_t)_master_secret.size(), "server finished", hash.c_str(), (uint32_t)hash.size(), _cipher->verify_length, verificationData.rawData()) ||
		    buffer != verificationData)
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}

		if (!changeState(ssl_conn_Active))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}
		return true;
	}
	bool handleHelloRequest(const tsCryptoData& buffer)
	{
		tsCryptoData hash;

		if (buffer.size() != 0)
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_decode_error);
			StopTunnel();
			return false;
		}

		if (__state != ssl_conn_Active)
			return true;

		if (!changeState(ssl_conn_Hello_Request))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}

		if (!changeState(ssl_conn_Client_Hello))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}
		if (!_sendClientHello())
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}

		return true;
	}
	bool handleServerKeyExchange(const tsCryptoData& buffer)
	{
		tsCryptoData hash;
		size_t offset = 0;

		_handshakeData << (uint8_t)ssl_hs_server_key_exchange << (uint8_t)(buffer.size() >> 16) << (uint8_t)(buffer.size() >> 8) << (uint8_t)(buffer.size() & 0xff) << buffer;

		if (!changeState(ssl_conn_Server_Key_Exchange))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}

		if (_cipher->KeyExchange == sslke_ec_diffie_hellman_ephemeral)
		{
			if (!process_ECDHE_Server_Key_Exchange(buffer, offset))
				return false;
		}
		else if (_cipher->KeyExchange == sslke_dhe)
		{
			if (!process_DHE_Server_Key_Exchange(buffer, offset))
				return false;
		}
		else if (_cipher->KeyExchange == sslke_ckmauth)
		{
			if (!process_CkmAuth_Server_Key_Exchange(buffer, offset))
				return false;
		}
		else if (_cipher->KeyExchange == sslke_psk || _cipher->KeyExchange == sslke_rsa_psk || _cipher->KeyExchange == sslke_ecdhe_psk || _cipher->KeyExchange == sslke_dhe_psk)
		{
			tsCryptoData hint;

			if (!getU2Buffer(buffer, offset, hint))
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_decode_error);
				StopTunnel();
				return false;
			}
			if (!pskCB)
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
				StopTunnel();
				return false;
			}
			if (!pskCB(hint, _pskIdentity, _psk))
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
				StopTunnel();
				return false;
			}
			if (_cipher->KeyExchange == sslke_ecdhe_psk)
			{
				if (!process_ECDHE_Server_Key_Exchange(buffer, offset))
					return false;
			}
			else if (_cipher->KeyExchange == sslke_dhe_psk)
			{
				if (!process_DHE_Server_Key_Exchange(buffer, offset))
					return false;
			}
		}
		else
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}


		return true;
	}
	bool handleHandshakeMessage(const uint8_t* data, uint32_t dataLen)
	{
		SSL_HandshakeType type;
		tsCryptoData buffer;

		{
			TSAUTOLOCKER lock(_bufferedHSDataLock);
			_bufferedHSData.append(data, dataLen);
		}
		while (GetHandshakeMessage(type, buffer))
		{
			// Now process the message
			switch (type)
			{
			case ssl_hs_hello_request:
				if (!handleHelloRequest(buffer))
					return false;
				break;
				//case client_hello:
				//	LOG(gSslState, "client_hello");
				//	break;
			case ssl_hs_server_hello:
				if (!handleServerHello(buffer))
					return false;
				break;
			case ssl_hs_certificate:
				if (!handleServerCertificate(buffer))
					return false;
				break;
			case ssl_hs_server_key_exchange:
				if (!handleServerKeyExchange(buffer))
					return false;
				break;
			case ssl_hs_certificate_request:
				// TODO:  Implement me
				break;
			case ssl_hs_server_hello_done:
				if (!handleServerHelloDone(buffer))
					return false;
				break;
				//case certificate_verify:
				//	LOG(gSslState, "certificate_verify");
				//	break;
				//case client_key_exchange:
				//	LOG(gSslState, "client_key_exchange");
				//	break;
			case ssl_hs_finished:
				if (!handleServerFinished(buffer))
					return false;
				break;
			default:
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
				StopTunnel();
				return false;
			}
		}
		return true;
	}
	uint32_t GetBEUint24(const uint8_t* ptr)
	{
		if (ptr == nullptr)
			return 0;

		return (ptr[0] << 16) | (ptr[1] << 8) | ptr[2];
	}
	bool GetHandshakeMessage(SSL_HandshakeType& type, tsCryptoData& buffer)
	{
		TSAUTOLOCKER lock(_bufferedHSDataLock);

		//typedef struct {
		//	uint8_t msgType;
		//	uint8_t length[3];
		//} HandshakeMessageHeader;

		buffer.clear();
		type = (SSL_HandshakeType)0;
		if (_bufferedHSData.size() > 3)
		{
			uint32_t len = GetBEUint24(_bufferedHSData.c_str() + 1);
			if (_bufferedHSData.size() >= 4 + len)
			{
				buffer.assign(_bufferedHSData.c_str() + 4, len);
				type = (SSL_HandshakeType)_bufferedHSData.c_str()[0];
				_bufferedHSData.erase(0, 4 + len);
				return true;
			}
		}
		return false;
	}
	bool _sendClientHello()
	{
		tsCryptoData buffer;
		tsCryptoData payload;
		size_t count;
		uint32_t packetLen;

		_psk.clear();
		_pskIdentity.clear();
		_dhParams.reset();
		_ckmAuthSessionKey.clear();
		if (!changeState(ssl_conn_Client_Hello))
		{
			return false;
		}

		//struct { 
		//	uint32 gmt_unix_time;       
		//	opaque random_bytes[28]; 
		//} Random;
		//opaque SessionID<0..32>;
		//uint8 CipherSuite[2];
		//struct { 
		//	ProtocolVersion client_version;       
		//	Random random;       
		//	SessionID session_id;       
		//	CipherSuite cipher_suites<2..2 ^ 16 - 2>;       
		//	CompressionMethod compression_methods<1..2 ^ 8 - 1>;       
		//	select(extensions_present) { 
		//		case false:               
		//			struct {};           
		//		case true:               
		//			Extension extensions<0..2 ^ 16 - 1>; 
		//	}; 
		//} ClientHello;
		payload.resize(2);
		payload[0] = _major;
		payload[1] = _minor;
		computeClientRandom();
		payload << _clientRandom;
		payload << (uint8_t)0; // no session id
		// Add the ciphers
		if (_useInternalCryptoList)
		{
			count = sizeof(gDefaultCiphers) / sizeof(gDefaultCiphers[0]) * 2; // make it bytes
			payload << (uint8_t)(count >> 8) << (uint8_t)(count & 0xff);
			count /= 2;
			for (size_t i = 0; i < count; i++)
			{
				payload << (uint8_t)(gDefaultCiphers[i] >> 8) << (uint8_t)(gDefaultCiphers[i] & 0xff);
			}
		}
		else
		{
			count = _cipherList.size() * 2; // make it bytes
			payload << (uint8_t)(count >> 8) << (uint8_t)(count & 0xff);
			count /= 2;
			for (size_t i = 0; i < count; i++)
			{
				payload << (uint8_t)(_cipherList[i] >> 8) << (uint8_t)(_cipherList[i] & 0xff);
			}
		}
		if (useCompression())
		{
			payload << (uint8_t)2 << (uint8_t)ssl_DeflateCompression << (uint8_t)ssl_NoCompression;
		}
		else
		{
			payload << (uint8_t)1 << (uint8_t)ssl_NoCompression;
		}
		// Handle extensions here
		tsCryptoData extensions;

		// Add extended master secret extension
		extensions << (uint8_t)(TLS_EXT_extended_master_secret >> 8) << (uint8_t)(TLS_EXT_extended_master_secret & 0xff) << (uint8_t)(0) << (uint8_t)(0);
		// ec_point_format
		extensions << (uint8_t)(TLS_EXT_ec_point_formats >> 8) << (uint8_t)(TLS_EXT_ec_point_formats & 0xff) << (uint8_t)(0) << (uint8_t)(2) << (uint8_t)(1) << (uint8_t)(_SSL_ECPointFormat::ssl_point_uncompressed);
		// curves
		extensions << (uint8_t)(TLS_EXT_supported_groups >> 8) << (uint8_t)(TLS_EXT_supported_groups & 0xff) << (uint8_t)(0) << (uint8_t)(8) << (uint8_t)(0) << (uint8_t)(6)
			<< (uint8_t)(ssl_secp256r1 >> 8) << (uint8_t)(ssl_secp256r1 & 0xff) << (uint8_t)(ssl_secp384r1 >> 8) << (uint8_t)(ssl_secp384r1 & 0xff) << (uint8_t)(ssl_secp256r1 >> 8) << (uint8_t)(ssl_secp256r1 & 0xff);

		if (_username.size() > 0)
		{
			// SRP extension to pass CkmAuth username to the server
			extensions << (uint8_t)(TLS_EXT_CkmAuth >> 8) << (uint8_t)(TLS_EXT_CkmAuth & 0xff) << (uint8_t)((_username.size() + 1) >> 8) << (uint8_t)((_username.size() + 1) & 0xff) << (uint8_t)(_username.size() & 0xff) << _username;
		}


		if (extensions.size() > 0)
		{
			payload << (uint8_t)(extensions.size() >> 8) << (uint8_t)(extensions.size() & 0xff);
			payload << extensions;
		}



		//typedef struct {
		//	uint8_t msgType;
		//	uint8_t length[3];
		//} HandshakeMessageHeader;

		buffer.resize(4);
		buffer[0] = ssl_hs_client_hello;
		buffer[1] = (uint8_t)(payload.size() >> 16);
		buffer[2] = (uint8_t)(payload.size() >> 8);
		buffer[3] = (uint8_t)(payload.size() & 0xff);
		buffer << payload;

		_handshakeData << buffer;

		packetLen = (uint32_t)buffer.size();
		buffer.resize(packetLen + 512);
		_lastError = rlDesc->sendData(rlDesc, rlWork, ssl_handshake, buffer.rawData(), packetLen);
		return _lastError == sslalert_no_error;
	}
	bool _sendClientKeyExchange()
	{
		tsCryptoData buffer;
		tsCryptoData payload;
		tsCryptoData preMaster;
		std::shared_ptr<AsymmetricKey> certKey;
		std::shared_ptr<EccKey> ecc;
		std::shared_ptr<RsaKey> rsa;
		std::shared_ptr<DhKey> dh;
		std::shared_ptr<TSALG_Access> tsAlg;
		uint32_t packetLen;

		if (_cipher->CertSign == sslsign_dsa || _cipher->CertSign == sslsign_rsa || _cipher->CertSign == sslsign_ecdsa)
		{
			if (_serverCerts->size() == 0)
			{
				return false;
			}

			tsCertificateParser cert;

			if (!cert.LoadCertificate(_serverCerts->at(0)))
			{
				return false;
			}
			certKey = cert.getPublicKeyObject();
			ecc = std::dynamic_pointer_cast<EccKey>(certKey);
			rsa = std::dynamic_pointer_cast<RsaKey>(certKey);
			dh = std::dynamic_pointer_cast<DhKey>(certKey);
			tsAlg = std::dynamic_pointer_cast<TSALG_Access>(certKey);
		}

		if (!changeState(ssl_conn_Client_Key_Exchange))
		{
			return false;
		}

		//struct { 
		//	select(KeyExchangeAlgorithm) {
		//		case rsa:               
		//			EncryptedPreMasterSecret;           
		//		case dhe_dss:           
		//		case dhe_rsa:           
		//		case dh_dss:           
		//		case dh_rsa:           
		//		case dh_anon:               
		//			ClientDiffieHellmanPublic; 
		//	} exchange_keys; 
		//} ClientKeyExchange;
		//struct { 
		//	ProtocolVersion client_version;       
		//	opaque random[46]; 
		//} PreMasterSecret;
		//struct { 
		//	public-key-encrypted PreMasterSecret pre_master_secret; 
		//} EncryptedPreMasterSecret;
		//enum { implicit, explicit } PublicValueEncoding;
		//struct { 
		//	select(PublicValueEncoding) { 
		//		case implicit: 
		//			struct {};           
		//		case explicit: 
		//			opaque DH_Yc<1..2 ^ 16 - 1>; 
		//	} dh_public; 
		//} ClientDiffieHellmanPublic;

		if (_cipher->KeyExchange == sslke_ec_diffie_hellman_ephemeral)
		{
			std::shared_ptr<EccKey> ephem;

			ecc = std::dynamic_pointer_cast<EccKey>(_serverEphemeral);
			ephem = std::dynamic_pointer_cast<EccKey>(ecc->generateNewKeyPair());

			if (!ephem)
			{
				return false;
			}
			payload = ephem->get_Point();

			if (!ephem->ComputeZ(ecc, preMaster))
			{
				return false;
			}
			uint16_t len = (uint16_t)payload.size();
			payload.insert(0, (uint8_t)(len & 0xff));
		}
		else if (_cipher->KeyExchange == sslke_dhe)
		{
			std::shared_ptr<DhKey> ephem;

			dh = std::dynamic_pointer_cast<DhKey>(_serverEphemeral);
			ephem = std::dynamic_pointer_cast<DhKey>(dh->generateNewKeyPair());

			if (!ephem)
			{
				return false;
			}
			payload = ephem->get_PublicKey();

			if (!ephem->ComputeZ(_serverEphemeral, preMaster))
			{
				return false;
			}
			uint16_t len = (uint16_t)payload.size();
			payload.insert(0, (uint8_t)(len & 0xff));
			payload.insert(0, (uint8_t)(len >> 8));
		}
		else if (_cipher->KeyExchange == sslke_ckmauth)
		{
			tsCryptoData clientPoint, ekgk, oidInfo, initProof;
			_POD_CkmAuthResponderParameters respParams;

			if (!respParams.Decode(_ckmAuthResponderParams))
			{
				return false;
			}

			payload << (uint8_t)(respParams.get_ephemeralPublic().size() & 0xff) << respParams.get_ephemeralPublic();
			payload << (uint8_t)(respParams.get_eKGK().size() & 0xff) << respParams.get_eKGK();
			payload << (uint8_t)(respParams.get_oidInfo().size() >> 8) << (uint8_t)(respParams.get_oidInfo().size() & 0xff) << respParams.get_oidInfo();
			payload << (uint8_t)(respParams.get_initiatorAuthProof().size() & 0xff) << respParams.get_initiatorAuthProof();

			preMaster = std::move(_ckmAuthSessionKey);
		}
		else if (_cipher->KeyExchange == sslke_psk)
		{
			if (_pskIdentity.empty())
			{
				if (!pskCB)
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
					StopTunnel();
					return false;
				}
				if (!pskCB(tsCryptoData(), _pskIdentity, _psk))
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
					StopTunnel();
					return false;
				}
			}
			uint16_t len = (uint16_t)_pskIdentity.size();
			payload << (uint8_t)(len >> 8) << (uint8_t)(len & 0xff) << _pskIdentity;
			preMaster << (uint8_t)(_psk.size() >> 8) << (uint8_t)(_psk.size() & 0xff);
			preMaster.resize(_psk.size() + 2);
			preMaster << (uint8_t)(_psk.size() >> 8) << (uint8_t)(_psk.size() & 0xff) << _psk;
		}
		else if (_cipher->KeyExchange == sslke_ecdhe_psk)
		{
			std::shared_ptr<EccKey> ephem;
			tsCryptoData point;
			tsCryptoData Z;

			if (_pskIdentity.empty())
			{
				if (!pskCB)
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
					StopTunnel();
					return false;
				}
				if (!pskCB(tsCryptoData(), _pskIdentity, _psk))
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
					StopTunnel();
					return false;
				}
			}
			uint16_t len = (uint16_t)_pskIdentity.size();
			payload << (uint8_t)(len >> 8) << (uint8_t)(len & 0xff) << _pskIdentity;

			ecc = std::dynamic_pointer_cast<EccKey>(_serverEphemeral);
			ephem = std::dynamic_pointer_cast<EccKey>(ecc->generateNewKeyPair());

			if (!ephem)
			{
				return false;
			}
			point = ephem->get_Point();

			if (!ephem->ComputeZ(ecc, Z))
			{
				return false;
			}
			len = (uint16_t)point.size();
			payload << (uint8_t)(len & 0xff) << point;
			preMaster << (uint8_t)(Z.size() >> 8) << (uint8_t)(Z.size() & 0xff) << Z;
			preMaster << (uint8_t)(_psk.size() >> 8) << (uint8_t)(_psk.size() & 0xff) << _psk;
		}
		else if (_cipher->KeyExchange == sslke_dhe_psk)
		{
			std::shared_ptr<DhKey> ephem;
			tsCryptoData Z;
			tsCryptoData Y;

			if (_pskIdentity.empty())
			{
				if (!pskCB)
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
					StopTunnel();
					return false;
				}
				if (!pskCB(tsCryptoData(), _pskIdentity, _psk))
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
					StopTunnel();
					return false;
				}
			}

			uint16_t len = (uint16_t)_pskIdentity.size();
			payload << (uint8_t)(len >> 8) << (uint8_t)(len & 0xff) << _pskIdentity;


			dh = std::dynamic_pointer_cast<DhKey>(_serverEphemeral);
			ephem = std::dynamic_pointer_cast<DhKey>(dh->generateNewKeyPair());

			if (!ephem)
			{
				return false;
			}
			Y = ephem->get_PublicKey();

			if (!ephem->ComputeZ(_serverEphemeral, preMaster))
			{
				return false;
			}

			len = (uint16_t)Y.size();
			payload << (uint8_t)(len >> 8) << (uint8_t)(len & 0xff) << Y;
			preMaster << (uint8_t)(Z.size() >> 8) << (uint8_t)(Z.size() & 0xff) << Z;
			preMaster << (uint8_t)(_psk.size() >> 8) << (uint8_t)(_psk.size() & 0xff) << _psk;
		}
		else if (_cipher->KeyExchange == sslke_rsa_psk)
		{
			if (_pskIdentity.empty())
			{
				if (!pskCB)
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
					StopTunnel();
					return false;
				}
				if (!pskCB(tsCryptoData(), _pskIdentity, _psk))
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
					StopTunnel();
					return false;
				}
			}

			uint16_t len = (uint16_t)_pskIdentity.size();
			payload << (uint8_t)(len >> 8) << (uint8_t)(len & 0xff) << _pskIdentity;

			if (!rsa || !tsAlg)
			{
				return false;
			}

			tsCryptoData R;
			uint32_t Rlen = 512;

			GenerateRandom(R, 46);
			preMaster << _major << _minor << R;

			const RSA_Descriptor* rsaDesc = ((const RSA_Descriptor*)tsAlg->Descriptor());
			CRYPTO_ASYMKEY keyPair = tsAlg->getKeyPair();

			R.clear();
			R.resize(Rlen);

			if (!rsaDesc->encodePkcsAndEncrypt(rsaDesc, keyPair, preMaster.c_str(), (uint32_t)preMaster.size(), R.rawData(), &Rlen))
			//if (!TSRSAEncrypt(rsa, preMaster, R))
			{
				return false;
			}
			R.resize(Rlen);
			payload << (uint8_t)(R.size() >> 8) << (uint8_t)(R.size() & 0xff);
			payload << R;

			preMaster << (uint8_t)(_psk.size() >> 8) << (uint8_t)(_psk.size() & 0xff) << _psk;
		}
		else if (!!rsa)
		{
			// 7.4.7.1
			tsCryptoData R;
			uint32_t len = 512;

			GenerateRandom(R, 46);
			preMaster << _major << _minor << R;

			const RSA_Descriptor* rsaDesc = ((const RSA_Descriptor*)tsAlg->Descriptor());
			CRYPTO_ASYMKEY keyPair = tsAlg->getKeyPair();

			R.clear();
			payload.resize(len);

			if (!rsaDesc->encodePkcsAndEncrypt(rsaDesc, keyPair, preMaster.c_str(), (uint32_t)preMaster.size(), payload.rawData(), &len))
			//if (!TSRSAEncrypt(rsa, preMaster, payload))
			{
				return false;
			}
			payload.resize(len);
			payload.insert(0, (uint8_t)(len & 0xff));
			payload.insert(0, (uint8_t)(len >> 8));
		}
		else if (!!dh)
		{
			// 7.4.7.2
			std::shared_ptr<DhKey> ephem;
			std::shared_ptr<DhKey> dhKey;
			tsCertificateParser parser;

			if (_serverCerts->size() == 0 || !parser.LoadCertificate(_serverCerts->at(0)))
			{
				return false;
			}
			dhKey = std::dynamic_pointer_cast<DhKey>(parser.getPublicKeyObject());
			if (!dhKey)
			{
				return false;
			}

			ephem = std::dynamic_pointer_cast<DhKey>(dhKey->generateNewKeyPair());

			if (!ephem)
			{
				return false;
			}
			payload = ephem->get_PublicKey();

			if (!ephem->ComputeZ(dhKey, preMaster))
			{
				return false;
			}
			uint16_t len = (uint16_t)payload.size();
			payload.insert(0, (uint8_t)(len & 0xff));
			payload.insert(0, (uint8_t)(len >> 8));
		}
		else if (!!ecc)
		{
			std::shared_ptr<EccKey> ephem;
			std::shared_ptr<EccKey> ecc1;
			tsCertificateParser parser;

			if (_serverCerts->size() == 0 || !parser.LoadCertificate(_serverCerts->at(0)))
			{
				return false;
			}
			ecc1 = std::dynamic_pointer_cast<EccKey>(parser.getPublicKeyObject());
			if (!ecc1)
			{
				return false;
			}

			ephem = std::dynamic_pointer_cast<EccKey>(ecc1->generateNewKeyPair());

			if (!ephem)
			{
				return false;
			}
			payload = ephem->get_Point();

			if (!ephem->ComputeZ(ecc1, preMaster))
			{
				return false;
			}
			uint16_t len = (uint16_t)payload.size();
			payload.insert(0, (uint8_t)(len & 0xff));
		}
		else
		{
			// TODO:  Handle error here
			return false;
		}

		//typedef struct {
		//	uint8_t msgType;
		//	uint8_t length[3];
		//} HandshakeMessageHeader;

		buffer.resize(4);
		buffer[0] = ssl_hs_client_key_exchange;
		buffer[1] = (uint8_t)(payload.size() >> 16);
		buffer[2] = (uint8_t)(payload.size() >> 8);
		buffer[3] = (uint8_t)(payload.size() & 0xff);
		buffer << payload;

		_handshakeData << buffer;

		packetLen = (uint32_t)buffer.size();
		buffer.resize(packetLen + 512);
		_lastError = rlDesc->sendData(rlDesc, rlWork, ssl_handshake, buffer.rawData(), packetLen);
		if (_lastError != sslalert_no_error)
		{
			return false;
		}

		//master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47];

		// Test the PRF
		//tsCryptoData secret("9b be 43 6b a9 40 f0 17 b1 76 52 84 9a 71 db 35", tsCryptoData::HEX);
		//tsCryptoData seed("a0 ba 9f 93 6c da 31 18 27 a6 f7 96 ff d5 19 8c", tsCryptoData::HEX);
		//tsCryptoData needed("e3 f2 29 ba 72 7b e1 7b 8d 12 26 20 55 7c d4 53 c2 aa b2 1d 07 c3 d4 95 32 9b 52 d4 e6 1e db 5a 6b 30 17 91 e9 0d 35 c9 c9 a4 6b 4e 14 ba f9 af 0f a0 22 f7 07 7d ef 17 ab fd 37 97 c0 56 4b ab 4f bc 91 66 6e 9d ef 9b 97 fc e3 4f 79 67 89 ba a4 80 82 d1 22 ee 42 c5 a7 2e 5a 51 10 ff f7 01 87 34 7b 66", tsCryptoData::HEX);
		//tsCryptoData output = PRF(secret, "test label", seed, 100);

		//if (output != needed)
		//{
		//	// TODO:  Handle error here
		//	return false;
		//}




		if (_extended_master_secret)
		{
			tsCryptoData emsHash;

			if (!TSHash(_handshakeData, emsHash, _cipher->helloHasher))
			{
				return false;
			}
			_master_secret.resize(48);
			if (!supDesc->PRF(_cipher->prfHasher, preMaster.c_str(), (uint32_t)preMaster.size(), "extended master secret", emsHash.c_str(), (uint32_t)emsHash.size(), 48, _master_secret.rawData()))
				return false;
		}
		else
		{
			tsCryptoData tmp;
			tmp << _clientRandom << _serverRandom;

			if (!supDesc->PRF(_cipher->prfHasher, preMaster.c_str(), (uint32_t)preMaster.size(), "master secret", tmp.c_str(), (uint32_t)tmp.size(), 48, _master_secret.rawData()))
				return false;
		}

		// Now we need to build up the crypto parts and the keys for them.
		// Client Mac Key
		// Server Mac Key
		// Client key
		// Server key
		// Client IV
		// Server IV
		uint32_t keyLenNeeded = _cipher->keySizeInBytes * 2 + _cipher->ivSizeInBytes * 2 + _cipher->hashKeySizeInBytes * 2;
		tsCryptoData tmp2;
		tmp2 << _serverRandom << _clientRandom;
		tsCryptoData keys;
		
		keys.resize(keyLenNeeded);
		if (!supDesc->PRF(_cipher->prfHasher, _master_secret.c_str(), (uint32_t)_master_secret.size(), "key expansion", tmp2.c_str(), (uint32_t)tmp2.size(), keyLenNeeded, keys.rawData()))
			return false;

		if (!rlDesc->setReceiveCryptoSuite(rlDesc, rlWork, _cipher->Encryptor, _cipher->hasher, 
				keys.substring(_cipher->hashKeySizeInBytes * 2 + _cipher->keySizeInBytes, _cipher->keySizeInBytes).c_str(), _cipher->keySizeInBytes,
				keys.substring(_cipher->hashKeySizeInBytes * 2 + _cipher->keySizeInBytes * 2 + _cipher->ivSizeInBytes, _cipher->ivSizeInBytes).c_str(), _cipher->ivSizeInBytes, 
				keys.substring(_cipher->hashKeySizeInBytes, _cipher->hashKeySizeInBytes).c_str(), _cipher->hashKeySizeInBytes, _compression, _cipher->tagLength))
		{
			return false;
		}
		if (!rlDesc->setSendCryptoSuite(rlDesc, rlWork, _cipher->Encryptor, _cipher->hasher, 
				keys.substring(_cipher->hashKeySizeInBytes * 2, _cipher->keySizeInBytes).c_str(), _cipher->keySizeInBytes,
				keys.substring(_cipher->hashKeySizeInBytes * 2 + _cipher->keySizeInBytes * 2, _cipher->ivSizeInBytes).c_str(), _cipher->ivSizeInBytes,
				keys.substring(0, _cipher->hashKeySizeInBytes).c_str(), _cipher->hashKeySizeInBytes, 
				_compression, _cipher->tagLength))
		{
			return false;
		}

		return true;
	}
	bool _sendClientFinished()
	{
		uint8_t buffer[384];
		uint32_t packetLen;
		tsCryptoData hash;

		if (!changeState(ssl_conn_Client_Finished))
		{
			return false;
		}

		if (!TSHash(_handshakeData, hash, _cipher->helloHasher))
		{
			return false;
		}

		tsCryptoData verificationData;

		verificationData.resize(_cipher->verify_length);
		if (!supDesc->PRF(_cipher->prfHasher, _master_secret.c_str(), (uint32_t)_master_secret.size(), "client finished", hash.c_str(), (uint32_t)hash.size(), _cipher->verify_length, verificationData.rawData()))
			return false;

		//typedef struct {
		//	uint8_t msgType;
		//	uint8_t length[3];
		//} HandshakeMessageHeader;

		buffer[0] = ssl_hs_finished;
		buffer[1] = (uint8_t)(verificationData.size() >> 16);
		buffer[2] = (uint8_t)(verificationData.size() >> 8);
		buffer[3] = (uint8_t)(verificationData.size() & 0xff);
		memcpy(buffer + 4, verificationData.c_str(), verificationData.size());
		packetLen = 4 + (uint32_t)verificationData.size();

		_handshakeData.append(buffer, packetLen);

		_lastError = rlDesc->sendData(rlDesc, rlWork, ssl_handshake, buffer, packetLen);
		memset(buffer, 0, sizeof(buffer));
		return _lastError == sslalert_no_error;
	}
	bool process_ECDHE_Server_Key_Exchange(const tsCryptoData& buffer, size_t& offset)
	{
		uint8_t curveType;
		// size_t originalOffset = offset;

		if (!getU1(buffer, offset, curveType))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_decode_error);
			StopTunnel();
			return false;
		}
		if (curveType == ssl_named_curve)
		{
			uint16_t curveId;
			std::shared_ptr<EccKey> key;
			tsCryptoData point;
			tsCryptoData signature;
			tsCryptoData signablePart;

			if (!getU2(buffer, offset, curveId) ||
				!getU1Buffer(buffer, offset, point))
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_decode_error);
				StopTunnel();
				return false;
			}
			signablePart = buffer.substring(0, offset);

			switch (curveId)
			{
			case ssl_secp256r1:
				if (!TSBuildEccKey(tsCryptoString("KEY-P256"), key))
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
					StopTunnel();
					return false;
				}
				break;
			case ssl_secp384r1:
				if (!TSBuildEccKey(tsCryptoString("KEY-P384"), key))
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
					StopTunnel();
					return false;
				}
				break;
			case ssl_secp521r1:
				if (!TSBuildEccKey(tsCryptoString("KEY-P521"), key))
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
					StopTunnel();
					return false;
				}
				break;
			default:
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
				StopTunnel();
				return false;
			}
			_serverEphemeral = std::dynamic_pointer_cast<AsymmetricKey>(key);

			if (!key->set_Point(point))
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
				StopTunnel();
				return false;
			}

			if (_cipher->CertSign == sslsign_rsa || _cipher->CertSign == sslsign_dsa || _cipher->CertSign == sslsign_ecdsa)
			{
				CertAlg recvdAlg = { sslhash_none, sslsign_anonymous };
				tsCertificateParser parser;
				std::shared_ptr<AsymmetricKey> certKey;
				tsCryptoString suffix;

				if (!getU1(buffer, offset, *(uint8_t*)&recvdAlg.hash) ||
					!getU1(buffer, offset, *(uint8_t*)&recvdAlg.sig) ||
					!getU2Buffer(buffer, offset, signature))
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_decode_error);
					StopTunnel();
					return false;
				}

				if (_serverCerts->size() == 0 || !parser.LoadCertificate(_serverCerts->at(0)))
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
					StopTunnel();
					return false;
				}
				certKey = parser.getPublicKeyObject();

				if (!!std::dynamic_pointer_cast<RsaKey>(certKey))
				{
					suffix = "PKCS-";
				}

				// TODO: validate recvdAlg with _certAlg

				switch (recvdAlg.hash)
				{
				case sslhash_sha1:
					suffix << "SHA1";
					break;
				case sslhash_sha224:
					suffix << "SHA224";
					break;
				case sslhash_sha256:
					suffix << "SHA256";
					break;
				case sslhash_sha384:
					suffix << "SHA384";
					break;
				case sslhash_sha512:
					suffix << "SHA512";
					break;
				}

				if (!TSVerifyData(certKey, _clientRandom + _serverRandom + signablePart, signature, suffix.c_str()))
				{
					rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
					StopTunnel();
					return false;
				}
			}
			if (offset != buffer.size())
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_record_overflow);
				StopTunnel();
				return false;
			}
		}
		else
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}
		return true;
	}
	bool process_DHE_Server_Key_Exchange(const tsCryptoData& buffer, size_t& offset)
	{
		tsCryptoData p, g, q, Y;
		tsCryptoData signablePart;
		std::shared_ptr<DhKey> dhKey;
		int qBitSize = 0;
		// size_t originalOffset = offset;

		if (!getU2Buffer(buffer, offset, p) ||
			!getU2Buffer(buffer, offset, g) ||
			!getU2Buffer(buffer, offset, Y))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}
		signablePart = buffer.substring(0, offset);

		// TODO:  HACK - SSL/TLS does not transmit the q value and our crypto needs it for DH to work.  Create a Q value and insert it  Will not validate but should make the crypto at least work
		switch (p.size() * 8)
		{
		case 512:
			qBitSize = 160;
			break;
		case 1024:
			qBitSize = 160;
			break;
		case 2048:
			qBitSize = 224;
			break;
		case 3072:
			qBitSize = 256;
			break;
		default:
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}
		if (!GenerateRandom(q, qBitSize / 8))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}
		q[0] |= 0x80;
		q[q.size() - 1] |= 1;

		if (!TSBuildDhParams(_dhParams) || !_dhParams->set_prime(p) || !_dhParams->set_subprime(q) || !_dhParams->set_generator(g) || !TSBuildDhKey(dhKey) || !dhKey->set_DomainParameters(_dhParams) || !dhKey->set_PublicKey(Y))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}

		_serverEphemeral = std::dynamic_pointer_cast<AsymmetricKey>(dhKey);

		if (_cipher->CertSign == sslsign_rsa || _cipher->CertSign == sslsign_dsa || _cipher->CertSign == sslsign_ecdsa)
		{
			CertAlg recvdAlg = { sslhash_none, sslsign_anonymous };
			tsCryptoData signature;
			tsCertificateParser parser;
			std::shared_ptr<AsymmetricKey> certKey;
			tsCryptoString suffix;

			if (!getU1(buffer, offset, *(uint8_t*)&recvdAlg.hash) ||
				!getU1(buffer, offset, *(uint8_t*)&recvdAlg.sig) ||
				!getU2Buffer(buffer, offset, signature))
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_decode_error);
				StopTunnel();
				return false;
			}

			if (_serverCerts->size() == 0 || !parser.LoadCertificate(_serverCerts->at(0)))
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
				StopTunnel();
				return false;
			}
			certKey = parser.getPublicKeyObject();

			if (!!std::dynamic_pointer_cast<RsaKey>(certKey))
			{
				suffix = "PKCS-";
			}

			// TODO: validate recvdAlg with _certAlg

			switch (recvdAlg.hash)
			{
			case sslhash_sha1:
				suffix << "SHA1";
				break;
			case sslhash_sha224:
				suffix << "SHA224";
				break;
			case sslhash_sha256:
				suffix << "SHA256";
				break;
			case sslhash_sha384:
				suffix << "SHA384";
				break;
			case sslhash_sha512:
				suffix << "SHA512";
				break;
			}

			if (!TSVerifyData(certKey, _clientRandom + _serverRandom + signablePart, signature, suffix.c_str()))
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
				StopTunnel();
				return false;
			}
		}
		if (offset != buffer.size())
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_record_overflow);
			StopTunnel();
			return false;
		}
		return true;
	}
	bool process_CkmAuth_Server_Key_Exchange(const tsCryptoData& buffer, size_t& offset)
	{
		tsCryptoData point;
		tsCryptoData nonce;
		tsCryptoData oidInfo;
		tsCryptoData converter;
		tsCryptoData salt;
		uint16_t count;
		tsCryptoData hmacName;
		std::shared_ptr<AuthenticationInitiator> ckmAuth;

		if (!getU1Buffer(buffer, offset, point) ||
			!getU1Buffer(buffer, offset, nonce) ||
			!getU2Buffer(buffer, offset, oidInfo) ||
			!getU1Buffer(buffer, offset, converter) ||
			!getU1Buffer(buffer, offset, salt) ||
			!getU2(buffer, offset, count) ||
			!getU1Buffer(buffer, offset, hmacName))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_decode_error);
			StopTunnel();
			return false;
		}
		if (offset != buffer.size())
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_record_overflow);
			StopTunnel();
			return false;
		}

		tsCryptoStringList oidParts = oidInfo.ToUtf8String().split(";", 4);
		if (oidParts->size() != 4 || oidParts->at(1) != _username)
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}

		ckmAuth = std::dynamic_pointer_cast<AuthenticationInitiator>(CryptoFactory(oidParts->at(0) + ";" + oidParts->at(3)));
		_serverRandom.FromBase64(oidParts->at(2));
		if (_serverRandom != nonce || !ckmAuth)
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}

		_POD_CkmAuthInitiatorParameters params;
		_POD_CkmAuthServerParameters serverParams;
		tsCryptoData initParams;
		tsCryptoData password, mitm;

		serverParams.get_params().set_selectedItem(_POD_CkmAuthServerParameters_params::Choice_Pbkdf);
		serverParams.get_params().get_Pbkdf().get_hmacAlgorithm().set_oid(hmacName.ToUtf8String());
		serverParams.get_params().get_Pbkdf().set_IterationCount(count);
		serverParams.get_params().get_Pbkdf().set_Salt(salt);

		params.set_responderPublicKey(point);
		params.set_oidInfo(oidInfo);
		params.set_nonce(_serverRandom);
		params.set_authParameters(serverParams);
		params.set_keySizeInBits((int)(512 + _msgKeyBitSize));
		// TODO:  Implement me params.set_responderPublicKeyOID()

		if (!passwordCB || !passwordCB(password))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}
		if (!params.Encode(initParams) ||
			!ckmAuth->computeInitiatorValues(initParams, password, _ckmAuthResponderParams, mitm, _ckmAuthSessionKey))
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return false;
		}
		if (_msgKeyBitSize > 0)
		{
			_msgKey = _ckmAuthSessionKey.substring(64, _msgKeyBitSize / 8);
			_ckmAuthSessionKey.erase(64, _msgKeyBitSize / 8);
		}
		return true;
	}
	void computeClientRandom()
	{
		tsCryptoData tmp;
#ifdef _WIN32
		__int64 ltime;

		_time64(&ltime);
#else
		time_t ltime;

		time(&ltime);
#endif
		_clientRandom.resize(4);
		_clientRandom[0] = (uint8_t)(ltime >> 24);
		_clientRandom[1] = (uint8_t)(ltime >> 16);
		_clientRandom[2] = (uint8_t)(ltime >> 8);
		_clientRandom[3] = (uint8_t)(ltime & 0xff);
		GenerateRandom(tmp, 28);
		_clientRandom << tmp;
	}
	bool changeState(SSL_CONNECTION_STATE newState)
	{
		if (__state != newState)
		{
			switch (newState)
			{
			case ssl_conn_ProtocolReset:
			case ssl_conn_ProtocolClosed:
				break;  // Allowed from all states
			case ssl_conn_Hello_Request:
				if (__state == ssl_conn_ProtocolClosed)
					return false;
				break;
			case ssl_conn_Client_Hello:
				if (__state == ssl_conn_ProtocolClosed)
					return false;
				break;
			case ssl_conn_Server_Hello:
				if (__state != ssl_conn_Client_Hello)
					return false;
				break;
			case ssl_conn_Server_Certificate:
				if (__state != ssl_conn_Server_Hello)
					return false;
				break;
			case ssl_conn_Server_Key_Exchange:
				if (__state != ssl_conn_Server_Certificate && __state != ssl_conn_Server_Hello)
					return false;
				break;
			case ssl_conn_Server_Hello_Done:
				if (__state != ssl_conn_Server_Key_Exchange && __state != ssl_conn_Server_Certificate &&
					__state != ssl_conn_Client_Certificate_Request && __state != ssl_conn_Server_Hello)
					return false;
				break;
			case ssl_conn_Client_Certificate_Request:
				if (__state != ssl_conn_Server_Certificate && __state != ssl_conn_Server_Key_Exchange)
					return false;
				break;
			case ssl_conn_Client_Key_Exchange:
				if (__state != ssl_conn_Server_Hello_Done && __state != ssl_conn_Client_Certificate)
					return false;
				break;
			case ssl_conn_Client_Certificate:
				if (__state != ssl_conn_Server_Hello_Done)
					return false;
				break;
			case ssl_conn_Client_Certificate_Verify:
				if (__state != ssl_conn_Client_Key_Exchange)
					return false;
				break;
			case ssl_conn_Client_Send_Change_Cipher_Spec:
				if (__state != ssl_conn_Client_Certificate_Verify && __state != ssl_conn_Client_Key_Exchange)
					return false;
				break;
			case ssl_conn_Client_Finished:
				if (__state != ssl_conn_Client_Send_Change_Cipher_Spec)
					return false;
				break;
			case ssl_conn_Server_Send_Change_Cipher_Spec:
				if (__state != ssl_conn_Client_Finished)
					return false;
				break;
			case ssl_conn_Server_Finished:
				if (__state != ssl_conn_Server_Send_Change_Cipher_Spec)
					return false;
				break;
			case ssl_conn_Active:
				if (__state != ssl_conn_Server_Finished)
					return false;
				break;
			case ssl_conn_Logout:
				break; // From any state
			}
			__state = newState;
			if (_ctrlChannel != nullptr)
				_ctrlChannel->stateChanged(newState == ssl_conn_Active, newState);
			return true;
}
		else
			return true;
	}

	void DataReceivedFromRecordLayer(SSL_ContentType contentType, uint8_t major, uint8_t minor, const uint8_t* data, uint32_t dataLen)
	{
		if (major != _major || minor != _minor)
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_protocol_version);
			StopTunnel();
			return;
		}

		if (!isValid())
		{
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
			StopTunnel();
			return;
		}

		switch (contentType)
		{
		case ssl_change_cipher_spec:
			if (!changeState(ssl_conn_Server_Send_Change_Cipher_Spec))
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
				StopTunnel();
				return;
			}
			if (_initiatingCipherChange)
			{
				_initiatingCipherChange = false;
				return;
			}
			if (!rlDesc->changeReaderCryptoSuite(rlDesc, rlWork))
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
				StopTunnel();
				return;
			}
			break;
		case ssl_alert:
			if (dataLen < 2)
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_record_overflow);
				StopTunnel();
				return;
			}
			_lastError = (SSL_AlertDescription)data[1];
			if (_lastError == sslalert_close_notify && __state != ssl_conn_Logout)
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_close_notify);
				changeState(ssl_conn_Logout);

				if (_ctrlChannel != nullptr)
				{
					tsCryptoString msg;

					msg << supDesc->getAlertLevel((SSL_AlertLevel)data[0]) << ":  " << supDesc->getSslAlertName((SSL_AlertDescription)data[1]);

					_ctrlChannel->failed(msg.c_str());
				}
			}
			else if ((SSL_AlertLevel)data[0] == ssl_fatal && __state != ssl_conn_Logout)
			{
				StopTunnel();
				if (_ctrlChannel != nullptr)
				{
					tsCryptoString msg;

					msg << supDesc->getAlertLevel((SSL_AlertLevel)data[0]) << ":  " << supDesc->getSslAlertName((SSL_AlertDescription)data[1]);

					_ctrlChannel->failed(msg.c_str());
				}
				if (_ctrlChannel != nullptr)
					_ctrlChannel->setCloseAfterTransmit();
			}
			StopTunnel();
			break;
		case ssl_handshake:
			if (!handleHandshakeMessage(data, dataLen))
				return;
			break;
		case ssl_application_data:
			if (_ctrlChannel == nullptr || !_ctrlChannel->sendReceivedData(tsCryptoData(data, dataLen)))
			{
				rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_handshake_failure);
				StopTunnel();
				return ;
			}
			break;
		default:
			rlDesc->sendAlert(rlDesc, rlWork, ssl_fatal, sslalert_unexpected_message);
			StopTunnel();
			return;
		}
	}

private:
	bool getFixedBuffer(const tsCryptoData& buffer, size_t& offset, uint32_t len, tsCryptoData& output)
	{
		if (buffer.size() < offset + len)
		{
			return false;
		}
		output = buffer.substring(offset, len);
		offset += len;
		return true;
	}
	bool getU3Buffer(const tsCryptoData& buffer, size_t& offset, tsCryptoData& output)
	{
		uint32_t len;

		if (buffer.size() < offset + 3)
		{
			return false;
		}
		len = (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];
		offset += 3;
		if (buffer.size() < offset + len)
		{
			return false;
		}
		output = buffer.substring(offset, len);
		offset += len;
		return true;
	}
	bool getU2Buffer(const tsCryptoData& buffer, size_t& offset, tsCryptoData& output)
	{
		uint16_t len;

		if (buffer.size() < offset + 2)
		{
			return false;
		}
		len = (buffer[offset] << 8) | buffer[offset + 1];
		offset += 2;
		if (buffer.size() < offset + len)
		{
			return false;
		}
		output = buffer.substring(offset, len);
		offset += len;
		return true;
	}
	bool getU1Buffer(const tsCryptoData& buffer, size_t& offset, tsCryptoData& output)
	{
		uint16_t len;

		if (buffer.size() < offset + 1)
		{
			return false;
		}
		len = buffer[offset++];
		if (buffer.size() < offset + len)
		{
			return false;
		}
		output = buffer.substring(offset, len);
		offset += len;
		return true;
	}
	bool getU1(const tsCryptoData& buffer, size_t& offset, uint8_t& output)
	{
		if (buffer.size() < offset)
		{
			return false;
		}
		output = buffer[offset++];
		return true;
	}
	bool getU2(const tsCryptoData& buffer, size_t& offset, uint16_t& output)
	{
		if (buffer.size() < offset + 1)
		{
			return false;
		}
		output = (uint16_t)((buffer[offset] << 8) | buffer[offset + 1]);
		offset += 2;
		return true;
	}

	bool isValid()
	{
		return rlDesc != nullptr && !rlWork.empty() && _keyHandler != nullptr && _ctrlChannel != nullptr;
	}
	void _resetTunnel()
	{
		std::shared_ptr<tscrypto::ICryptoObject> keepAlive = _me.lock();
	
		if (isValid())
		{
			rlDesc->reset(rlDesc, rlWork);
			// TODO:  Reset state
		}
		_major = 3;
		_minor = 3;
		_clientRandom.clear();
		_serverRandom.clear();
		changeState(ssl_conn_ProtocolReset);
		_appDataBuffer.clear();
		_serverEphemeral.reset();
		_cipher = nullptr;
		_compression = ssl_NoCompression;
		_serverCerts->clear();
		_master_secret.clear();
		_sessionId.clear();
		_handshakeData.clear();
		_pskIdentity.clear();
		_psk.clear();
		_extended_master_secret = false;
		memset(&_certAlg, 0, sizeof(_certAlg));
		_dhParams.reset();
		_username.clear();
		_ckmAuthSessionKey.clear();
		_msgKey.clear();
		_ckmAuthResponderParams.clear();
		_msgKeyBitSize = 0;
		_msgEncAlg.clear();
		_msgMacAlg.clear();
		

		_compression = (ssl_NoCompression);

		changeState(ssl_conn_ProtocolClosed);
	}

	static ts_bool _dataReceivedFromRecordLayer(void* params, SSL_ContentType contentType, uint8_t majorVersion, uint8_t minorVersion, const uint8_t* data, uint32_t dataLen)
	{
		SslHandshake_Client* This = (SslHandshake_Client*)params;

		This->DataReceivedFromRecordLayer(contentType, majorVersion, minorVersion, data, dataLen);
		return ts_true;
	}
	static ts_bool _sendReceivedData(void* params, const uint8_t* data, uint32_t dataLen)
	{
		SslHandshake_Client* This = (SslHandshake_Client*)params;
		if (!This->_ctrlChannel)
			return false;
		if (!!This->_packetSentFn)
			This->_packetSentFn(data[0], data, dataLen);
		return This->_ctrlChannel->sendReceivedData(tsCryptoData(data, dataLen));
	}
	static ts_bool _sendControlData(void* params, const uint8_t* data, uint32_t dataLen)
	{
		SslHandshake_Client* This = (SslHandshake_Client*)params;
		if (!This->_ctrlChannel)
			return false;
		if (!!This->_packetSentFn)
			This->_packetSentFn(data[0], data, dataLen);
		return This->_ctrlChannel->sendControlData(tsCryptoData(data, dataLen));
	}
	static ts_bool _flushApplicationData(void* params)
	{
		SslHandshake_Client* This = (SslHandshake_Client*)params;
		// TODO:  See if this is needed
		//tsCryptoData buffer;
		//std::shared_ptr<ISslHandshakeData> hs = handshakeLayer.lock();

		//if (!hs)
		//	return sslalert_access_denied;

		//buffer = dataToSend;
		//dataToSend.erase(0, buffer.size());
		//hs->SendAppDataToComms(buffer);
		//return sslalert_no_error;
		return true;
	}
	static ts_bool _closeChannel(void* params)
	{
		SslHandshake_Client* This = (SslHandshake_Client*)params;
		if (This->_ctrlChannel != nullptr)
			This->_ctrlChannel->setCloseAfterTransmit();
		return true;
	}
	static void _internalPacketReceivedFn(void *params, uint8_t packetType, const uint8_t* data, uint32_t dataLen)
	{
		SslHandshake_Client* This = (SslHandshake_Client*)params;
		if (!!This->_packetReceiverFn)
			This->_packetReceiverFn(packetType, data, dataLen);
	}
private:
	static const TlsHandshakeDataCallback_Descriptor _handshakeDesc;
	const TlsSupport_Descriptor* supDesc;
	const TlsRecordLayer_Descriptor* rlDesc;
	SmartCryptoWorkspace rlWork;

	uint8_t _major, _minor;
	bool _allowCompression;
	std::function<SSL_AlertDescription(const tsCryptoDataList& certificates, SSL_CIPHER cipher)> certVerifierCB;
	std::function<bool(const tsCryptoData& serverHint, tsCryptoData& clientHint, tsCryptoData& psk)> pskCB;
	std::function<bool(tsCryptoData& password)> passwordCB;
	bool _initiatingCipherChange;
	tsCryptoData _bufferedHSData;
	AutoCriticalSection _bufferedHSDataLock;
	tsCryptoData _clientRandom;
	tsCryptoData _serverRandom;
	//tsCryptoData _processedReceivedData;
	tsCryptoData _appDataBuffer;

	const SSL_CIPHER_INFO* _cipher;
	SSL_CompressionMethod _compression;
	SSL_CONNECTION_STATE __state;
	tsCryptoDataList _serverCerts;
	tsCryptoData _master_secret;
	tsCryptoData _handshakeData;
	tsCryptoData _sessionId;
	tsCryptoData _psk;
	tsCryptoData _pskIdentity;
	bool _extended_master_secret;
	std::shared_ptr<AsymmetricKey> _serverEphemeral;
	//	std::shared_ptr<ISslCertSelector> _certSelector;
	CertAlg _certAlg;
	bool _useInternalCryptoList;
	std::vector<SSL_CIPHER> _cipherList;
	SSL_AlertDescription _lastError;
	std::shared_ptr<DhParameters> _dhParams;
	tsCryptoString _username;
	tsCryptoData _ckmAuthSessionKey;
	tsCryptoData _ckmAuthResponderParams;
	size_t _msgKeyBitSize;
	_POD_AlgorithmIdentifier _msgEncAlg;
	_POD_AlgorithmIdentifier _msgMacAlg;
	tsCryptoData _msgKey;
	std::function<void(uint8_t packetType, const uint8_t* data, uint32_t dataLen)> _packetSentFn;
	std::function<void(uint8_t packetType, const uint8_t* data, uint32_t dataLen)> _packetReceiverFn;
	authenticationInitiatorTunnelKeyHandler* _keyHandler;
	authenticationControlDataCommunications* _ctrlChannel;
};

const TlsHandshakeDataCallback_Descriptor SslHandshake_Client::_handshakeDesc =
{
	&SslHandshake_Client::_sendReceivedData,
	&SslHandshake_Client::_dataReceivedFromRecordLayer,
	&SslHandshake_Client::_sendControlData,
	&SslHandshake_Client::_flushApplicationData,
	&SslHandshake_Client::_closeChannel,
};

tscrypto::ICryptoObject* CreateSslHandshake_Client()
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new SslHandshake_Client());
}