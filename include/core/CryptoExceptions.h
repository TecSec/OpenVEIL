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

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \file   CryptoExceptions.h
///
/// \brief  Defines the exception classes used by the crypto library.
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __CryptoExceptions_H__
#define __CryptoExceptions_H__

namespace tscrypto {
	class VEILCORE_API Exception
	{
	public:
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

		Exception() {}
		Exception(const tscrypto::tsCryptoStringBase& msg) : _msg(msg) {}
		Exception(const Exception& obj) :
			_msg(obj._msg)
		{
		}
		Exception(Exception&& obj) :
			_msg(std::move(obj._msg))
		{
		}
		virtual ~Exception() {}

		virtual tscrypto::tsCryptoStringBase Message() const { return _msg; }

	protected:
		tscrypto::tsCryptoStringBase _msg;
	};
	class VEILCORE_API OverflowException : public Exception
	{
	public:
		OverflowException() {}
		OverflowException(const tscrypto::tsCryptoStringBase& msg) : Exception(msg) {}
		OverflowException(const OverflowException& obj) :
			Exception(obj._msg)
		{
		}
		OverflowException(OverflowException&& obj) :
			Exception(std::move(obj._msg))
		{
		}
		virtual ~OverflowException() {}
	};
	class VEILCORE_API DivideByZeroException : public Exception
	{
	public:
		DivideByZeroException() {}
		DivideByZeroException(const tscrypto::tsCryptoStringBase& msg) : Exception(msg) {}
		DivideByZeroException(const DivideByZeroException& obj) :
			Exception(obj._msg)
		{
		}
		DivideByZeroException(DivideByZeroException&& obj) :
			Exception(std::move(obj._msg))
		{
		}
		virtual ~DivideByZeroException() {}
	};
	class VEILCORE_API NotImplementedException : public Exception
	{
	public:
		NotImplementedException() {}
		NotImplementedException(const tscrypto::tsCryptoStringBase& msg) : Exception(msg) {}
		NotImplementedException(const NotImplementedException& obj) :
			Exception(obj._msg)
		{
		}
		NotImplementedException(NotImplementedException&& obj) :
			Exception(std::move(obj._msg))
		{
		}
		virtual ~NotImplementedException() {}
	};
	class VEILCORE_API ArgumentNullException : public Exception
	{
	public:
		ArgumentNullException(const tscrypto::tsCryptoStringBase& message) : Exception(message)
		{
		}
	};
	class VEILCORE_API ArgumentException : public Exception
	{
	public:
		ArgumentException(const tscrypto::tsCryptoStringBase& message) : Exception(message)
		{
		}
	};
	class VEILCORE_API OutOfRange : public Exception
	{
	public:
		OutOfRange(const tscrypto::tsCryptoStringBase& message) : Exception(message)
		{
		}
		OutOfRange() : Exception()
		{
		}
	};
	class VEILCORE_API length_error : public Exception
	{
	public:
		length_error() : Exception()
		{
		}
		length_error(const tscrypto::tsCryptoStringBase& message) : Exception(message)
		{
		}
	};
	class VEILCORE_API bad_alloc : public Exception
	{
	public:
		bad_alloc() : Exception()
		{
		}
	};
	class VEILCORE_API crypto_failure : public Exception
	{
	public:
		crypto_failure() : Exception()
		{
		}
	};
	class VEILCORE_API not_ready : public Exception
	{
	public:
		not_ready() : Exception()
		{
		}
		not_ready(const tscrypto::tsCryptoStringBase& message) : Exception(message)
		{
		}
	};
}

#endif // __CryptoExceptions_H__
