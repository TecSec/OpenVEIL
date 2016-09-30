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

#pragma once

namespace tsmod {
	typedef struct VEILCORE_API OptionList {
	const char *option;
	const char *description;
	} OptionList;

	class VEILCORE_API IVeilUtilities
	{
	public:
	virtual ~IVeilUtilities() {}
	virtual xp_console& console() = 0;
	virtual void TopUsage() = 0;
		virtual void Usage(const tsmod::OptionList* list, size_t count) = 0;
	virtual void localGetConsolePin(tscrypto::tsCryptoString& enteredPin, uint32_t len, const tscrypto::tsCryptoString& prompt) = 0;
	virtual void OutputError(char *msg, ...) = 0;
	virtual void DumpOptionLine(const tscrypto::tsCryptoString& left, const tscrypto::tsCryptoString& right) = 0;
	virtual tsmod::IObject* buildCommandMenu(const tscrypto::tsCryptoString& description, const tscrypto::tsCryptoString& commandPrefix, const tscrypto::tsCryptoString& name, const tscrypto::tsCryptoString& menuHeader) = 0;
	};
}
