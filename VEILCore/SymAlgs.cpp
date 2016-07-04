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
#include "Salsa20.h"
#include "ChaCha20.h"
#include "poly1305-donna.h"
#include "md5.h"
#include "RipeMD160/RMD160.h"
#include "sha3.h"
#include "aes/aes_interface.h"

static AdditiveBlockStreamAlgorithmDescriptor *gABSDescriptors[] =
{
	&Salsa20Descriptor_ABS,
	&XSalsa20Descriptor_ABS,
	&ChaCha20_ABS_Descriptor,
	&ChaCha20_ietf_ABS_Descriptor,
	&AES_Ctr_Stream_Descriptor,
};

static SymmetricAlgorithmDescriptor *gDescriptors[] =
{
	&Salsa20Descriptor,
	&XSalsa20Descriptor,
	&ChaCha20_xor_Descriptor,
	&ChaCha20_ietf_xor_Descriptor,
	&AES_CTR_xor_Descriptor,
	&AES_ECB_Descriptor,
	&AES_CBC_Descriptor,
	&AES_OFB_Descriptor,
	&AES_CFB8_Descriptor,
	&AES_CFBfull_Descriptor,
};

static HASH_Descriptor *gHashDescriptors[] = 
{
	&MD5_Descriptor,
	&SHA1_Descriptor,
    &SHA224_Descriptor,
    &SHA256_Descriptor,
    &SHA384_Descriptor,
    &SHA512_Descriptor,
	&RIPEMD160_Descriptor,
	&SHA3_224_Descriptor,
	&SHA3_256_Descriptor,
	&SHA3_384_Descriptor,
	&SHA3_512_Descriptor,
};
static MAC_Descriptor *gMacDescriptors[] =
{
	&HMAC_MD5_Descriptor,
	&HMAC_SHA1_Descriptor,
	&HMAC_SHA224_Descriptor,
	&HMAC_SHA256_Descriptor,
	&HMAC_SHA384_Descriptor,
	&HMAC_SHA512_Descriptor,
	&HMAC_SHA3_224_Descriptor,
	&HMAC_SHA3_256_Descriptor,
	&HMAC_SHA3_384_Descriptor,
	&HMAC_SHA3_512_Descriptor,
	&HMAC_RIPEMD160_Descriptor,
	&POLY1305_Descriptor,
};
static HASH_Descriptor *gXofDescriptors[] = 
{
	&SHAKE128_Descriptor,
	&SHAKE256_Descriptor,
};


uint32_t getAdditiveBlockStreamAlgorithmCount()
{
	return (sizeof(gABSDescriptors) / sizeof(gABSDescriptors[0]));
}
AdditiveBlockStreamAlgorithmDescriptor** getAdditiveBlockStreamAlgorithmList()
{
	return gABSDescriptors;
}

uint32_t getSymmetricAlgorithmCount()
{
	return (sizeof(gDescriptors) / sizeof(gDescriptors[0]));
}

SymmetricAlgorithmDescriptor** getSymmetricAlgorithmList()
{
	return gDescriptors;
}

uint32_t getHashAlgorithmCount()
{
	return (sizeof(gHashDescriptors) / sizeof(gHashDescriptors[0]));
}
HASH_Descriptor** getHashAlgorithmList()
{
	return gHashDescriptors;
}

uint32_t getMacAlgorithmCount()
{
	return (sizeof(gMacDescriptors) / sizeof(gMacDescriptors[0]));
}
MAC_Descriptor** getMacAlgorithmList()
{
	return gMacDescriptors;
}

uint32_t getXofAlgorithmCount()
{
	return (sizeof(gXofDescriptors) / sizeof(gXofDescriptors[0]));
}
HASH_Descriptor** getXofAlgorithmList()
{
	return gXofDescriptors;
}
