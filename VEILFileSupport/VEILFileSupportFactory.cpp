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

#include "VEILFileSupportFactory.h"
#include "FileVEILFileList.h"
#include "FileOperations.h"

class VEILFileSupportFactoryImpl :
	public IVEILFileSupportFactory, public tsmod::IObject
{
public:
	VEILFileSupportFactoryImpl();
	virtual ~VEILFileSupportFactoryImpl();

	virtual bool CreateFileOperations(std::shared_ptr<IFileVEILOperations>& pVal);
	virtual bool CreateFileList(std::shared_ptr<IVEILFileList>& pVal);
	virtual bool CreateFileStream(const tscrypto::tsCryptoString& filename, bool readable, bool writable, std::shared_ptr<IDataIOBase>& pVal);
	virtual bool CreateMemoryStream(std::shared_ptr<IDataIOBase>& pVal);
	virtual bool CreateFifoMemoryStream(std::shared_ptr<IDataIOBase>& pVal);
	virtual bool CreateReadAppendFileStream(const tscrypto::tsCryptoString& filename, std::shared_ptr<IDataIOBase>& pVal);
};

std::shared_ptr<IVEILFileSupportFactory> CreateVEILFileSupportFactory()
{
	return ::TopServiceLocator()->Finish<IVEILFileSupportFactory>(new VEILFileSupportFactoryImpl());
}

VEILFileSupportFactoryImpl::VEILFileSupportFactoryImpl()
{
}

VEILFileSupportFactoryImpl::~VEILFileSupportFactoryImpl()
{
}

bool VEILFileSupportFactoryImpl::CreateFileOperations(std::shared_ptr<IFileVEILOperations>& pVal)
{
	pVal = ::TopServiceLocator()->Finish<IFileVEILOperations>(new FileVEILOperationsImpl());
	if ( !pVal)
		return false;
	return true;
}

bool VEILFileSupportFactoryImpl::CreateFileList(std::shared_ptr<IVEILFileList>& pVal)
{
	return (!!(pVal = ::TopServiceLocator()->Finish<IVEILFileList>(new FileVEILFileListImpl())));
}

bool VEILFileSupportFactoryImpl::CreateFileStream(const tscrypto::tsCryptoString& filename, bool readable, bool writable, std::shared_ptr<IDataIOBase>& pVal)
{
	pVal.reset();
	if (readable && writable)
	{
		pVal = CreateReadWriteFile(filename);
	}
	else if (readable)
	{
		pVal = CreateFileReader(filename);
	}
	else if (writable)
	{
		pVal = CreateDataWriter(filename);
	}
	return !!pVal;
}

bool VEILFileSupportFactoryImpl::CreateMemoryStream(std::shared_ptr<IDataIOBase>& pVal)
{
	pVal = ::CreateMemoryStream();
	return !!pVal;
}

bool VEILFileSupportFactoryImpl::CreateFifoMemoryStream(std::shared_ptr<IDataIOBase>& pVal)
{
	pVal = CreateMemoryFifoStream();
	return !!pVal;
}

bool VEILFileSupportFactoryImpl::CreateReadAppendFileStream(const tscrypto::tsCryptoString& filename, std::shared_ptr<IDataIOBase>& pVal)
{
	pVal = CreateReadAppendFile(filename);
	return !!pVal;
}

