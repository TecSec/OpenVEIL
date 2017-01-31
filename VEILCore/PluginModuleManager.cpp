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
#include <algorithm>

class PluginModuleManager : public RWLock, public tsmod::IPluginModuleManager, public tsmod::IObject
{
public:
	PluginModuleManager();
	virtual ~PluginModuleManager();

	virtual void LoadModule(const tscrypto::tsCryptoStringBase& path, tsmod::IReportError* log, std::function<void(std::function<bool()>)> registerCleanup) override;
	virtual std::shared_ptr<tsmod::IPluginModule> FindModule(const tscrypto::tsCryptoStringBase& path) override;
	virtual void LoadModulesOfType(const tscrypto::tsCryptoStringBase& pattern, tsmod::IReportError* log, std::function<void(std::function<bool()>)> registerCleanup) override;
	virtual bool UseRootedPlugins() const override;
	virtual void UseRootedPlugins(bool setTo) override;
	virtual void TerminateAllPlugins() override;
	virtual void LoadModuleForService(const tscrypto::tsCryptoStringBase& path, tsmod::IReportError* log, std::shared_ptr<tsmod::IServiceLocator> servLoc, std::function<void(std::function<bool()>)> registerCleanup) override;
	virtual void LoadModulesOfTypeForService(const tscrypto::tsCryptoStringBase& pattern, tsmod::IReportError* log, std::shared_ptr<tsmod::IServiceLocator> servLoc, std::function<void(std::function<bool()>)> registerCleanup) override;

	// IMakeNewInstance
	virtual std::shared_ptr<tsmod::IObject> newInstance() const override;
private:
	bool _useRootedPlugins;
};

PluginModuleManager::PluginModuleManager() : _useRootedPlugins(false)
{
}

PluginModuleManager::~PluginModuleManager()
{
}

std::shared_ptr<tsmod::IObject> PluginModuleManager::newInstance() const
{
	return ServiceLocator()->Finish<tsmod::IObject>(new PluginModuleManager);
}

void PluginModuleManager::LoadModule(const tscrypto::tsCryptoStringBase& path, tsmod::IReportError* log, std::function<void(std::function<bool()>)> registerCleanup)
{
	std::string dllPath;
#ifdef _WIN32
	tsCryptoString tmp(path);

	dllPath = path.data();

	tmp.ToUpper();

    std::string id(tmp.c_str());
#else
    std::string id(path.c_str());
	dllPath = id;
#endif
	id.insert(0, "PLUGIN_");

	AutoWriterLock lock(*this);

	std::shared_ptr<tsmod::IPluginModule> mod = ServiceLocator()->try_get_instance<tsmod::IPluginModule>(id.c_str());

    if (!!mod)
        return; // We have already loaded that module.

	if (UseRootedPlugins())
	{
		mod = ServiceLocator()->get_instance<tsmod::IPluginModule>("/RootedPlugin");
	}
	else
	{
		mod = ServiceLocator()->get_instance<tsmod::IPluginModule>("/Plugin");
	}
    
    if (!mod->connect(dllPath.c_str(), log))
        return;
	if (registerCleanup)
	{
		std::shared_ptr<tsmod::IServiceLocator>	loc = ServiceLocator();
		registerCleanup([id, loc, mod]()->bool { mod->Terminate(); loc->DeleteClass(id.c_str()); return true; });
	}
	if (!mod->Initialize(log))
        return;

	ServiceLocator()->AddSingletonObject(id.c_str(), std::dynamic_pointer_cast<tsmod::IObject>(mod));
}
void PluginModuleManager::LoadModuleForService(const tscrypto::tsCryptoStringBase& path, tsmod::IReportError* log, std::shared_ptr<tsmod::IServiceLocator> servLoc, std::function<void(std::function<bool()>)> registerCleanup)
{
	std::string dllPath;
#ifdef _WIN32
	tsCryptoString tmp(path);

	dllPath = path.data();

	tmp.ToUpper();

	std::string id(tmp.c_str());
#else
    std::string id(path.c_str());
	dllPath = id;
#endif
	id.insert(0, "PLUGIN_");

	AutoWriterLock lock(*this);

	std::shared_ptr<tsmod::IPluginModule> mod = ServiceLocator()->try_get_instance<tsmod::IPluginModule>(id.c_str());

    if (!!mod)
        return; // We have already loaded that module.

	if (UseRootedPlugins())
	{
		mod = ServiceLocator()->get_instance<tsmod::IPluginModule>("/RootedPlugin");
	}
	else
	{
		mod = ServiceLocator()->get_instance<tsmod::IPluginModule>("/Plugin");
	}
    
    if (!mod->connect(dllPath.c_str(), log))
        return;
	if (registerCleanup)
	{
		std::shared_ptr<tsmod::IServiceLocator>	loc = servLoc;
		registerCleanup([id, loc, mod]()->bool { mod->Terminate(); loc->DeleteClass(id.c_str()); return true; });
	}
	if (!mod->Initialize(log))
        return;

	servLoc->AddSingletonObject(id.c_str(), std::dynamic_pointer_cast<tsmod::IObject>(mod));
}

std::shared_ptr<tsmod::IPluginModule> PluginModuleManager::FindModule(const tscrypto::tsCryptoStringBase& path)
{
#ifdef _WIN32
	tsCryptoString tmp(path);

	tmp.ToUpper();

	std::string id(tmp.c_str());
#else
    std::string id(path.c_str());
#endif
	std::string dllPath(id);
	id.insert(0, "PLUGIN_");

	AutoReaderLock lock(*this);
	return ServiceLocator()->try_get_instance<tsmod::IPluginModule>(id.c_str());
}

void PluginModuleManager::LoadModulesOfType(const tscrypto::tsCryptoStringBase& pattern, tsmod::IReportError* log, std::function<void(std::function<bool()>)> registerCleanup)
{
#ifndef ANDROID
    tsCryptoString name;
    
// #ifdef _DEBUG
// printf ("Searching for modules:  %s\n", pattern);
// #endif

	XP_FileListHandle files = xp_GetFileListHandle(pattern);
	DWORD count;

	if (files == XP_FILELIST_INVALID)
	{
// #ifdef _DEBUG
// printf ("  None found\n");
// #endif
		return;
	}

	auto cleanup = finally([&files]() {xp_CloseFileList(files);});

	count = (DWORD)xp_GetFileCount(files);

	for (DWORD i = 0; i < count; i++)
	{
		if (xp_GetFileName(files, i, name))
		{
// #ifdef _DEBUG
// printf ("  found: %s\n", name.c_str());
// #endif
			LoadModule(name.c_str(), log, registerCleanup);
		}
	}
#endif // ANDROID
}
void PluginModuleManager::LoadModulesOfTypeForService(const tscrypto::tsCryptoStringBase& pattern, tsmod::IReportError* log, std::shared_ptr<tsmod::IServiceLocator> servLoc, std::function<void(std::function<bool()>)> registerCleanup)
{
#ifndef ANDROID
	XP_FileListHandle files = xp_GetFileListHandle(pattern);
	DWORD count;
    tsCryptoString name;
    
	if (files == XP_FILELIST_INVALID)
		return;

	auto cleanup = finally([&files]() {xp_CloseFileList(files);});

	count = (DWORD)xp_GetFileCount(files);

	for (DWORD i = 0; i < count; i++)
	{
		if (xp_GetFileName(files, i, name))
		{
			LoadModuleForService(name.c_str(), log, servLoc, registerCleanup);
		}
	}
#endif // ANDROID
}

bool PluginModuleManager::UseRootedPlugins() const
{
	return _useRootedPlugins;
}

void PluginModuleManager::UseRootedPlugins(bool setTo)
{
	_useRootedPlugins = setTo;
}

tsmod::IObject* tsmod::CreatePluginModuleManager()
{
	return dynamic_cast<tsmod::IObject*>(new PluginModuleManager);
}

void PluginModuleManager::TerminateAllPlugins()
{
	AutoReaderLock lock(*this);
	tscrypto::tsCryptoStringList list = ServiceLocator()->ObjectGroup("PLUGIN_", true);

	for (auto name : *list)
	{
		std::shared_ptr<tsmod::IPluginModule> module = ServiceLocator()->try_get_instance<tsmod::IPluginModule>(name.c_str());
		if (!!module)
		{
			module->Terminate();
		}
	}
	for (auto name : *list)
	{
		std::shared_ptr<tsmod::IPluginModule> module = ServiceLocator()->try_get_instance<tsmod::IPluginModule>(name.c_str());
		if (!!module)
		{
			module->disconnect();
		}
		ServiceLocator()->DeleteClass(name.c_str());
	}
}
