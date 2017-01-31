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

class PluginModule : public tsmod::IPluginModule, public tsmod::IObject
{
public:
	PluginModule();
	virtual ~PluginModule();

	virtual bool connect(const tscrypto::tsCryptoStringBase& path, tsmod::IReportError* log) override;
	virtual void disconnect() override;
	virtual tscrypto::tsCryptoString Name() const override { return _name; }
	XP_MODULE Handle() const { return _handle; }
	virtual bool isValid() const override { return _handle != XP_MODULE_INVALID; }
	virtual bool Initialize(tsmod::IReportError* log) override;
	virtual bool Terminate() override;

private:
	XP_MODULE _handle;
	tscrypto::tsCryptoString _name;
	tscrypto::AutoCriticalSection _lock;
    tscrypto::tsCryptoString _baseName;
};

class RootedPluginModule : public PluginModule, public tsmod::IServiceLocator
{
public:
	RootedPluginModule(){}
	virtual ~RootedPluginModule(){}

	// tsmod::IServiceLocator
	virtual bool AddSingletonClass(const tscrypto::tsCryptoStringBase& className, std::function<tsmod::IObject* ()> creator) override
	{
		return myServices->AddSingletonClass(className, creator);
	}
	virtual bool AddSingletonObject(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tsmod::IObject> object) override
	{
		return myServices->AddSingletonObject(className, object);
	}
	virtual bool AddClass(const tscrypto::tsCryptoStringBase& className, std::function<tsmod::IObject* ()> creator) override
	{
		return myServices->AddClass(className, creator);
	}
	virtual bool CopyClass(const tscrypto::tsCryptoStringBase& className, tsmod::IServiceLocator* copyTo) const override
	{
		return myServices->CopyClass(className, copyTo);
	}
	virtual bool DeleteClass(const tscrypto::tsCryptoStringBase& className) override
	{
		return myServices->DeleteClass(className);
	}
	virtual std::shared_ptr<tsmod::IObject> Create(const tscrypto::tsCryptoStringBase& className) override
	{
		return myServices->Create(className);
	}
	virtual std::shared_ptr<tsmod::IObject> TryCreate(const tscrypto::tsCryptoStringBase& className) override
	{
		return myServices->TryCreate(className);
	}
	virtual tscrypto::tsCryptoStringList ObjectNames(bool onlyInstantiatedSingletons) const override
	{
		return myServices->ObjectNames(onlyInstantiatedSingletons);
	}
	virtual tscrypto::tsCryptoStringList ObjectGroup(const tscrypto::tsCryptoStringBase& prefix, bool onlyInstantiatedSingletons) const override
	{
		return myServices->ObjectGroup(prefix, onlyInstantiatedSingletons);
	}
	virtual bool CanCreate(const tscrypto::tsCryptoStringBase& className) const override
	{
		return myServices->CanCreate(className);
	}
	virtual std::shared_ptr<tsmod::IServiceLocator> Creator() const override
	{
		return myServices->Creator();
	}
	virtual std::shared_ptr<tsmod::IObject> FinishConstruction(tsmod::IObject* obj) override
	{
		return myServices->FinishConstruction(obj);
	}
	virtual void acceptVisitor(tsmod::IServiceLocatorVisitor *visitor) override
	{
		return myServices->acceptVisitor(visitor);
	}
	virtual void acceptVisitor(tsmod::IConstServiceLocatorVisitor *visitor) const override
	{
		return myServices->acceptVisitor(visitor);
	}
	virtual std::shared_ptr<tsmod::IObject> newInstance() const override { return nullptr; }

	virtual std::shared_ptr<tsmod::IServiceLocator> resolvePath(tscrypto::tsCryptoStringBase &path, bool createPaths) override
	{
		return myServices->resolvePath(path, createPaths);
	}
	virtual std::shared_ptr<tsmod::IServiceLocator> resolvePath(tscrypto::tsCryptoStringBase &path) const override
	{
		return myServices->resolvePath(path);
	}
	virtual tscrypto::tsCryptoString findObjectName(tsmod::IObject* obj) override
	{
		return myServices->findObjectName(obj);
	}
	virtual void BuildObjectPath(tscrypto::tsCryptoStringBase& name) override
	{
		myServices->BuildObjectPath(name);
	}

	virtual void CleanEmptyCollections(const tscrypto::tsCryptoStringBase& className) override
	{
		myServices->CleanEmptyCollections(className);
	}
	virtual void clear() override
	{
		myServices->clear();
	}
	virtual void SetAsRoot() override
	{
		myServices->SetAsRoot();
	}
	virtual bool IsRoot() const override
	{
		return myServices->IsRoot();
	}
	virtual std::shared_ptr<tsmod::IObject> Create(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tsmod::IServiceLocator> onService) override
	{
		return myServices->Create(className, onService);
	}
	virtual std::shared_ptr<tsmod::IObject> TryCreate(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tsmod::IServiceLocator> onService) override
	{
		return myServices->TryCreate(className, onService);
	}
	virtual bool CopyClassDef(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& newName) override
	{
		return myServices->CopyClassDef(className, newName);
	}

	// tsmod::IObject
	virtual std::shared_ptr<tsmod::IServiceLocator> ServiceLocator() const override
	{
		return myServices;
	}
	virtual void OnConstructionFinished() override
	{
		// Create the ServiceLocator for this service
		myServices = std::dynamic_pointer_cast<tsmod::IServiceLocator>(tsmod::IObject::ServiceLocator()->newInstance());

		// Transfer over the plugin manager and plugin for use by the service
		std::shared_ptr<tsmod::IPluginModuleManager> mgr = tsmod::IObject::ServiceLocator()->get_instance<tsmod::IPluginModuleManager>("/PluginManager");
		myServices->AddSingletonObject("PluginManager", std::dynamic_pointer_cast<tsmod::IObject>(mgr)->newInstance());
		tsmod::IObject::ServiceLocator()->CopyClass("Plugin", myServices.get());

		// Reconfigure the service copy of the plugin manager
		mgr.reset();
		mgr = myServices->get_instance<tsmod::IPluginModuleManager>("/PluginManager");
		std::shared_ptr<tsmod::IObject> mgrObj = std::dynamic_pointer_cast<tsmod::IObject>(mgr);
		mgrObj->_serviceLocator.reset();
		mgrObj->_serviceLocator = myServices;
	}
private:
	std::shared_ptr<tsmod::IServiceLocator> myServices;
};

PluginModule::PluginModule() : _handle(XP_MODULE_INVALID)
{
}

//PluginModule(PluginModule &&obj);
//PluginModule(const PluginModule& obj);
//PluginModule(HMODULE hndl, const std::string& nm);
PluginModule::~PluginModule()
{
    disconnect();
}

//   PluginModule &operator=(PluginModule&& obj);
//PluginModule &operator=(const PluginModule& obj) { UNREFERENCED_PARAMETER(obj); throw std::runtime_error("assignment not allowed"); }

//extern "C" const char *GetLastDLError();

bool PluginModule::connect(const tscrypto::tsCryptoStringBase& _path, tsmod::IReportError* log)
{
    tscrypto::tsCryptoString tmp1, tmp2, path;
 //   if (!localAuthenticateModule(path))
	//{
	//	log->SetFault("Server", "The specified module could not load because it has been modified.", "");
 //       return false;
	//}
 //

 	xp_GetFullPathName(_path, path, nullptr);
//printf("Loading module %s\n", path.c_str());
    if (xp_LoadSharedLib(path, &_handle) != 0)
    {
//printf ("Module load returned %s\n", GetLastDLError());

		if (log != nullptr)
			log->SetJSONFault("SystemException", "The specified module is missing one or more dependent components.", "Server", "");
		else
		{
			LOG(FrameworkError, "The specified module is missing one or more dependent components." << tscrypto::endl << "The path is:  " << path);
		}
        _name.clear();
        return false;
    }
    xp_SplitPath(path, tmp1, _baseName, tmp2);
    _baseName.Replace(".", "_");
#ifdef _DEBUG
    if (_baseName[_baseName.size() - 1] == 'd' && _baseName[_baseName.size() - 2] == '_')
        _baseName.resize(_baseName.size() - 2);
#endif // _DEBUG
    _name = path;
    return true;
}

void PluginModule::disconnect()
{
    if (isValid())
    {
        // TODO:  Disabled for now due to problems closing VEILssm     xp_FreeSharedLib(_handle);
    }
	_handle = XP_MODULE_INVALID;
	_name.clear();
}

bool PluginModule::Initialize(tsmod::IReportError* log)
{
    typedef bool (*fn_t)(std::shared_ptr<tsmod::IServiceLocator>, tsmod::IReportError* log);
    fn_t fn = nullptr;

	TSAUTOLOCKER lock(_lock);
    if (!isValid())
	{
		if (log != nullptr)
			log->SetJSONFault("SystemException", "The service could not be initialized because it is not loaded.", "Server", "");
		else
		{
			LOG(FrameworkError, "The service could not be initialized because it is not loaded.");
		}
        return false;
	}

//	if (log != nullptr)
	{
#ifdef _WIN32
		fn = (fn_t)xp_GetProcAddress(_handle, "Initialize");
#endif
		if (fn == nullptr)
		{
			fn = (fn_t)xp_GetProcAddress(_handle, ("Initialize" + _baseName).c_str());
		}
		if (fn == nullptr)
		{
			fn = (fn_t)xp_GetProcAddress(_handle, ("Initialize" + _baseName + "_d").c_str());
		}
		if (fn == nullptr)
		{
			if (log != nullptr)
			log->SetJSONFault("SystemException", "The service specification is invalid.  The service is missing the initialization entry point.", "Server", "");
			else
			{
				LOG(FrameworkError, "The service specification is invalid.  The service is missing the initialization entry point.");
			}
			return false;
		}
		if (!fn(ServiceLocator(), log))
		{
			if (log != nullptr)
			log->SetJSONFault("SystemException", "The service specification is invalid.  The service initialization routine failed.", "Server", "");
			else
			{
				LOG(FrameworkError, "The service specification is invalid.  The service initialization routine failed.");
			}
			return false;
		}
	}
	return true;
}

bool PluginModule::Terminate()
{
    typedef bool (*fn_t)(std::shared_ptr<tsmod::IServiceLocator>);
    fn_t fn = nullptr;

	TSAUTOLOCKER lock(_lock);
    if (!isValid())
        return false;

#ifdef _WIN32
    fn = (fn_t)xp_GetProcAddress(_handle, "Terminate");
#endif
	if (fn == nullptr)
	{
		fn = (fn_t)xp_GetProcAddress(_handle, ("Terminate" + _baseName).c_str());
	}
    if (fn == nullptr)
        return true;
	return fn(ServiceLocator());
}

tsmod::IObject* tsmod::CreatePluginModule()
{
	return dynamic_cast<tsmod::IObject*>(new PluginModule());
}

tsmod::IObject* tsmod::CreateRootedPluginModule()
{
	return dynamic_cast<tsmod::IObject*>(new RootedPluginModule());
}
