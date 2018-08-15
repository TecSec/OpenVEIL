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

/*! @file tsmod_extension.h
 * @brief This file defines the classes and interfaces for the service locator and related classes.
*/

#ifndef __TSMOD_EXTENSION_H__
#define __TSMOD_EXTENSION_H__

#pragma once

#include <memory>
#include <map>
//#include <vector>
//#include <list>
#include <functional>

namespace tsmod
{
	struct IServiceLocator;

	struct IServiceLocatorVisitor
	{
		virtual bool visitEnter(const tscrypto::tsCryptoStringBase& name, IServiceLocator* locator) = 0;
		virtual void visitLeave(const tscrypto::tsCryptoStringBase& name, IServiceLocator* locator) = 0;
		virtual void visit(const tscrypto::tsCryptoStringBase& name, bool singleton, bool object) = 0;
	};
	struct IConstServiceLocatorVisitor
	{
		virtual bool visitEnter(const tscrypto::tsCryptoStringBase& name, const IServiceLocator* locator) const = 0;
		virtual void visitLeave(const tscrypto::tsCryptoStringBase& name, const IServiceLocator* locator) const = 0;
		virtual void visit(const tscrypto::tsCryptoStringBase& name, bool singleton, bool object) = 0;
	};

	struct IObject;
}

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4231)

VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::weak_ptr<tsmod::IServiceLocator>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<tsmod::IServiceLocator>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::weak_ptr<tsmod::IObject>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<tsmod::IObject>;
#pragma warning(pop)
#endif // _MSC_VER

namespace tsmod
{
	struct VEILCORE_API IObject
	{
		static void *operator new(std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
		static void *operator new[](std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
			static void operator delete(void *ptr) {
			tscrypto::cryptoDelete(ptr);
		}
		static void operator delete[](void *ptr) {
			tscrypto::cryptoDelete(ptr);
		}

		virtual ~IObject();
		virtual std::shared_ptr<IServiceLocator> ServiceLocator() const
		{
			if (_serviceLocator.use_count() == 0)
				throw std::runtime_error("Service locator is already destroyed.");
			return _serviceLocator.lock();
		}
		virtual std::shared_ptr<IObject> clone() const { return nullptr; };
		virtual std::shared_ptr<IObject> newInstance() const { return nullptr; }
		virtual void OnConstructionFinished() {}

		std::weak_ptr<IServiceLocator> _serviceLocator;
		std::weak_ptr<IObject> _me;
	};

	struct VEILCORE_API IInitializableObject
	{
		virtual ~IInitializableObject() {}
		virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) = 0;
	};
}

extern VEILCORE_API std::shared_ptr<tsmod::IServiceLocator> TopServiceLocator();

namespace tsmod
{
	struct VEILCORE_API IServiceLocator
	{
		virtual bool AddSingletonClass(const tscrypto::tsCryptoStringBase& className, std::function<IObject* ()> creator) = 0;
		virtual bool AddSingletonObject(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<IObject> object) = 0;
		virtual bool AddClass(const tscrypto::tsCryptoStringBase& className, std::function<IObject* ()> creator) = 0;
		virtual bool CopyClass(const tscrypto::tsCryptoStringBase& className, IServiceLocator* copyTo) const = 0;
		virtual bool DeleteClass(const tscrypto::tsCryptoStringBase& className) = 0;

		virtual std::shared_ptr<IObject> Create(const tscrypto::tsCryptoStringBase& className) = 0;
		virtual std::shared_ptr<IObject> TryCreate(const tscrypto::tsCryptoStringBase& className) = 0;

		virtual tscrypto::tsCryptoStringList ObjectNames(bool onlyInstantiatedSingletons) const = 0;
		virtual tscrypto::tsCryptoStringList ObjectGroup(const tscrypto::tsCryptoStringBase& prefix, bool onlyInstantiatedSingletons) const = 0;

		virtual bool CanCreate(const tscrypto::tsCryptoStringBase& className) const = 0;
		virtual std::shared_ptr<IServiceLocator> Creator() const = 0;
		virtual std::shared_ptr<IObject> FinishConstruction(IObject* obj) = 0;

		virtual void acceptVisitor(IServiceLocatorVisitor *visitor) = 0;
		virtual void acceptVisitor(IConstServiceLocatorVisitor *visitor) const = 0;

		virtual std::shared_ptr<IObject> newInstance() const = 0;

		template <class T>
		std::shared_ptr<T> get_instance(const tscrypto::tsCryptoStringBase& className)
		{
			std::shared_ptr<T> obj = std::dynamic_pointer_cast<T>(TryCreate(className));
			if (!obj)
			{
				#ifdef _MSC_VER
				if (FrameworkDevOnly.WillLog())
					FrameworkDevOnly << "FAILED get_instance<" << typeid(T).name() << ">(" << className << ")" << tscrypto::endl;
				#endif
				throw std::runtime_error((tscrypto::tsCryptoString().append("Object not supported:  ").append(className)).c_str());
			}
			return obj;
		}
		template <class T>
		std::shared_ptr<T> try_get_instance(const tscrypto::tsCryptoStringBase& className)
		{
			std::shared_ptr<T> p = std::dynamic_pointer_cast<T>(TryCreate(className));
			if (!p)
			{
				#ifdef _MSC_VER
				if (FrameworkDevOnly.WillLog())
					FrameworkDevOnly << "FAILED try_get_instance<" << typeid(T).name() << ">(" << className << ")" << tscrypto::endl;
				#endif
			}
			return p;
		}
		template <class T>
		std::shared_ptr<T> Finish(IObject* obj)
		{
			std::shared_ptr<T> p = std::dynamic_pointer_cast<T>(FinishConstruction(obj));
			if (!p)
			{
				#ifdef _MSC_VER
				if (FrameworkDevOnly.WillLog())
					FrameworkDevOnly << "FAILED finish<" << typeid(T).name() << ">()" << tscrypto::endl;
				#endif
			}
			return p;
		}
		template <class T>
		std::vector<std::shared_ptr<T> > try_get_group(const tscrypto::tsCryptoStringBase& prefix, bool onlyInstantiatedSingletons)
		{
			tscrypto::tsCryptoString id(prefix);
			std::shared_ptr<tsmod::IServiceLocator> loc = resolvePath(id);
			std::vector<std::shared_ptr<T> > objList;

			if (!loc)
			{
				return objList;
			}

			if (loc.get() != dynamic_cast<const tsmod::IServiceLocator*>(this))
				return loc->try_get_group<T>(id.c_str(), onlyInstantiatedSingletons);

			tscrypto::tsCryptoStringList initializerList = ObjectGroup(id.c_str(), onlyInstantiatedSingletons);

			if (initializerList->size() > 0)
			{
				objList.reserve(initializerList->size());
				std::find_if(initializerList->begin(), initializerList->end(), [this, &objList](tscrypto::tsCryptoStringBase& name) -> bool {
					std::shared_ptr<T> obj = try_get_instance<T>(name.c_str());
					if (!obj)
						return true;
					objList.push_back(obj);
					return false;
				});
			}
			return objList;
		}
		template <class T>
		std::vector<std::shared_ptr<T> > get_group(const tscrypto::tsCryptoStringBase& prefix, bool onlyInstantiatedSingletons)
		{
			tscrypto::tsCryptoString id(prefix);
			std::shared_ptr<tsmod::IServiceLocator> loc = resolvePath(id);

			if (!loc)
			{
				throw std::runtime_error("Invalid service locator path requested.");
			}

			if (loc.get() != dynamic_cast<const tsmod::IServiceLocator*>(this))
				return loc->get_group<T>(id.c_str(), onlyInstantiatedSingletons);

			tscrypto::tsCryptoStringList initializerList = ObjectGroup(prefix, onlyInstantiatedSingletons);
			std::vector<std::shared_ptr<T> > objList;

			if (initializerList->size() > 0)
			{
				objList.reserve(initializerList->size());
				auto it1 = std::find_if(initializerList->begin(), initializerList->end(), [this, &objList](tscrypto::tsCryptoStringBase& name) -> bool {
					std::shared_ptr<T> obj = try_get_instance<T>(name.c_str());
					if (!obj)
						return true;
					objList.push_back(obj);
					return false;
				});
				if (it1 != initializerList->end())
					throw std::runtime_error("Object not supported");
			}
			return objList;
		}
		virtual std::shared_ptr<tsmod::IServiceLocator> resolvePath(tscrypto::tsCryptoStringBase &path, bool createPaths) = 0;
		virtual std::shared_ptr<tsmod::IServiceLocator> resolvePath(tscrypto::tsCryptoStringBase &path) const = 0;
		virtual tscrypto::tsCryptoString findObjectName(tsmod::IObject* obj) = 0;
		virtual void BuildObjectPath(tscrypto::tsCryptoStringBase& name) = 0;
		virtual ~IServiceLocator() {}
		virtual void CleanEmptyCollections(const tscrypto::tsCryptoStringBase& className = "") = 0;
		virtual void clear() = 0;
		// Added 7.0.33
		virtual void SetAsRoot() = 0;
		virtual bool IsRoot() const = 0;
		virtual std::shared_ptr<IObject> Create(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tsmod::IServiceLocator> onService) = 0;
		virtual std::shared_ptr<IObject> TryCreate(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tsmod::IServiceLocator> onService) = 0;
		template <class T>
		std::shared_ptr<T> get_instance(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tsmod::IServiceLocator> onService)
		{
			std::shared_ptr<T> obj = std::dynamic_pointer_cast<T>(TryCreate(className, onService));
			if (!obj)
			{
				tscrypto::tsCryptoString tmp;
				tmp << "Object not supported:  " << className;
				#ifdef _MSC_VER
				if (FrameworkDevOnly.WillLog())
					FrameworkDevOnly << "FAILED get_instance<" << typeid(T).name() << ">(" << className << ", onService)" << tscrypto::endl;
				#endif
				throw std::runtime_error(tmp.c_str());
			}
			return obj;
		}
		template <class T>
		std::shared_ptr<T> try_get_instance(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tsmod::IServiceLocator> onService)
		{
			std::shared_ptr<T> p = std::dynamic_pointer_cast<T>(TryCreate(className, onService));
			if (!p)
			{
				#ifdef _MSC_VER			
				if (FrameworkDevOnly.WillLog())
					FrameworkDevOnly << "FAILED try_get_instance<" << typeid(T).name() << ">(" << className << ", onService)" << tscrypto::endl;
				#endif
			}
			return p;
		}
		// Added 7.0.35
		virtual bool CopyClassDef(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& newName) = 0;
	};

	VEILCORE_API std::shared_ptr<tsmod::IServiceLocator> CreateServiceLocator();

	class VEILCORE_API IResourceLoader
	{
	public:
		virtual ~IResourceLoader() {}
		virtual bool LoadResourceFile(const tscrypto::tsCryptoStringBase& filename) = 0;
		virtual bool IsValid() = 0;
		virtual bool HasResource(const tscrypto::tsCryptoStringBase& resourceName) = 0;
		virtual tscrypto::tsCryptoData LoadResource(const tscrypto::tsCryptoStringBase& resourceName) = 0;

		// Added 7.0.21
		virtual void SetResourcePin(const tscrypto::tsCryptoData& pin) = 0;
	};
	class VEILCORE_API IReportError
	{
	public:
		virtual ~IReportError() {}
		virtual void SetJSONFault(const tscrypto::tsCryptoStringBase& ExceptionName, const tscrypto::tsCryptoStringBase& userMessage, const tscrypto::tsCryptoStringBase& devMessage, const tscrypto::tsCryptoStringBase& details) = 0;

		// Added 7.0.35
		typedef enum {
			Connection,
			Creation,
			Deletion,
			Move,
			Retrieval,
			Update,
			System,
			Argument,
			NotAdmin,
			NotAllowed,
			DataAccess,
			Protocol,
			License,
			NoFault,
			NeedsAuthentication,
		} FaultType;
		virtual void SetJSONFault(FaultType fault, const tscrypto::tsCryptoStringBase& userMessage, const tscrypto::tsCryptoStringBase& devMessage, const tscrypto::tsCryptoStringBase& details) = 0;
	};

	class VEILCORE_API IPluginModule
	{
	public:
		virtual bool connect(const tscrypto::tsCryptoStringBase& path, tsmod::IReportError* log) = 0;
		virtual void disconnect() = 0;
		virtual tscrypto::tsCryptoString Name() const = 0;
		virtual bool isValid() const = 0;
		virtual bool Initialize(tsmod::IReportError* log) = 0;
		virtual bool Terminate() = 0;
		virtual ~IPluginModule() {}
	};

	class VEILCORE_API IPluginModuleManager
	{
	public:
		virtual void LoadModule(const tscrypto::tsCryptoStringBase& path, tsmod::IReportError* log, std::function<void(std::function<bool()>)> registerCleanup) = 0;
		virtual std::shared_ptr<IPluginModule> FindModule(const tscrypto::tsCryptoStringBase& path) = 0;
		virtual void LoadModulesOfType(const tscrypto::tsCryptoStringBase& pattern, tsmod::IReportError* log, std::function<void(std::function<bool()>)> registerCleanup) = 0;
		virtual bool UseRootedPlugins() const = 0;
		virtual void UseRootedPlugins(bool setTo) = 0;
		virtual void TerminateAllPlugins() = 0;
		virtual ~IPluginModuleManager() {}

		// Added 7.0.33
		virtual void LoadModuleForService(const tscrypto::tsCryptoStringBase& path, tsmod::IReportError* log, std::shared_ptr<tsmod::IServiceLocator> servLoc, std::function<void(std::function<bool()>)> registerCleanup) = 0;
		virtual void LoadModulesOfTypeForService(const tscrypto::tsCryptoStringBase& pattern, tsmod::IReportError* log, std::shared_ptr<tsmod::IServiceLocator> servLoc, std::function<void(std::function<bool()>)> registerCleanup) = 0;
	};

	class VEILCORE_API ICleanup
	{
	public:
		virtual void TerminateSystem() = 0;
		virtual ~ICleanup() {}
	};
	class VEILCORE_API IAggregatableObject
	{
	public:
		virtual ~IAggregatableObject() {}
		virtual std::shared_ptr<tsmod::IObject> getContained() = 0;
		virtual void setContained(std::shared_ptr<tsmod::IObject> setTo) = 0;
		virtual std::shared_ptr<tsmod::IObject> getContainer() = 0;
		virtual void setContainer(std::shared_ptr<tsmod::IObject> setTo) = 0;
		virtual std::shared_ptr<tsmod::IObject> findTopContainer() = 0;
	};

	class VEILCORE_API IOrderedObject
	{
	public:
		virtual ~IOrderedObject() {}
		virtual uint32_t order() const = 0;
	};
	class VEILCORE_API IOrderedInitializer
	{
	public:
		virtual ~IOrderedInitializer() {}
		virtual uint32_t order() const = 0;
		virtual bool Initialize() = 0;
	};

	VEILCORE_API tsmod::IObject* CreatePluginModule();
	VEILCORE_API tsmod::IObject* CreateRootedPluginModule();

	VEILCORE_API tsmod::IObject* CreatePluginModuleManager();

	class VEILCORE_API IBaseProtocolStack
	{
	public:
		virtual ~IBaseProtocolStack() {}

		virtual void QueueReceivedData(const tscrypto::tsCryptoData& data) = 0;
		virtual void SetSentDataCallback(std::function<void(const tscrypto::tsCryptoData& data)> func) = 0;
		virtual void reserved3(bool setTo) = 0;
		virtual bool reserved4() = 0;
		virtual void closingConnection() = 0;
		virtual void channelShutdown() = 0;

		virtual bool supportProtocol(const char *protocolName) = 0;
		virtual bool startProtocol(const char *protocolName) = 0;
		virtual bool stopProtocol(const char *protocolName) = 0;
		virtual bool activateProtocol(const char *protocolName) = 0;
		virtual bool setActiveCallback(const char *protocolName, std::function<void(tsmod::IObject*)> onActive) = 0;
		virtual bool setInactiveCallback(const char *protocolName, std::function<void(tsmod::IObject*)> onInactive) = 0;
		virtual bool setProtocolIdentityObject(std::shared_ptr<tsmod::IObject> setTo) = 0;
		virtual bool setCommand(const char *protocolName, const char* commandName) = 0;
		virtual bool setCommandObject(const char *protocolName, std::shared_ptr<tsmod::IObject> setTo) = 0;
	};

};

#endif // __TSMOD_EXTENSION_H__

/*! @} */
