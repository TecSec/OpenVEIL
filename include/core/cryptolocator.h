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


/*! @file cryptolocator.h
 * @brief This file defines the classes and interfaces for the service locator and related classes.
*/

#ifndef __CRYPTOLOCATOR_H__
#define __CRYPTOLOCATOR_H__

#pragma once

namespace tscrypto
{
	class VEILCORE_API RWLock
	{
	public:
		RWLock();
		RWLock(RWLock&& obj);
		~RWLock();
		void StartReader() const;
		void EndReader() const;
		void StartWriter();
		void EndWriter();

	protected:
		void *_internal;

	private:
		RWLock(const RWLock& obj) = delete;
		RWLock& operator=(RWLock&& obj) = delete;
		RWLock& operator=(const RWLock& obj) = delete;
	};

	class VEILCORE_API AutoReaderLock
	{
	public:
		AutoReaderLock(const RWLock& lock);
		~AutoReaderLock();

	private:
		const RWLock& _lock;

		AutoReaderLock& operator=(const AutoReaderLock& obj) = delete;
	};

	class VEILCORE_API AutoWriterLock
	{
	public:
		AutoWriterLock(RWLock& lock);
		~AutoWriterLock();

	private:
		RWLock& _lock;

		AutoWriterLock& operator=(const AutoWriterLock& obj) = delete;
	};

	struct ICryptoLocator;

	struct ICryptoLocatorVisitor
	{
		virtual bool visitEnter(const tscrypto::tsCryptoStringBase& name, ICryptoLocator* locator) = 0;
		virtual void visitLeave(const tscrypto::tsCryptoStringBase& name, ICryptoLocator* locator) = 0;
		virtual void visit(const tscrypto::tsCryptoStringBase& name, bool singleton, bool object) = 0;
	};
	struct IConstCryptoLocatorVisitor
	{
		virtual bool visitEnter(const tscrypto::tsCryptoStringBase& name, const ICryptoLocator* locator) const = 0;
		virtual void visitLeave(const tscrypto::tsCryptoStringBase& name, const ICryptoLocator* locator) const = 0;
		virtual void visit(const tscrypto::tsCryptoStringBase& name, bool singleton, bool object) = 0;
	};

	struct ICryptoObject;
}

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4231)

VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::weak_ptr<tscrypto::ICryptoLocator>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::weak_ptr<tscrypto::ICryptoObject>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<tscrypto::ICryptoObject>;
#pragma warning(pop)
#endif // _MSC_VER

namespace tscrypto
{
	struct VEILCORE_API ICryptoObject
	{
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

		virtual ~ICryptoObject();
		virtual std::shared_ptr<ICryptoLocator> CryptoLocator() const
		{
			if (_cryptoLocator.use_count() == 0)
				throw std::runtime_error("Crypto locator is already destroyed.");
			return _cryptoLocator.lock();
		}
		virtual std::shared_ptr<ICryptoObject> clone() const { return nullptr; };
		virtual std::shared_ptr<ICryptoObject> newInstance() const { return nullptr; }
		virtual void OnConstructionFinished() {}

		std::weak_ptr<ICryptoLocator> _cryptoLocator;
		std::weak_ptr<ICryptoObject> _me;
	};

	struct VEILCORE_API IInitializableObject
	{
		virtual ~IInitializableObject() {}
		virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) = 0;
	};
}

namespace tscrypto
{
	struct VEILCORE_API ICryptoLocator
	{
		virtual ~ICryptoLocator() {}

		virtual std::shared_ptr<ICryptoObject> Create(const tscrypto::tsCryptoStringBase& className) = 0;
		virtual std::shared_ptr<ICryptoObject> TryCreate(const tscrypto::tsCryptoStringBase&className) = 0;

		virtual tsCryptoStringList ObjectNames(bool onlyInstantiatedSingletons) const = 0;
		virtual tsCryptoStringList ObjectGroup(const tscrypto::tsCryptoStringBase& prefix, bool onlyInstantiatedSingletons) const = 0;

		virtual bool CanCreate(const tscrypto::tsCryptoStringBase& className) const = 0;
		virtual std::shared_ptr<ICryptoLocator> Creator() const = 0;
		virtual std::shared_ptr<ICryptoObject> FinishConstruction(ICryptoObject* obj) = 0;

		virtual void acceptVisitor(ICryptoLocatorVisitor *visitor) = 0;
		virtual void acceptVisitor(IConstCryptoLocatorVisitor *visitor) const = 0;

		virtual std::shared_ptr<ICryptoObject> newInstance() const = 0;

		template <class T>
		std::shared_ptr<T> get_instance(const tscrypto::tsCryptoStringBase& className)
		{
			std::shared_ptr<T> obj = std::dynamic_pointer_cast<T>(TryCreate(className));
			if (!obj)
            {
                // printf ("typename:  %s\n", typeid(T).name());
				throw std::runtime_error((tsCryptoStringBase().append("Object not supported:  ").append(className)).c_str());
            }
			return obj;
		}
		template <class T>
		std::shared_ptr<T> try_get_instance(const tscrypto::tsCryptoStringBase& className)
		{
			return std::dynamic_pointer_cast<T>(TryCreate(className));
		}
		template <class T>
		std::shared_ptr<T> Finish(ICryptoObject* obj)
		{
			return std::dynamic_pointer_cast<T>(FinishConstruction(obj));
		}
		template <class T>
		std::vector<std::shared_ptr<T> > try_get_group(const tscrypto::tsCryptoStringBase& prefix, bool onlyInstantiatedSingletons)
		{
			tsCryptoStringBase id(prefix);
			std::shared_ptr<tscrypto::ICryptoLocator> loc = resolvePath(id);
			std::vector<std::shared_ptr<T> > objList;

			if (!loc)
			{
				return objList;
			}

			if (loc.get() != dynamic_cast<const tscrypto::ICryptoLocator*>(this))
				return loc->try_get_group<T>(id, onlyInstantiatedSingletons);

			tsCryptoStringList initializerList = ObjectGroup(id, onlyInstantiatedSingletons);

			if (initializerList->size() > 0)
			{
				objList.reserve(initializerList->size());
				std::find_if(initializerList->begin(), initializerList->end(), [this, &objList](tsCryptoStringBase& name) -> bool {
					std::shared_ptr<T> obj = try_get_instance<T>(name);
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
			tsCryptoStringBase id(prefix);
			std::shared_ptr<tscrypto::ICryptoLocator> loc = resolvePath(id);

			if (!loc)
			{
				throw std::runtime_error("Invalid service locator path requested.");
			}

			if (loc.get() != dynamic_cast<const tscrypto::ICryptoLocator*>(this))
				return loc->get_group<T>(id, onlyInstantiatedSingletons);

			tsCryptoStringList initializerList = ObjectGroup(prefix, onlyInstantiatedSingletons);
			std::vector<std::shared_ptr<T> > objList;

			if (initializerList->size() > 0)
			{
				objList.reserve(initializerList->size());
				auto it1 = std::find_if(initializerList->begin(), initializerList->end(), [this, &objList](tsCryptoStringBase& name) -> bool {
					std::shared_ptr<T> obj = try_get_instance<T>(name);
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
		virtual std::shared_ptr<tscrypto::ICryptoLocator> resolvePath(tsCryptoStringBase &path, bool createPaths) = 0;
		virtual std::shared_ptr<tscrypto::ICryptoLocator> resolvePath(tsCryptoStringBase &path) const = 0;
		virtual tsCryptoString findObjectName(tscrypto::ICryptoObject* obj) = 0;
		virtual void BuildObjectPath(tsCryptoStringBase& name) = 0;
		virtual bool IsRoot() const = 0;
		virtual std::shared_ptr<ICryptoObject> Create(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tscrypto::ICryptoLocator> onService) = 0;
		virtual std::shared_ptr<ICryptoObject> TryCreate(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tscrypto::ICryptoLocator> onService) = 0;
		template <class T>
		std::shared_ptr<T> get_instance(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tscrypto::ICryptoLocator> onService)
		{
			std::shared_ptr<T> obj = std::dynamic_pointer_cast<T>(TryCreate(className, onService));
			if (!obj)
				throw std::runtime_error((tsCryptoStringBase().append("Object not supported:  " ).append( className)).c_str());
			return obj;
		}
		template <class T>
		std::shared_ptr<T> try_get_instance(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tscrypto::ICryptoLocator> onService)
		{
			return std::dynamic_pointer_cast<T>(TryCreate(className, onService));
		}
	};

	VEILCORE_API std::shared_ptr<tscrypto::ICryptoLocator> CreateCryptoLocator();

	class VEILCORE_API IAggregatableObject
	{
	public:
		virtual ~IAggregatableObject() {}
		virtual std::shared_ptr<tscrypto::ICryptoObject> getContained() = 0;
		virtual void setContained(std::shared_ptr<tscrypto::ICryptoObject> setTo) = 0;
		virtual std::shared_ptr<tscrypto::ICryptoObject> getContainer() = 0;
		virtual void setContainer(std::shared_ptr<tscrypto::ICryptoObject> setTo) = 0;
		virtual std::shared_ptr<tscrypto::ICryptoObject> findTopContainer() = 0;
	};

};

#endif // __CRYPTOLOCATOR_H__

/*! @} */
