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

using namespace tscrypto;

tscrypto::ICryptoObject::~ICryptoObject()
{
	//#ifdef _DEBUG
	//	AutoLocker lock(gAllocatedObjectsListLock);
	//	auto it = std::remove_if(gAllocatedObjects.begin(), gAllocatedObjects.end(), [this](std::weak_ptr<tscrypto::ICryptoObject> obj) ->bool {
	//		if (obj.expired())
	//			return true;
	//		if (!obj.owner_before(_me) && !_me.owner_before(obj))
	//			return true;
	//		return false;
	//	});
	//	if (it != gAllocatedObjects.end())
	//		gAllocatedObjects.erase(it, gAllocatedObjects.end());
	//#endif
}
class CryptoLocator_t : public RWLock, public tscrypto::ICryptoLocatorWriter, public tscrypto::ICryptoObject
{
public:
	static std::shared_ptr<tscrypto::ICryptoLocator> Create();
	CryptoLocator_t();
	virtual ~CryptoLocator_t();

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

	virtual bool AddSingletonClass(const tscrypto::tsCryptoStringBase& className, std::function<tscrypto::ICryptoObject* ()> creator) override;
	virtual bool AddSingletonObject(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tscrypto::ICryptoObject> object) override;
	virtual bool AddClass(const tscrypto::tsCryptoStringBase& className, std::function<tscrypto::ICryptoObject* ()> creator) override;
	virtual bool CopyClass(const tscrypto::tsCryptoStringBase& className, ICryptoLocator* copyTo) const override;
	virtual bool DeleteClass(const tscrypto::tsCryptoStringBase& className) override;

	virtual std::shared_ptr<tscrypto::ICryptoObject> Create(const tscrypto::tsCryptoStringBase& className) override;
	virtual std::shared_ptr<tscrypto::ICryptoObject> TryCreate(const tscrypto::tsCryptoStringBase& className) override;

	virtual tsCryptoStringList ObjectNames(bool onlyInstantiatedSingletons) const override;
	virtual tsCryptoStringList ObjectGroup(const tscrypto::tsCryptoStringBase& prefix, bool onlyInstantiatedSingletons) const override;

	virtual bool CanCreate(const tscrypto::tsCryptoStringBase& className) const override;
	virtual std::shared_ptr<tscrypto::ICryptoLocator> Creator() const override;
	virtual std::shared_ptr<tscrypto::ICryptoObject> FinishConstruction(tscrypto::ICryptoObject* obj) override;
	virtual std::shared_ptr<tscrypto::ICryptoObject> Create(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tscrypto::ICryptoLocator> onService) override;
	virtual std::shared_ptr<tscrypto::ICryptoObject> TryCreate(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tscrypto::ICryptoLocator> onService) override;

	// IMakeNewInstance
	virtual std::shared_ptr<tscrypto::ICryptoObject> newInstance() const override;

	// Hierarchical visitor
	virtual void acceptVisitor(tscrypto::ICryptoLocatorVisitor *visitor) override;
	virtual void acceptVisitor(tscrypto::IConstCryptoLocatorVisitor *visitor) const override;

	virtual std::shared_ptr<tscrypto::ICryptoLocator> resolvePath(tsCryptoStringBase &path, bool createPaths) override;
	virtual std::shared_ptr<tscrypto::ICryptoLocator> resolvePath(tsCryptoStringBase &path) const override;
	virtual tsCryptoString findObjectName(tscrypto::ICryptoObject* obj) override;
	virtual void BuildObjectPath(tsCryptoStringBase& name) override;

	virtual void CleanEmptyCollections(const tscrypto::tsCryptoStringBase& className) override
	{
		std::shared_ptr<tscrypto::ICryptoObject> ptr = _me.lock();

		if (className == nullptr)
		{
			// First go through the children and clean up any and all empty containers
			size_t count = _singleton_objects.size();
			for (ptrdiff_t i = count - 1; i >= 0; i--)
			{
				auto it = _singleton_objects.begin();
				std::advance(it, i);
				std::shared_ptr<tscrypto::ICryptoLocatorWriter> loc = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(it->second);
				if (!!loc)
					loc->CleanEmptyCollections(nullptr);
			}
			if (_classes.size() == 0 && _singleton_classes.size() == 0 && _singleton_objects.size() == 0)
			{
				if (!_creator.expired())
				{
					tsCryptoString name = _creator.lock()->findObjectName(this);
					if (name.size() > 0)
					{
						std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(_creator.lock())->DeleteClass(name);
					}
				}
			}
		}
		else
		{
			std::shared_ptr<tscrypto::ICryptoLocatorWriter> loc = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(internalTryCreateSingleton(className, className));

			if (!!loc)
			{
				loc->CleanEmptyCollections(nullptr);
			}
		}
	}
	virtual void clear() override
	{
		// First go through the children and clean up any and all empty containers
		for (std::pair<const tsCryptoString, std::shared_ptr<tscrypto::ICryptoObject>>& obj : _singleton_objects) {
			std::shared_ptr<tscrypto::ICryptoLocatorWriter> loc = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(obj.second);
			if (!!loc)
				loc->clear();
		}
		_classes.clear();
		_singleton_classes.clear();
		_singleton_objects.clear();
		_creator.reset();
	}
	virtual void SetAsRoot() override
	{
		_isRoot = true;
		_creator.reset();
	}
	virtual bool IsRoot() const override
	{
		return _isRoot || _creator.expired();
	}
protected:
	typedef std::map<tsCryptoString, std::function<tscrypto::ICryptoObject*()> > _ClassMap;
	typedef std::map<tsCryptoString, std::shared_ptr<tscrypto::ICryptoObject>>	_ObjectMap;

	std::shared_ptr<tscrypto::ICryptoObject> internalTryCreate(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName);
	std::shared_ptr<tscrypto::ICryptoObject> internalTryCreateSingleton(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName);
	std::shared_ptr<tscrypto::ICryptoObject> internalTryCreate(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName, std::shared_ptr<tscrypto::ICryptoLocator> onService);
	std::shared_ptr<tscrypto::ICryptoObject> internalTryCreateSingleton(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName, std::shared_ptr<tscrypto::ICryptoLocator> onService);
	bool internalCanCreate(const tscrypto::tsCryptoStringBase& className) const;
	std::shared_ptr<tscrypto::ICryptoLocator> findRoot() const
	{
		std::shared_ptr<tscrypto::ICryptoLocator> item = std::dynamic_pointer_cast<tscrypto::ICryptoLocator>(_me.lock());

		while (!item->IsRoot())
		{
			std::shared_ptr<tscrypto::ICryptoLocator> prior(item);
			item = item->Creator();
			if (item == prior)
				break;
		}
		return item;
	}


	_ClassMap	_classes;
	_ClassMap	_singleton_classes;
	_ObjectMap  _singleton_objects;
	std::weak_ptr<tscrypto::ICryptoLocator> _creator;
	bool _isRoot;

};

std::shared_ptr<tscrypto::ICryptoLocator> CryptoLocator_t::Create()
{
	std::shared_ptr<CryptoLocator_t> obj = std::make_shared<CryptoLocator_t>();
	std::shared_ptr<tscrypto::ICryptoObject> io = std::dynamic_pointer_cast<tscrypto::ICryptoObject>(obj);

	io->_cryptoLocator = obj;
	io->_me = io;
	io->OnConstructionFinished();
	return std::dynamic_pointer_cast<tscrypto::ICryptoLocator>(obj);
}

CryptoLocator_t::CryptoLocator_t() : _isRoot(false)
{
}

CryptoLocator_t::~CryptoLocator_t()
{
	AutoWriterLock lock(*this);
	clear();
}

std::shared_ptr<tscrypto::ICryptoObject> CryptoLocator_t::newInstance() const
{
	std::shared_ptr<CryptoLocator_t> servLoc = std::make_shared<CryptoLocator_t>();
	std::shared_ptr<tscrypto::ICryptoObject> obj = std::dynamic_pointer_cast<tscrypto::ICryptoObject>(servLoc);

	std::dynamic_pointer_cast<CryptoLocator_t>(obj)->_creator = CryptoLocator();
	obj->_cryptoLocator = std::dynamic_pointer_cast<tscrypto::ICryptoLocator>(obj);
	obj->_me = obj;
	obj->OnConstructionFinished();
	return obj;
}

bool CryptoLocator_t::AddSingletonClass(const tscrypto::tsCryptoStringBase& className, std::function<tscrypto::ICryptoObject* ()> creator)
{
	AutoWriterLock lock(*this);

	tsCryptoString id(className);
	std::shared_ptr<tscrypto::ICryptoLocatorWriter> loc = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(resolvePath(id, true));

	if (!loc)
	{
		throw std::runtime_error("Invalid service locator path requested.");
	}

	if (loc.get() != dynamic_cast<tscrypto::ICryptoLocatorWriter*>(this))
		return loc->AddSingletonClass(id, creator);

	_ClassMap::iterator found_single = _singleton_classes.find(id);
	if (found_single != _singleton_classes.end())
	{
		return false;
	}
	_ObjectMap::iterator foundObject = _singleton_objects.find(id);
	if (foundObject != _singleton_objects.end())
	{
		return false;
	}
	_singleton_classes.insert(std::make_pair(id, creator));
	return true;
}

bool CryptoLocator_t::AddSingletonObject(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tscrypto::ICryptoObject> object)
{
	AutoWriterLock lock(*this);
	tsCryptoString id(className);
	std::shared_ptr<tscrypto::ICryptoLocatorWriter> loc = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(resolvePath(id, true));

	if (!loc)
	{
		throw std::runtime_error("Invalid service locator path requested.");
	}

	if (loc.get() != dynamic_cast<tscrypto::ICryptoLocatorWriter*>(this))
		return loc->AddSingletonObject(id, object);

	_ObjectMap::iterator foundObject = _singleton_objects.find(id);
	if (foundObject != _singleton_objects.end())
	{
		std::shared_ptr<tscrypto::IAggregatableObject> child = std::dynamic_pointer_cast<tscrypto::IAggregatableObject>(foundObject->second);
		std::shared_ptr<tscrypto::IAggregatableObject> parent = std::dynamic_pointer_cast<tscrypto::IAggregatableObject>(object);

		if (!parent)
			return false;
		parent->setContained(foundObject->second);
		if (!!child)
		{
			child->setContainer(object);
		}
		foundObject->second = object;
		return true;
	}
	_singleton_objects.insert(std::make_pair(id, object));
	return true;
}

bool CryptoLocator_t::AddClass(const tscrypto::tsCryptoStringBase& className, std::function<tscrypto::ICryptoObject* ()> creator)
{
	tsCryptoString id(className);
	std::shared_ptr<tscrypto::ICryptoLocatorWriter> loc = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(resolvePath(id, true));

	if (!loc)
	{
		throw std::runtime_error("Invalid service locator path requested.");
	}

	if (loc.get() != dynamic_cast<tscrypto::ICryptoLocatorWriter*>(this))
		return loc->AddClass(id, creator);

	AutoWriterLock lock(*this);
	_ClassMap::iterator found_single = _singleton_classes.find(id);
	if (found_single != _singleton_classes.end())
	{
		return false;
	}
	_ObjectMap::iterator foundObject = _singleton_objects.find(id);
	if (foundObject != _singleton_objects.end())
	{
		return false;
	}
	found_single = _classes.find(id);
	if (found_single != _classes.end())
	{
		return false;
	}
	_classes.insert(std::make_pair(id, creator));
	return true;
}

bool CryptoLocator_t::CopyClass(const tscrypto::tsCryptoStringBase& className, ICryptoLocator* copyTo) const
{
	tsCryptoString id(className);

	std::shared_ptr<tscrypto::ICryptoLocatorWriter> loc = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(resolvePath(id));

	if (!loc)
	{
		throw std::runtime_error("Invalid service locator path requested.");
	}

	if (loc.get() != dynamic_cast<const tscrypto::ICryptoLocatorWriter*>(this))
		return loc->CopyClass(id, copyTo);

	AutoReaderLock lock(*this);
	_ClassMap::const_iterator found_single = _singleton_classes.find(id);
	if (found_single != _singleton_classes.end())
	{
		tscrypto::ICryptoLocatorWriter* writableCopyTo = dynamic_cast<tscrypto::ICryptoLocatorWriter*>(copyTo);
		if (writableCopyTo == nullptr)
			return false;

		bool retVal = writableCopyTo->AddSingletonClass(className, found_single->second);
		return retVal;
	}
	found_single = _classes.find(id);
	if (found_single != _classes.end())
	{
		tscrypto::ICryptoLocatorWriter* writableCopyTo = dynamic_cast<tscrypto::ICryptoLocatorWriter*>(copyTo);
		if (writableCopyTo == nullptr)
			return false;

		bool retVal = writableCopyTo->AddClass(className, found_single->second);
		return retVal;
	}
	return false;
}

bool CryptoLocator_t::DeleteClass(const tscrypto::tsCryptoStringBase& className)
{
	tsCryptoString id(className);
	bool retVal = false;

	std::shared_ptr<tscrypto::ICryptoLocatorWriter> loc = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(resolvePath(id, false));

	if (!loc)
	{
		return true;
	}

	if (loc.get() != dynamic_cast<tscrypto::ICryptoLocator*>(this))
		return loc->DeleteClass(id);

	AutoWriterLock lock(*this);
	_ClassMap::iterator found_single = _singleton_classes.find(id);
	if (found_single != _singleton_classes.end())
	{
		_singleton_classes.erase(found_single);
		retVal = true;
	}
	_ObjectMap::iterator foundObject = _singleton_objects.find(id);
	if (foundObject != _singleton_objects.end())
	{
		std::shared_ptr<tscrypto::IAggregatableObject> parent = std::dynamic_pointer_cast<tscrypto::IAggregatableObject>(foundObject->second);

		if (!!parent && !!parent->getContained())
		{
			std::shared_ptr<tscrypto::IAggregatableObject> child = std::dynamic_pointer_cast<tscrypto::IAggregatableObject>(foundObject->second);
			foundObject->second = parent->getContained();
			if (!!child)
				child->setContainer(nullptr);
		}
		else
		{
			_singleton_objects.erase(foundObject);
		}

		retVal = true;
	}
	found_single = _classes.find(id);
	if (found_single != _classes.end())
	{
		_classes.erase(found_single);
		retVal = true;
	}
	return retVal;
}

std::shared_ptr<tscrypto::ICryptoObject> CryptoLocator_t::Create(const tscrypto::tsCryptoStringBase& className)
{
	std::shared_ptr<tscrypto::ICryptoObject> obj = TryCreate(className);

	if (!obj)
		throw std::runtime_error(("invalid id: " + tsCryptoString(className)).c_str());
	return obj;
}

std::shared_ptr<tscrypto::ICryptoObject> CryptoLocator_t::Create(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tscrypto::ICryptoLocator> onService)
{
	std::shared_ptr<tscrypto::ICryptoObject> obj = TryCreate(className, onService);

	if (!obj)
		throw std::runtime_error(("invalid id: " + tsCryptoString(className)).c_str());
	return obj;
}

std::shared_ptr<tscrypto::ICryptoLocator> CryptoLocator_t::resolvePath(tsCryptoStringBase &path, bool createPaths)
{
	tsCryptoString id(path);

	id.ToUpper();
    // printf("---- Locating %s ----\n", id.c_str());
	if (id.find('/') != tsCryptoString::npos)
	{
		std::shared_ptr<tscrypto::ICryptoLocatorWriter> loc = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(_me.lock());

		id.Replace("//", "/");
		if (id[0] == '/')
		{
			loc = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(findRoot());
			id.DeleteAt(0, 1);
		}

		// Resolve paths first
		tsCryptoStringList paths = id.split("/", 5000, true);
		size_t count = paths->size();

		for (size_t i = 0; i < count - 1; i++)
		{
			if (paths->at(i) == ".")
			{
				// Current service locator
			}
			else if (paths->at(i) == "..")
			{
				// Parent service locator
				if (!loc->Creator())
					return nullptr;
				loc = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(loc->Creator());
			}
			else
			{
				std::shared_ptr<tscrypto::ICryptoLocatorWriter> newLoc;

				newLoc = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(((CryptoLocator_t*)loc.get())->internalTryCreateSingleton(paths->at(i), paths->at(i)));
				if (!newLoc && createPaths)
				{
					newLoc = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(loc->newInstance());
					loc->AddSingletonObject(paths->at(i), std::dynamic_pointer_cast<tscrypto::ICryptoObject>(newLoc));
				}
				if (!newLoc)
					return nullptr;
				loc = newLoc;
			}
		}
		path = paths->at(count - 1);
		return loc;
	}
	path = id;
	return std::dynamic_pointer_cast<tscrypto::ICryptoLocator>(_me.lock());
}
std::shared_ptr<tscrypto::ICryptoLocator> CryptoLocator_t::resolvePath(tsCryptoStringBase &path) const
{
	tsCryptoString id(path);

	id.ToUpper();
	if (id.find('/') != tsCryptoString::npos)
	{
		std::shared_ptr<tscrypto::ICryptoLocator> loc = std::dynamic_pointer_cast<tscrypto::ICryptoLocator>(_me.lock());

		id.Replace("//", "/");
		if (id[0] == '/')
		{
			loc = findRoot();
			id.DeleteAt(0, 1);
		}

		// Resolve paths first
		tsCryptoStringList paths = id.split("/", 5000, true);
		size_t count = paths->size();

		for (size_t i = 0; i < count - 1; i++)
		{
			if (paths->at(i) == ".")
			{
				// Current service locator
			}
			else if (paths->at(i) == "..")
			{
				// Parent service locator
				if (!loc->Creator())
					return nullptr;
				loc = loc->Creator();
			}
			else
			{
				std::shared_ptr<tscrypto::ICryptoLocator> newLoc;

				newLoc = std::dynamic_pointer_cast<tscrypto::ICryptoLocator>(((CryptoLocator_t*)loc.get())->internalTryCreateSingleton(paths->at(i), paths->at(i)));
				if (!newLoc)
					return nullptr;
				loc = newLoc;
			}
		}
		path = paths->at(count - 1);
		return loc;
	}
	path = id;
	return std::dynamic_pointer_cast<tscrypto::ICryptoLocator>(_me.lock());
}

std::shared_ptr<tscrypto::ICryptoObject> CryptoLocator_t::TryCreate(const tscrypto::tsCryptoStringBase& className)
{
	tsCryptoString id(className);
	std::shared_ptr<tscrypto::ICryptoObject> obj;
	std::shared_ptr<tscrypto::ICryptoLocator> loc = resolvePath(id, false);

	if (!loc)
	{
		//throw std::runtime_error("Invalid service locator path requested.  Parent does not exist.");
		return nullptr;
	}

	if (loc.get() != dynamic_cast<tscrypto::ICryptoLocator*>(this))
		return loc->TryCreate(id);

	tsCryptoString fullName(id);

	// Remove parameters
	tsCryptoStringList parts = id.split(";", 2);
	id = parts->at(0);

	// Now find the object
	while (id.size() > 0)
	{
		if (!(obj = internalTryCreate(id, fullName)))
		{
			size_t index = id.rfind('-');

			if (index == tsCryptoString::npos)
				return nullptr;
			id.resize(index);
		}
		else
			return obj;
	}
	return nullptr;
}
std::shared_ptr<tscrypto::ICryptoObject> CryptoLocator_t::TryCreate(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tscrypto::ICryptoLocator> onService)
{
	tsCryptoString id(className);
	std::shared_ptr<tscrypto::ICryptoObject> obj;
	std::shared_ptr<tscrypto::ICryptoLocator> loc = resolvePath(id, false);

	if (!loc)
	{
		//throw std::runtime_error("Invalid service locator path requested.  Parent does not exist.");
		return nullptr;
	}

	if (loc.get() != dynamic_cast<tscrypto::ICryptoLocator*>(this))
		return loc->TryCreate(id, onService);

	tsCryptoString fullName(id);

	// Remove parameters
	tsCryptoStringList parts = id.split(";", 2);
	id = parts->at(0);

	// Now find the object
	while (id.size() > 0)
	{
		if (!(obj = internalTryCreate(id, fullName, onService)))
		{
			size_t index = id.rfind('-');

			if (index == tsCryptoString::npos)
				return nullptr;
			id.resize(index);
		}
		else
			return obj;
	}
	return nullptr;
}

tsCryptoStringList CryptoLocator_t::ObjectNames(bool onlyInstantiatedSingletons) const
{
	tsCryptoStringList tmp = CreateTsCryptoStringList();

	AutoReaderLock lock(*this);
	for (auto iter = _singleton_objects.begin(); iter != _singleton_objects.end(); iter++)
	{
		tmp->push_back(iter->first);
	}
	if (!onlyInstantiatedSingletons)
	{
		for (auto iter = _singleton_classes.begin(); iter != _singleton_classes.end(); iter++)
		{
			tmp->push_back(iter->first);
		}
		for (auto iter = _classes.begin(); iter != _classes.end(); iter++)
		{
			tmp->push_back(iter->first);
		}
	}
	return tmp;
}

tsCryptoStringList CryptoLocator_t::ObjectGroup(const tscrypto::tsCryptoStringBase& prefix, bool onlyInstantiatedSingletons) const
{
	tsCryptoStringList tmp = CreateTsCryptoStringList();
	tsCryptoString id(prefix);
	std::shared_ptr<tscrypto::ICryptoLocator> loc = resolvePath(id);
	tsCryptoString path;

	if (!loc)
	{
		throw std::runtime_error("Invalid service locator path requested.");
	}

	if (loc.get() != dynamic_cast<const tscrypto::ICryptoLocator*>(this))
		return loc->ObjectGroup(id, onlyInstantiatedSingletons);

	loc->BuildObjectPath(path);

	AutoReaderLock lock(*this);
	for (auto iter = _singleton_objects.begin(); iter != _singleton_objects.end(); iter++)
	{
		if (TsStrnCmp(id.c_str(), iter->first.c_str(), id.size()) == 0)
			tmp->push_back(path + iter->first);
	}
	if (!onlyInstantiatedSingletons)
	{
		for (auto iter = _singleton_classes.begin(); iter != _singleton_classes.end(); iter++)
		{
			if (TsStrnCmp(id.c_str(), iter->first.c_str(), id.size()) == 0)
				tmp->push_back(path + iter->first);
		}
		for (auto iter = _classes.begin(); iter != _classes.end(); iter++)
		{
			if (TsStrnCmp(id.c_str(), iter->first.c_str(), id.size()) == 0)
				tmp->push_back(path + iter->first);
		}
	}
	return tmp;
}

bool CryptoLocator_t::CanCreate(const tscrypto::tsCryptoStringBase& className) const
{
	tsCryptoString id(className);

	std::shared_ptr<tscrypto::ICryptoLocator> loc = resolvePath(id);

	if (!loc)
	{
		return false;
	}

	if (loc.get() != dynamic_cast<const tscrypto::ICryptoLocator*>(this))
		return loc->CanCreate(id);

	// Remove parameters
	tsCryptoStringList parts = id.split(";", 2);
	id = parts->at(0);

	// Now find the object
	while (id.size() > 0)
	{
		if (!internalCanCreate(id))
		{
			size_t index = id.rfind('-');

			if (index == tsCryptoString::npos)
				return false;
			id.resize(index);
		}
		else
			return true;
	}
	return false;
}

std::shared_ptr<tscrypto::ICryptoLocator> CryptoLocator_t::Creator() const
{
	if (_creator.use_count() == 0)
		return nullptr;
	return _creator.lock();
}

std::shared_ptr<tscrypto::ICryptoObject> CryptoLocator_t::FinishConstruction(tscrypto::ICryptoObject* obj)
{
	if (!obj)
		return nullptr;

	std::shared_ptr<tscrypto::ICryptoObject> o(obj);

	o->_cryptoLocator = CryptoLocator();
	o->_me = o;
	o->OnConstructionFinished();
	//#ifdef _DEBUG
	//	tsAutoLocker lock(gAllocatedObjectsListLock);
	//	gAllocatedObjects.push_back(o->_me);
	//#endif
	return o;
}

void CryptoLocator_t::acceptVisitor(tscrypto::ICryptoLocatorVisitor *visitor)
{
	std::map<tsCryptoString, bool> tmp;
	std::shared_ptr<tscrypto::ICryptoLocator> Me = CryptoLocator();

	AutoWriterLock lock(*this);
	for (auto iter = _singleton_classes.begin(); iter != _singleton_classes.end(); iter++)
	{
		tmp.insert(std::make_pair(iter->first, true));
	}
	for (auto iter = _classes.begin(); iter != _classes.end(); iter++)
	{
		tmp.insert(std::make_pair(iter->first, false));
	}

	//  for (auto iter = _singleton_objects.begin(); iter != _singleton_objects.end(); iter++)
	//  {
		  //std::shared_ptr<tscrypto::ICryptoObject> obj = iter->second->_me.lock();
		  //if (!!obj && !!std::dynamic_pointer_cast<tscrypto::ICryptoLocator>(obj))
		  //{
		  //	auto it = std::find(tmp.begin(), tmp.end(), std::make_pair(iter->first, true));
		  //	if (it != tmp.end())
		  //	{
		  //		tmp.erase(it);
		  //	}
		  //}
	//  }

	for (auto value : tmp)
	{
		visitor->visit(value.first, value.second, false);
	}
	for (auto iter : _singleton_objects)
	{
		if (!!iter.second)
		{
			std::shared_ptr<tscrypto::ICryptoObject> obj = iter.second->_me.lock();
			if (!!obj)
			{
				std::shared_ptr<tscrypto::ICryptoLocator> subLoc = std::dynamic_pointer_cast<tscrypto::ICryptoLocator>(obj);
				if (!subLoc)
				{
					visitor->visit(iter.first, true, true);
				}
			}
		}
	}
	for (auto iter : _singleton_objects)
	{
		std::shared_ptr<tscrypto::ICryptoObject> obj = iter.second->_me.lock();
		if (!!obj)
		{
			std::shared_ptr<tscrypto::ICryptoLocator> subLoc = std::dynamic_pointer_cast<tscrypto::ICryptoLocator>(obj);
			if (!!subLoc)
			{
				if (visitor->visitEnter(iter.first, subLoc.get()))
				{
					subLoc->acceptVisitor(visitor);
				}
				visitor->visitLeave(iter.first, subLoc.get());
			}
		}
	}
}

void CryptoLocator_t::acceptVisitor(tscrypto::IConstCryptoLocatorVisitor *visitor) const
{
	std::map<tsCryptoString, bool> tmp;
	std::shared_ptr<tscrypto::ICryptoLocator> Me = CryptoLocator();

	AutoReaderLock lock(*this);
	for (auto iter = _singleton_classes.begin(); iter != _singleton_classes.end(); iter++)
	{
		tmp.insert(std::make_pair(iter->first, true));
	}
	for (auto iter = _classes.begin(); iter != _classes.end(); iter++)
	{
		tmp.insert(std::make_pair(iter->first, false));
	}

	//  for (auto iter = _singleton_objects.begin(); iter != _singleton_objects.end(); iter++)
	//  {
		  //std::shared_ptr<tscrypto::ICryptoObject> obj = iter->second->_me.lock();
		  //if (!!obj && !!std::dynamic_pointer_cast<tscrypto::ICryptoLocator>(obj))
		  //{
		  //	auto it = std::find(tmp.begin(), tmp.end(), std::make_pair(iter->first, true));
		  //	if (it != tmp.end())
		  //	{
		  //		tmp.erase(it);
		  //	}
		  //}
	//  }

	for (auto value : tmp)
	{
		visitor->visit(value.first, value.second, false);
	}
	for (auto iter : _singleton_objects)
	{
		std::shared_ptr<tscrypto::ICryptoObject> obj = iter.second->_me.lock();
		if (!!obj)
		{
			std::shared_ptr<tscrypto::ICryptoLocator> subLoc = std::dynamic_pointer_cast<tscrypto::ICryptoLocator>(obj);
			if (!subLoc)
			{
				visitor->visit(iter.first, true, true);
			}
		}
	}
	for (auto iter = _singleton_objects.begin(); iter != _singleton_objects.end(); iter++)
	{
		std::shared_ptr<tscrypto::ICryptoObject> obj = iter->second->_me.lock();
		if (!!obj)
		{
			std::shared_ptr<tscrypto::ICryptoLocator> subLoc = std::dynamic_pointer_cast<tscrypto::ICryptoLocator>(obj);
			if (!!subLoc)
			{
				if (visitor->visitEnter(iter->first, subLoc.get()))
				{
					subLoc->acceptVisitor(visitor);
				}
				visitor->visitLeave(iter->first, subLoc.get());
			}
		}
	}
}

std::shared_ptr<tscrypto::ICryptoObject> CryptoLocator_t::internalTryCreateSingleton(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName)
{
	tscrypto::ICryptoObject* obj = nullptr;
	tsCryptoString id(className);
	bool registerAsSingleton = false;

	id.ToUpper();
	{
		_ObjectMap::const_iterator foundObject;
		_ClassMap::const_iterator found_single;

		{
			AutoReaderLock lock(*this);
			foundObject = _singleton_objects.find(id);
			if (foundObject != _singleton_objects.end())
			{
				std::shared_ptr<tscrypto::ICryptoObject> tmp = foundObject->second;
				return tmp;
			}

			found_single = _singleton_classes.find(id);
		}
		if (found_single != _singleton_classes.end())
		{
			obj = found_single->second();
			if (!!obj)
			{
				registerAsSingleton = true;
			}
		}
	}
	if (obj == nullptr)
	{
		return nullptr;
	}

	std::shared_ptr<tscrypto::ICryptoObject> o = FinishConstruction(obj);

	std::shared_ptr<tscrypto::IInitializableObject> initObj = std::dynamic_pointer_cast<tscrypto::IInitializableObject>(o);
	if (!!initObj)
	{
		if (!initObj->InitializeWithFullName(fullName))
			throw std::runtime_error(("Initialization failed: " + tsCryptoString(fullName)).c_str());
	}

	if (registerAsSingleton && !!o)
	{
		AutoWriterLock lock(*this);
		_singleton_objects.insert(std::make_pair(id, o));
	}
	return o;
}
std::shared_ptr<tscrypto::ICryptoObject> CryptoLocator_t::internalTryCreateSingleton(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName, std::shared_ptr<tscrypto::ICryptoLocator> _onService)
{
	tscrypto::ICryptoObject* obj = nullptr;
	tsCryptoString id(className);
	bool registerAsSingleton = false;
	std::shared_ptr<tscrypto::ICryptoLocatorWriter> onService = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(_onService);

	if (!onService && !!_onService)
		return nullptr;

	id.ToUpper();
	{
		_ObjectMap::const_iterator foundObject;
		_ClassMap::const_iterator found_single;

		{
			AutoReaderLock lock(*this);
			foundObject = _singleton_objects.find(id);
			if (foundObject != _singleton_objects.end())
			{
				std::shared_ptr<tscrypto::ICryptoObject> tmp = foundObject->second;
				return tmp;
			}

			found_single = _singleton_classes.find(id);
		}
		if (found_single != _singleton_classes.end())
		{
			obj = found_single->second();
			if (!!obj)
			{
				registerAsSingleton = true;
			}
		}
	}
	if (obj == nullptr)
	{
		return nullptr;
	}

	std::shared_ptr<tscrypto::ICryptoObject> o = onService->FinishConstruction(obj);

	std::shared_ptr<tscrypto::IInitializableObject> initObj = std::dynamic_pointer_cast<tscrypto::IInitializableObject>(o);
	if (!!initObj)
	{
		if (!initObj->InitializeWithFullName(fullName))
			throw std::runtime_error(("Initialization failed: " + tsCryptoString(fullName)).c_str());
	}

	if (registerAsSingleton && !!o)
	{
		AutoWriterLock lock(*this);
		onService->AddSingletonObject(id, o);
	}
	return o;
}

std::shared_ptr<tscrypto::ICryptoObject> CryptoLocator_t::internalTryCreate(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName)
{
	tscrypto::ICryptoObject* obj = nullptr;
	tsCryptoString id(className);
	bool registerAsSingleton = false;

	id.ToUpper();
	{
		_ObjectMap::const_iterator foundObject;
		_ClassMap::const_iterator found_single;

		{
			AutoReaderLock lock(*this);
			foundObject = _singleton_objects.find(id);
			if (foundObject != _singleton_objects.end())
			{
				std::shared_ptr<tscrypto::ICryptoObject> tmp = foundObject->second;
				return tmp;
			}

			found_single = _singleton_classes.find(id);
		}
		if (found_single != _singleton_classes.end())
		{
			obj = found_single->second();
			if (!!obj)
			{
				registerAsSingleton = true;
			}
		}
		else
		{
			found_single = _classes.find(id);
			if (found_single != _classes.end())
			{
				obj = found_single->second();
			}
		}
	}

	std::shared_ptr<tscrypto::ICryptoObject> o = FinishConstruction(obj);

	std::shared_ptr<tscrypto::IInitializableObject> initObj = std::dynamic_pointer_cast<tscrypto::IInitializableObject>(o);
	if (!!initObj)
	{
		if (!initObj->InitializeWithFullName(fullName))
			throw std::runtime_error(("Initialization failed: " + tsCryptoString(fullName)).c_str());
	}

	if (registerAsSingleton && !!o)
	{
		AutoWriterLock lock(*this);
		_singleton_objects.insert(std::make_pair(id, o));
	}
	return o;
}
std::shared_ptr<tscrypto::ICryptoObject> CryptoLocator_t::internalTryCreate(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName, std::shared_ptr<tscrypto::ICryptoLocator> _onService)
{
	tscrypto::ICryptoObject* obj = nullptr;
	tsCryptoString id(className);
	bool registerAsSingleton = false;
	std::shared_ptr<tscrypto::ICryptoLocatorWriter> onService = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(_onService);

	if (!onService && !!_onService)
		return nullptr;

	id.ToUpper();
	{
		_ObjectMap::const_iterator foundObject;
		_ClassMap::const_iterator found_single;

		{
			AutoReaderLock lock(*this);
			foundObject = _singleton_objects.find(id);
			if (foundObject != _singleton_objects.end())
			{
				std::shared_ptr<tscrypto::ICryptoObject> tmp = foundObject->second;
				return tmp;
			}

			found_single = _singleton_classes.find(id);
		}
		if (found_single != _singleton_classes.end())
		{
			obj = found_single->second();
			if (!!obj)
			{
				registerAsSingleton = true;
			}
		}
		else
		{
			found_single = _classes.find(id);
			if (found_single != _classes.end())
			{
				obj = found_single->second();
			}
		}
	}

	std::shared_ptr<tscrypto::ICryptoObject> o = onService->FinishConstruction(obj);

	std::shared_ptr<tscrypto::IInitializableObject> initObj = std::dynamic_pointer_cast<tscrypto::IInitializableObject>(o);
	if (!!initObj)
	{
		if (!initObj->InitializeWithFullName(fullName))
			throw std::runtime_error(("Initialization failed: " + tsCryptoString(fullName)).c_str());
	}

	if (registerAsSingleton && !!o)
	{
		AutoWriterLock lock(*this);
		onService->AddSingletonObject(id, o);
	}
	return o;
}

bool CryptoLocator_t::internalCanCreate(const tscrypto::tsCryptoStringBase& className) const
{
	tsCryptoString id(className);

	id.ToUpper();
	AutoReaderLock lock(*this);
	_ClassMap::const_iterator found_single = _singleton_classes.find(id);
	if (found_single != _singleton_classes.end())
		return true;
	_ObjectMap::const_iterator foundObject = _singleton_objects.find(id);
	if (foundObject != _singleton_objects.end())
		return true;
	found_single = _classes.find(id);
	if (found_single != _classes.end())
		return true;
	return false;
}

tsCryptoString CryptoLocator_t::findObjectName(tscrypto::ICryptoObject* obj)
{
	auto it = std::find_if(_singleton_objects.begin(), _singleton_objects.end(), [obj](std::pair<const tsCryptoString, std::shared_ptr<tscrypto::ICryptoObject> >& item) { return item.second.get() == obj; });
	if (it != _singleton_objects.end())
		return it->first;
	return "";
}

void CryptoLocator_t::BuildObjectPath(tsCryptoStringBase& name)
{
	if (_creator.expired())
	{
		name = "/";
		return;
	}
	std::shared_ptr<tscrypto::ICryptoLocator> loc = _creator.lock();

	loc->BuildObjectPath(name);
	name.append(loc->findObjectName(this)).append("/");
}

std::shared_ptr<tscrypto::ICryptoLocator> tscrypto::CreateCryptoLocator()
{
	return CryptoLocator_t::Create();
}
