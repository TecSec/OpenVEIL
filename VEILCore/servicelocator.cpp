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
#include <algorithm>

using namespace tscrypto;

tsmod::IObject::~IObject()
{
#ifdef _DEBUG
	TSAUTOLOCKER lock(gAllocatedObjectsListLock);
	auto it = std::remove_if(gAllocatedObjects.begin(), gAllocatedObjects.end(), [this](std::weak_ptr<tsmod::IObject> obj) ->bool {
		if (obj.expired())
			return true;
		if (!obj.owner_before(_me) && !_me.owner_before(obj))
			return true;
		return false;
	});
	if (it != gAllocatedObjects.end())
		gAllocatedObjects.erase(it, gAllocatedObjects.end());
#endif
}
class ServiceLocator_t : public RWLock, public tsmod::IServiceLocator, public tsmod::IObject
{
public:
	static std::shared_ptr<tsmod::IServiceLocator> Create();
	ServiceLocator_t();
	virtual ~ServiceLocator_t();

	virtual bool AddSingletonClass(const tscrypto::tsCryptoStringBase& className, std::function<tsmod::IObject* ()> creator) override;
	virtual bool AddSingletonObject(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tsmod::IObject> object) override;
	virtual bool AddClass(const tscrypto::tsCryptoStringBase& className, std::function<tsmod::IObject* ()> creator) override;
	virtual bool CopyClass(const tscrypto::tsCryptoStringBase& className, IServiceLocator* copyTo) const override;
	virtual bool DeleteClass(const tscrypto::tsCryptoStringBase& className) override;

	virtual std::shared_ptr<tsmod::IObject> Create(const tscrypto::tsCryptoStringBase& className) override;
	virtual std::shared_ptr<tsmod::IObject> TryCreate(const tscrypto::tsCryptoStringBase& className) override;

	virtual tscrypto::tsCryptoStringList ObjectNames(bool onlyInstantiatedSingletons) const override;
	virtual tscrypto::tsCryptoStringList ObjectGroup(const tscrypto::tsCryptoStringBase& prefix, bool onlyInstantiatedSingletons) const override;

	virtual bool CanCreate(const tscrypto::tsCryptoStringBase& className) const override;
	virtual std::shared_ptr<tsmod::IServiceLocator> Creator() const override;
	virtual std::shared_ptr<tsmod::IObject> FinishConstruction(tsmod::IObject* obj) override;
	virtual std::shared_ptr<tsmod::IObject> Create(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tsmod::IServiceLocator> onService) override;
	virtual std::shared_ptr<tsmod::IObject> TryCreate(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tsmod::IServiceLocator> onService) override;

	// IMakeNewInstance
	virtual std::shared_ptr<tsmod::IObject> newInstance() const override;

	// Hierarchical visitor
	virtual void acceptVisitor(tsmod::IServiceLocatorVisitor *visitor) override;
	virtual void acceptVisitor(tsmod::IConstServiceLocatorVisitor *visitor) const override;

	virtual std::shared_ptr<tsmod::IServiceLocator> resolvePath(tscrypto::tsCryptoStringBase &path, bool createPaths) override;
	virtual std::shared_ptr<tsmod::IServiceLocator> resolvePath(tscrypto::tsCryptoStringBase &path) const override;
	virtual tscrypto::tsCryptoString findObjectName(tsmod::IObject* obj) override;
	virtual void BuildObjectPath(tscrypto::tsCryptoStringBase& name) override;

	virtual void CleanEmptyCollections(const tscrypto::tsCryptoStringBase& className) override
	{
		std::shared_ptr<tsmod::IObject> ptr = _me.lock();

		if (className == nullptr)
		{
			// First go through the children and clean up any and all empty containers
			size_t count = _singleton_objects.size();
			for (ptrdiff_t i = count - 1; i >= 0; i--)
			{
				auto it = _singleton_objects.begin();
				std::advance(it, i);
				std::shared_ptr<tsmod::IServiceLocator> loc = std::dynamic_pointer_cast<tsmod::IServiceLocator>(it->second);
				if (!!loc)
					loc->CleanEmptyCollections(nullptr);
			}
			if (_classes.size() == 0 && _singleton_classes.size() == 0 && _singleton_objects.size() == 0)
			{
				if (!_creator.expired())
				{
					tscrypto::tsCryptoString name = _creator.lock()->findObjectName(this);
					if (name.size() > 0)
					{
						_creator.lock()->DeleteClass(name.c_str());
					}
				}
			}
		}
		else
		{
			std::shared_ptr<tsmod::IServiceLocator> loc = std::dynamic_pointer_cast<tsmod::IServiceLocator>(internalTryCreateSingleton(className, className));

			if (!!loc)
			{
				loc->CleanEmptyCollections(nullptr);
			}
		}
	}
	virtual void clear() override
	{
		// First go through the children and clean up any and all empty containers
		for (std::pair<const tscrypto::tsCryptoString, std::shared_ptr<tsmod::IObject>>& obj : _singleton_objects) {
			std::shared_ptr<tsmod::IServiceLocator> loc = std::dynamic_pointer_cast<tsmod::IServiceLocator>(obj.second);
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
	virtual bool CopyClassDef(const tscrypto::tsCryptoStringBase&className, const tscrypto::tsCryptoStringBase& newName) override;
protected:
	typedef std::map<tscrypto::tsCryptoString, std::function<tsmod::IObject*()> > _ClassMap;
	typedef std::map<tscrypto::tsCryptoString, std::shared_ptr<tsmod::IObject>>	_ObjectMap;

	std::shared_ptr<tsmod::IObject> internalTryCreate(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName);
	std::shared_ptr<tsmod::IObject> internalTryCreateSingleton(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName);
	std::shared_ptr<tsmod::IObject> internalTryCreate(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName, std::shared_ptr<tsmod::IServiceLocator> onService);
	std::shared_ptr<tsmod::IObject> internalTryCreateSingleton(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName, std::shared_ptr<tsmod::IServiceLocator> onService);
	bool internalCanCreate(const tscrypto::tsCryptoStringBase& className) const;
	std::shared_ptr<tsmod::IServiceLocator> findRoot() const
	{
		std::shared_ptr<tsmod::IServiceLocator> item = std::dynamic_pointer_cast<tsmod::IServiceLocator>(_me.lock());

		while (!item->IsRoot())
		{
			std::shared_ptr<tsmod::IServiceLocator> prior(item);
			item = item->Creator();
			if (item == prior)
				break;
		}
		return item;
	}


	_ClassMap	_classes;
	_ClassMap	_singleton_classes;
	_ObjectMap  _singleton_objects;
	std::weak_ptr<tsmod::IServiceLocator> _creator;
	bool _isRoot;

};

std::shared_ptr<tsmod::IServiceLocator> ServiceLocator_t::Create()
{
	ServiceLocator_t* o = new ServiceLocator_t();
	std::shared_ptr<tsmod::IServiceLocator> obj = std::shared_ptr<tsmod::IServiceLocator>((tsmod::IServiceLocator*) o);
	std::shared_ptr<tsmod::IObject> io = std::dynamic_pointer_cast<tsmod::IObject>(obj);

	io->_serviceLocator = obj;
	io->_me = io;
	io->OnConstructionFinished();
	return obj;
}

ServiceLocator_t::ServiceLocator_t() : _isRoot(false)
{
}

ServiceLocator_t::~ServiceLocator_t()
{
	AutoWriterLock lock(*this);
	_singleton_objects.clear();
}

std::shared_ptr<tsmod::IObject> ServiceLocator_t::newInstance() const
{
	ServiceLocator_t* servLoc = new ServiceLocator_t();

	std::shared_ptr<tsmod::IObject> obj = std::shared_ptr<tsmod::IObject>(dynamic_cast<tsmod::IObject*>(servLoc));

	std::dynamic_pointer_cast<ServiceLocator_t>(obj)->_creator = ServiceLocator();
	obj->_serviceLocator = std::dynamic_pointer_cast<tsmod::IServiceLocator>(obj);
	obj->_me = obj;
	obj->OnConstructionFinished();
	return obj;
}

bool ServiceLocator_t::AddSingletonClass(const tscrypto::tsCryptoStringBase& className, std::function<tsmod::IObject* ()> creator)
{
	AutoWriterLock lock(*this);

	tscrypto::tsCryptoString id(className);
	std::shared_ptr<tsmod::IServiceLocator> loc = resolvePath(id, true);

	if (!loc)
	{
		throw std::runtime_error("Invalid service locator path requested.");
	}

	if (loc.get() != dynamic_cast<tsmod::IServiceLocator*>(this))
		return loc->AddSingletonClass(id.c_str(), creator);

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

bool ServiceLocator_t::AddSingletonObject(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tsmod::IObject> object)
{
	AutoWriterLock lock(*this);
	tscrypto::tsCryptoString id(className);
	std::shared_ptr<tsmod::IServiceLocator> loc = resolvePath(id, true);

	if (!loc)
	{
		throw std::runtime_error("Invalid service locator path requested.");
	}

	if (loc.get() != dynamic_cast<tsmod::IServiceLocator*>(this))
		return loc->AddSingletonObject(id.c_str(), object);

	_ObjectMap::iterator foundObject = _singleton_objects.find(id);
	if (foundObject != _singleton_objects.end())
	{
		std::shared_ptr<tsmod::IAggregatableObject> child = std::dynamic_pointer_cast<tsmod::IAggregatableObject>(foundObject->second);
		std::shared_ptr<tsmod::IAggregatableObject> parent = std::dynamic_pointer_cast<tsmod::IAggregatableObject>(object);

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

bool ServiceLocator_t::AddClass(const tscrypto::tsCryptoStringBase& className, std::function<tsmod::IObject* ()> creator)
{
	tscrypto::tsCryptoString id(className);
	std::shared_ptr<tsmod::IServiceLocator> loc = resolvePath(id, true);

	if (!loc)
	{
		throw std::runtime_error("Invalid service locator path requested.");
	}

	if (loc.get() != dynamic_cast<tsmod::IServiceLocator*>(this))
		return loc->AddClass(id.c_str(), creator);

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

bool ServiceLocator_t::CopyClassDef(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& newName)
{
	tscrypto::tsCryptoString id(className);

	std::shared_ptr<tsmod::IServiceLocator> loc = resolvePath(id);

	if (!loc)
	{
		throw std::runtime_error("Invalid service locator path requested.");
	}

	if (loc.get() != dynamic_cast<const tsmod::IServiceLocator*>(this))
		return loc->CopyClassDef(id.c_str(), newName);

	AutoReaderLock lock(*this);
	_ClassMap::const_iterator found_single = _singleton_classes.find(id);
	if (found_single != _singleton_classes.end())
	{
		bool retVal = AddSingletonClass(newName, found_single->second);
		return retVal;
	}
	found_single = _classes.find(id);
	if (found_single != _classes.end())
	{
		bool retVal = AddClass(newName, found_single->second);
		return retVal;
	}
	return false;
}
bool ServiceLocator_t::CopyClass(const tscrypto::tsCryptoStringBase& className, IServiceLocator* copyTo) const
{
	tscrypto::tsCryptoString id(className);

	std::shared_ptr<tsmod::IServiceLocator> loc = resolvePath(id);

	if (!loc)
	{
		throw std::runtime_error("Invalid service locator path requested.");
	}

	if (loc.get() != dynamic_cast<const tsmod::IServiceLocator*>(this))
		return loc->CopyClass(id.c_str(), copyTo);

	AutoReaderLock lock(*this);
	_ClassMap::const_iterator found_single = _singleton_classes.find(id);
	if (found_single != _singleton_classes.end())
	{
		bool retVal = copyTo->AddSingletonClass(className, found_single->second);
		return retVal;
	}
	found_single = _classes.find(id);
	if (found_single != _classes.end())
	{
		bool retVal = copyTo->AddClass(className, found_single->second);
		return retVal;
	}
	return false;
}

bool ServiceLocator_t::DeleteClass(const tscrypto::tsCryptoStringBase& className)
{
	tscrypto::tsCryptoString id(className);
	bool retVal = false;

	std::shared_ptr<tsmod::IServiceLocator> loc = resolvePath(id, false);

	if (!loc)
	{
		return true;
	}

	if (loc.get() != dynamic_cast<tsmod::IServiceLocator*>(this))
		return loc->DeleteClass(id.c_str());

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
		std::shared_ptr<tsmod::IAggregatableObject> parent = std::dynamic_pointer_cast<tsmod::IAggregatableObject>(foundObject->second);

		if (!!parent && !!parent->getContained())
		{
			std::shared_ptr<tsmod::IAggregatableObject> child = std::dynamic_pointer_cast<tsmod::IAggregatableObject>(foundObject->second);
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

std::shared_ptr<tsmod::IObject> ServiceLocator_t::Create(const tscrypto::tsCryptoStringBase& className)
{
	std::shared_ptr<tsmod::IObject> obj = TryCreate(className);

	if (!obj)
		throw std::runtime_error(("invalid id: " + tscrypto::tsCryptoString(className)).c_str());
	return obj;
}

std::shared_ptr<tsmod::IObject> ServiceLocator_t::Create(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tsmod::IServiceLocator> onService)
{
	std::shared_ptr<tsmod::IObject> obj = TryCreate(className, onService);

	if (!obj)
		throw std::runtime_error(("invalid id: " + tscrypto::tsCryptoString(className)).c_str());
	return obj;
}

std::shared_ptr<tsmod::IServiceLocator> ServiceLocator_t::resolvePath(tscrypto::tsCryptoStringBase &path, bool createPaths)
{
	tscrypto::tsCryptoString id(path);

	id.ToUpper();
	if (id.find('/') != tsCryptoString::npos && id.find('/') < id.find_first_of("[{:;!@#$%^&*(<>?", 0))
	{
		std::shared_ptr<tsmod::IServiceLocator> loc = std::dynamic_pointer_cast<tsmod::IServiceLocator>(_me.lock());

		id.Replace("//", "/");
		if (id[0] == '/')
		{
			loc = findRoot();
			id.erase(0, 1);
		}

		// Resolve paths first
		tscrypto::tsCryptoStringList paths = id.split("/", 5000, true);
		size_t count = paths->size();

		for (size_t i = 0; i < count - 1; i++)
		{
			if (paths->at(i) == ".")
			{
				// Current service locator
				id.erase(0, 2);
			}
			else if (paths->at(i) == "..")
			{
				// Parent service locator
				if (!loc->Creator())
					return nullptr;
				loc = loc->Creator();
				id.erase(0, 3);
			}
			else if (paths->at(i).find_first_of("[{:;!@#$%^&*(<>?", 0) != tsCryptoString::npos)
			{
				path = id;
				return loc;
			}
			else
			{
				std::shared_ptr<tsmod::IServiceLocator> newLoc;

				newLoc = std::dynamic_pointer_cast<tsmod::IServiceLocator>(((ServiceLocator_t*)loc.get())->internalTryCreateSingleton(paths->at(i).c_str(), paths->at(i).c_str()));
				if (!newLoc && createPaths)
				{
					newLoc = std::dynamic_pointer_cast<tsmod::IServiceLocator>(loc->newInstance());
					loc->AddSingletonObject(paths->at(i).c_str(), std::dynamic_pointer_cast<tsmod::IObject>(newLoc));
				}
				if (!newLoc)
					return nullptr;
				loc = newLoc;
				id.erase(0, paths->at(i).size() + 1);
			}
		}
		path = id;
		return loc;
	}
	path = id;
	return std::dynamic_pointer_cast<tsmod::IServiceLocator>(_me.lock());
}
std::shared_ptr<tsmod::IServiceLocator> ServiceLocator_t::resolvePath(tscrypto::tsCryptoStringBase &path) const
{
	tscrypto::tsCryptoString id(path);

	id.ToUpper();
	if (id.find('/') != tsCryptoString::npos && id.find('/') < id.find_first_of("[{:;!@#$%^&*(<>?", 0))
	{
		std::shared_ptr<tsmod::IServiceLocator> loc = std::dynamic_pointer_cast<tsmod::IServiceLocator>(_me.lock());

		id.Replace("//", "/");
		if (id[0] == '/')
		{
			loc = findRoot();
			id.erase(0, 1);
		}

		// Resolve paths first
		tscrypto::tsCryptoStringList paths = id.split("/", 5000, true);
		size_t count = paths->size();

		for (size_t i = 0; i < count - 1; i++)
		{
			if (paths->at(i) == ".")
			{
				// Current service locator
				id.erase(0, 2);
			}
			else if (paths->at(i) == "..")
			{
				// Parent service locator
				if (!loc->Creator())
					return nullptr;
				loc = loc->Creator();
				id.erase(0, 3);
			}
			else if (paths->at(i).find_first_of("[{:;!@#$%^&*(<>?", 0) != tsCryptoString::npos)
			{
				path = id;
				return loc;
			}
			else
			{
				std::shared_ptr<tsmod::IServiceLocator> newLoc;

				newLoc = std::dynamic_pointer_cast<tsmod::IServiceLocator>(((ServiceLocator_t*)loc.get())->internalTryCreateSingleton(paths->at(i).c_str(), paths->at(i).c_str()));
				if (!newLoc)
					return nullptr;
				loc = newLoc;
				id.erase(0, paths->at(i).size() + 1);
			}
		}
		path = id;
		return loc;
	}
	path = id;
	return std::dynamic_pointer_cast<tsmod::IServiceLocator>(_me.lock());
}

std::shared_ptr<tsmod::IObject> ServiceLocator_t::TryCreate(const tscrypto::tsCryptoStringBase& className)
{
	tscrypto::tsCryptoString id(className);
	std::shared_ptr<tsmod::IObject> obj;
	std::shared_ptr<tsmod::IServiceLocator> loc = resolvePath(id, false);

	if (!loc)
	{
		//throw std::runtime_error("Invalid service locator path requested.  Parent does not exist.");
		return nullptr;
	}

	if (loc.get() != dynamic_cast<tsmod::IServiceLocator*>(this))
		return loc->TryCreate(id.c_str());

	tscrypto::tsCryptoString fullName(id);

	// Remove parameters
	tscrypto::tsCryptoStringList parts = id.split("[{:;!@#$%^&*(<>?", 2);
	id = parts->at(0);

	// Now find the object
	while (id.size() > 0)
	{
		if (!(obj = internalTryCreate(id.c_str(), fullName.c_str())))
		{
			ptrdiff_t index = id.rfind('-');

			if (index < 0)
				return nullptr;
			id.resize(index);
		}
		else
			return obj;
	}
	return nullptr;
}
std::shared_ptr<tsmod::IObject> ServiceLocator_t::TryCreate(const tscrypto::tsCryptoStringBase& className, std::shared_ptr<tsmod::IServiceLocator> onService)
{
	tscrypto::tsCryptoString id(className);
	std::shared_ptr<tsmod::IObject> obj;
	std::shared_ptr<tsmod::IServiceLocator> loc = resolvePath(id, false);

	if (!loc)
	{
		//throw std::runtime_error("Invalid service locator path requested.  Parent does not exist.");
		return nullptr;
	}

	if (loc.get() != dynamic_cast<tsmod::IServiceLocator*>(this))
		return loc->TryCreate(id.c_str(), onService);

	tscrypto::tsCryptoString fullName(id);

	// Remove parameters
	tscrypto::tsCryptoStringList parts = id.split("[{:;!@#$%^&*(<>?", 2);
	id = parts->at(0);

	// Now find the object
	while (id.size() > 0)
	{
		if (!(obj = internalTryCreate(id.c_str(), fullName.c_str(), onService)))
		{
			ptrdiff_t index = id.rfind('-');

			if (index < 0)
				return nullptr;
			id.resize(index);
		}
		else
			return obj;
	}
	return nullptr;
}

tscrypto::tsCryptoStringList ServiceLocator_t::ObjectNames(bool onlyInstantiatedSingletons) const
{
	tscrypto::tsCryptoStringList tmp = CreateTsAsciiList();

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

tscrypto::tsCryptoStringList ServiceLocator_t::ObjectGroup(const tscrypto::tsCryptoStringBase& prefix, bool onlyInstantiatedSingletons) const
{
	tscrypto::tsCryptoStringList tmp = CreateTsAsciiList();
	tscrypto::tsCryptoString id(prefix);
	std::shared_ptr<tsmod::IServiceLocator> loc = resolvePath(id);
	tscrypto::tsCryptoString path;

	if (!loc)
	{
		throw std::runtime_error("Invalid service locator path requested.");
	}

	if (loc.get() != dynamic_cast<const tsmod::IServiceLocator*>(this))
		return loc->ObjectGroup(id.c_str(), onlyInstantiatedSingletons);

	loc->BuildObjectPath(path);

	AutoReaderLock lock(*this);
	for (auto iter = _singleton_objects.begin(); iter != _singleton_objects.end(); iter++)
	{
		if (strncmp(id.c_str(), iter->first.c_str(), id.size()) == 0)
			tmp->push_back(path + iter->first);
	}
	if (!onlyInstantiatedSingletons)
	{
		for (auto iter = _singleton_classes.begin(); iter != _singleton_classes.end(); iter++)
		{
			if (strncmp(id.c_str(), iter->first.c_str(), id.size()) == 0)
				tmp->push_back(path + iter->first);
		}
		for (auto iter = _classes.begin(); iter != _classes.end(); iter++)
		{
			if (strncmp(id.c_str(), iter->first.c_str(), id.size()) == 0)
				tmp->push_back(path + iter->first);
		}
	}
	return tmp;
}

bool ServiceLocator_t::CanCreate(const tscrypto::tsCryptoStringBase&className) const
{
	tscrypto::tsCryptoString id(className);

	std::shared_ptr<tsmod::IServiceLocator> loc = resolvePath(id);

	if (!loc)
	{
		return false;
	}

	if (loc.get() != dynamic_cast<const tsmod::IServiceLocator*>(this))
		return loc->CanCreate(id.c_str());

	// Remove parameters
	tscrypto::tsCryptoStringList parts = id.split("[{:;!@#$%^&*(<>?", 2);
	id = parts->at(0);

	// Now find the object
	while (id.size() > 0)
	{
		if (!internalCanCreate(id.c_str()))
		{
			ptrdiff_t index = id.rfind('-');

			if (index < 0)
				return false;
			id.resize(index);
		}
		else
			return true;
	}
	return false;
}

std::shared_ptr<tsmod::IServiceLocator> ServiceLocator_t::Creator() const
{
	if (_creator.use_count() == 0)
		return nullptr;
	return _creator.lock();
}

std::shared_ptr<tsmod::IObject> ServiceLocator_t::FinishConstruction(tsmod::IObject* obj)
{
	if (!obj)
		return nullptr;

	std::shared_ptr<tsmod::IObject> o(obj);

	o->_serviceLocator = ServiceLocator();
	o->_me = o;
	o->OnConstructionFinished();
#ifdef _DEBUG
	TSAUTOLOCKER lock(gAllocatedObjectsListLock);
	gAllocatedObjects.push_back(o->_me);
#endif
	return o;
}

void ServiceLocator_t::acceptVisitor(tsmod::IServiceLocatorVisitor *visitor)
{
	std::map<tscrypto::tsCryptoString, bool> tmp;
	std::shared_ptr<tsmod::IServiceLocator> Me = ServiceLocator();

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
		  //std::shared_ptr<tsmod::IObject> obj = iter->second->_me.lock();
		  //if (!!obj && !!std::dynamic_pointer_cast<tsmod::IServiceLocator>(obj))
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
		visitor->visit(value.first.c_str(), value.second, false);
	}
	for (auto iter : _singleton_objects)
	{
		if (!!iter.second)
		{
			std::shared_ptr<tsmod::IObject> obj = iter.second->_me.lock();
			if (!!obj)
			{
				std::shared_ptr<tsmod::IServiceLocator> subLoc = std::dynamic_pointer_cast<tsmod::IServiceLocator>(obj);
				if (!subLoc)
				{
					visitor->visit(iter.first.c_str(), true, true);
				}
			}
		}
	}
	for (auto iter : _singleton_objects)
	{
		std::shared_ptr<tsmod::IObject> obj = iter.second->_me.lock();
		if (!!obj)
		{
			std::shared_ptr<tsmod::IServiceLocator> subLoc = std::dynamic_pointer_cast<tsmod::IServiceLocator>(obj);
			if (!!subLoc)
			{
				if (visitor->visitEnter(iter.first.c_str(), subLoc.get()))
				{
					subLoc->acceptVisitor(visitor);
				}
				visitor->visitLeave(iter.first.c_str(), subLoc.get());
			}
		}
	}
}

void ServiceLocator_t::acceptVisitor(tsmod::IConstServiceLocatorVisitor *visitor) const
{
	std::map<tscrypto::tsCryptoString, bool> tmp;
	std::shared_ptr<tsmod::IServiceLocator> Me = ServiceLocator();

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
		  //std::shared_ptr<tsmod::IObject> obj = iter->second->_me.lock();
		  //if (!!obj && !!std::dynamic_pointer_cast<tsmod::IServiceLocator>(obj))
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
		visitor->visit(value.first.c_str(), value.second, false);
	}
	for (auto iter : _singleton_objects)
	{
		std::shared_ptr<tsmod::IObject> obj = iter.second->_me.lock();
		if (!!obj)
		{
			std::shared_ptr<tsmod::IServiceLocator> subLoc = std::dynamic_pointer_cast<tsmod::IServiceLocator>(obj);
			if (!subLoc)
			{
				visitor->visit(iter.first.c_str(), true, true);
			}
		}
	}
	for (auto iter = _singleton_objects.begin(); iter != _singleton_objects.end(); iter++)
	{
		std::shared_ptr<tsmod::IObject> obj = iter->second->_me.lock();
		if (!!obj)
		{
			std::shared_ptr<tsmod::IServiceLocator> subLoc = std::dynamic_pointer_cast<tsmod::IServiceLocator>(obj);
			if (!!subLoc)
			{
				if (visitor->visitEnter(iter->first.c_str(), subLoc.get()))
				{
					subLoc->acceptVisitor(visitor);
				}
				visitor->visitLeave(iter->first.c_str(), subLoc.get());
			}
		}
	}
}

std::shared_ptr<tsmod::IObject> ServiceLocator_t::internalTryCreateSingleton(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName)
{
	tsmod::IObject* obj = nullptr;
	tscrypto::tsCryptoString id(className);
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
				std::shared_ptr<tsmod::IObject> tmp = foundObject->second;
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

	std::shared_ptr<tsmod::IObject> o = FinishConstruction(obj);

	std::shared_ptr<tsmod::IInitializableObject> initObj = std::dynamic_pointer_cast<tsmod::IInitializableObject>(o);
	if (!!initObj)
	{
		if (!initObj->InitializeWithFullName(fullName))
			throw std::runtime_error(("Initialization failed: " + tscrypto::tsCryptoString(fullName)).c_str());
	}

	if (registerAsSingleton && !!o)
	{
		AutoWriterLock lock(*this);
		_singleton_objects.insert(std::make_pair(id, o));
	}
	return o;
}
std::shared_ptr<tsmod::IObject> ServiceLocator_t::internalTryCreateSingleton(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName, std::shared_ptr<tsmod::IServiceLocator> onService)
{
	tsmod::IObject* obj = nullptr;
	tscrypto::tsCryptoString id(className);
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
				std::shared_ptr<tsmod::IObject> tmp = foundObject->second;
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

	std::shared_ptr<tsmod::IObject> o = onService->FinishConstruction(obj);

	std::shared_ptr<tsmod::IInitializableObject> initObj = std::dynamic_pointer_cast<tsmod::IInitializableObject>(o);
	if (!!initObj)
	{
		if (!initObj->InitializeWithFullName(fullName))
			throw std::runtime_error(("Initialization failed: " + tscrypto::tsCryptoString(fullName)).c_str());
	}

	if (registerAsSingleton && !!o)
	{
		AutoWriterLock lock(*this);
		onService->AddSingletonObject(id.c_str(), o);
	}
	return o;
}

std::shared_ptr<tsmod::IObject> ServiceLocator_t::internalTryCreate(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName)
{
	tsmod::IObject* obj = nullptr;
	tscrypto::tsCryptoString id(className);
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
				std::shared_ptr<tsmod::IObject> tmp = foundObject->second;
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

	std::shared_ptr<tsmod::IObject> o = FinishConstruction(obj);

	std::shared_ptr<tsmod::IInitializableObject> initObj = std::dynamic_pointer_cast<tsmod::IInitializableObject>(o);
	if (!!initObj)
	{
		if (!initObj->InitializeWithFullName(fullName))
			throw std::runtime_error(("Initialization failed: " + tscrypto::tsCryptoString(fullName)).c_str());
	}

	if (registerAsSingleton && !!o)
	{
		AutoWriterLock lock(*this);
		_singleton_objects.insert(std::make_pair(id, o));
	}
	return o;
}
std::shared_ptr<tsmod::IObject> ServiceLocator_t::internalTryCreate(const tscrypto::tsCryptoStringBase& className, const tscrypto::tsCryptoStringBase& fullName, std::shared_ptr<tsmod::IServiceLocator> onService)
{
	tsmod::IObject* obj = nullptr;
	tscrypto::tsCryptoString id(className);
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
				std::shared_ptr<tsmod::IObject> tmp = foundObject->second;
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

	std::shared_ptr<tsmod::IObject> o = onService->FinishConstruction(obj);

	std::shared_ptr<tsmod::IInitializableObject> initObj = std::dynamic_pointer_cast<tsmod::IInitializableObject>(o);
	if (!!initObj)
	{
		if (!initObj->InitializeWithFullName(fullName))
			throw std::runtime_error(("Initialization failed: " + tscrypto::tsCryptoString(fullName)).c_str());
	}

	if (registerAsSingleton && !!o)
	{
		AutoWriterLock lock(*this);
		onService->AddSingletonObject(id.c_str(), o);
	}
	return o;
}

bool ServiceLocator_t::internalCanCreate(const tscrypto::tsCryptoStringBase& className) const
{
	tscrypto::tsCryptoString id(className);

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

tscrypto::tsCryptoString ServiceLocator_t::findObjectName(tsmod::IObject* obj)
{
	auto it = std::find_if(_singleton_objects.begin(), _singleton_objects.end(), [obj](std::pair<const tscrypto::tsCryptoString, std::shared_ptr<tsmod::IObject> >& item) { return item.second.get() == obj; });
	if (it != _singleton_objects.end())
		return it->first;
	return "";
}

void ServiceLocator_t::BuildObjectPath(tscrypto::tsCryptoStringBase& name)
{
	if (_creator.expired())
	{
		name = "/";
		return;
	}
	std::shared_ptr<tsmod::IServiceLocator> loc = _creator.lock();

	loc->BuildObjectPath(name);
	name.append(loc->findObjectName(this)).append("/");
}

std::shared_ptr<tsmod::IServiceLocator> tsmod::CreateServiceLocator()
{
	return ServiceLocator_t::Create();
}
