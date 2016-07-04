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

// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define VEILSMARTCARDDEF

#include "VEILSmartCard.h"

#include "tsWinscardSupport.h"
#define TLP_READER_NAME ("Tlp 224 Simulator")

extern HIDDEN tsDebugStream debug;
extern HIDDEN bool gTimeCommands;
extern HIDDEN bool gLogDecryptedInfo;

namespace tscrypto {
	template <typename baseType>
	class CryptoContainerWrapper : public ICryptoContainerWrapper<baseType>/*, public tscrypto::IObject*/
	{
	public:
		typedef typename std::vector<baseType> listType;
		typedef size_t size_type;
		typedef ptrdiff_t difference_type;
		typedef const baseType& const_reference;
		typedef baseType& reference;
		typedef baseType* pointer;
		typedef const baseType* const_pointer;

		typedef CryptoIterator<ICryptoContainerWrapper<baseType>> iterator;
		typedef const_CryptoIterator<ICryptoContainerWrapper<baseType>> const_iterator;
		typedef std::reverse_iterator<iterator> reverse_iterator;
		typedef std::reverse_iterator<const_iterator> const_reverse_iterator;

		CryptoContainerWrapper()
		{}
		//CryptoContainerWrapper(std::initializer_list<baseType> ilist) : _list(ilist)
		//{}
		CryptoContainerWrapper(std::vector<baseType>& list) : _list(list)
		{}
		CryptoContainerWrapper(const CryptoContainerWrapper& obj) : _list(obj.list)
		{}
		CryptoContainerWrapper(CryptoContainerWrapper&& obj) : _list(std::move(obj.list))
		{}

		CryptoContainerWrapper& operator=(const std::vector<baseType>& list)
		{
			_list = list;
			return *this;
		}
		CryptoContainerWrapper& operator=(std::vector<baseType>&& list)
		{
			_list = std::move(list);
			return *this;
		}
		virtual CryptoContainerWrapper& operator=(const CryptoContainerWrapper<baseType>& obj)
		{
			const CryptoContainerWrapper<baseType> *p = dynamic_cast<const CryptoContainerWrapper<baseType> *>(&obj);
			if (p != nullptr && p != this)
			{
				_list = p->_list;
			}
			return *this;
		}
		virtual CryptoContainerWrapper& operator=(CryptoContainerWrapper<baseType>&& obj)
		{
			CryptoContainerWrapper<baseType> *p = dynamic_cast<CryptoContainerWrapper<baseType> *>(&obj);
			if (p != nullptr && p != this)
			{
				_list = std::move(p->_list);
			}
			return *this;
		}
		virtual CryptoContainerWrapper& operator=(const ICryptoContainerWrapper<baseType>& obj) override
		{
			const CryptoContainerWrapper<baseType> *p = dynamic_cast<const CryptoContainerWrapper<baseType> *>(&obj);
			if (p != nullptr && p != this)
			{
				_list = p->_list;
			}
			return *this;
		}
		virtual CryptoContainerWrapper& operator=(ICryptoContainerWrapper<baseType>&& obj) override
		{
			CryptoContainerWrapper<baseType> *p = dynamic_cast<CryptoContainerWrapper<baseType> *>(&obj);
			if (p != nullptr && p != this)
			{
				_list = std::move(p->_list);
			}
			return *this;
		}
		//virtual CryptoContainerWrapper& operator=(std::initializer_list<baseType> ilist) override
		//{
		//	_list = ilist;
		//	return *this;
		//}

		virtual void assign(size_type count, const_reference value) override
		{
			_list.assign(count, value);
		}

		virtual void assign(const_iterator insertBegin, const_iterator insertEnd) override
		{
			_list.assign(insertBegin, insertEnd);
		}

		//virtual void assign(std::initializer_list<baseType> ilist) override
		//{
		//	_list.assign(ilist);
		//}

		virtual baseType& operator[](size_type index) override
		{
			return _list[index];
		}
		virtual const baseType& operator[](size_type index) const override
		{
			return _list[index];
		}
		virtual baseType& at(size_type index) override
		{
			return _list[index];
		}
		virtual const baseType& at(size_type index) const override
		{
			return _list[index];
		}

		virtual reference front() override
		{
			return _list.front();
		}
		virtual const_reference front() const override
		{
			return _list.front();
		}
		virtual reference back() override
		{
			return _list.back();
		}
		virtual const_reference back() const override
		{
			return _list.back();
		}
		virtual pointer data() override
		{
			return _list.data();
		}
		virtual const_pointer data() const override
		{
			return _list.data();
		}
		virtual iterator begin()  override
		{
			return iterator(std::dynamic_pointer_cast<ICryptoContainerWrapper<baseType>>(_me.lock()));
		}
		virtual const_iterator begin() const  override
		{
			return const_iterator(std::dynamic_pointer_cast<ICryptoContainerWrapper<baseType>>(_me.lock()));
		}
		virtual iterator end()  override
		{
			return iterator(std::dynamic_pointer_cast<ICryptoContainerWrapper<baseType>>(_me.lock()), _list.size());
		}
		virtual const_iterator end() const  override
		{
			return const_iterator(std::dynamic_pointer_cast<ICryptoContainerWrapper<baseType>>(_me.lock()), _list.size());
		}
		virtual const_iterator cbegin() const  override
		{
			return const_iterator(std::dynamic_pointer_cast<ICryptoContainerWrapper<baseType>>(_me.lock()));
		}
		virtual const_iterator cend() const  override
		{
			return const_iterator(std::dynamic_pointer_cast<ICryptoContainerWrapper<baseType>>(_me.lock()), _list.size());
		}
		virtual reverse_iterator rbegin()  override
		{
			return reverse_iterator(end());
		}
		virtual reverse_iterator rend()  override
		{
			return reverse_iterator(begin());
		}
		virtual const_reverse_iterator crbegin() const  override
		{
			return const_reverse_iterator(cend());
		}
		virtual const_reverse_iterator crend() const  override
		{
			return const_reverse_iterator(cbegin());
		}
		virtual bool empty() const override
		{
			return _list.empty();
		}
		virtual size_type size() const override
		{
			return _list.size();
		}
		virtual size_type max_size() const override
		{
			return _list.max_size();
		}
		virtual size_type capacity() const override
		{
			return _list.capacity();
		}
		virtual void reserve(size_type setTo) override
		{
			_list.reserve(setTo);
		}
		virtual void shrink_to_fit() override
		{
			_list.shrink_to_fit();
		}
		virtual void clear() override
		{
			_list.clear();
		}
		virtual iterator insert(const_iterator pos, const_reference data) override
		{
			typename listType::iterator it1 = _list.insert(_list.begin() + (pos - begin()), data);
			size_type idx = it1 - _list.begin();
			return iterator(std::dynamic_pointer_cast<ICryptoContainerWrapper<baseType>>(_me.lock()), idx);
		}
		virtual iterator insert(const_iterator pos, baseType&& data) override
		{
			typename listType::iterator it1 = _list.insert(_list.begin() + (pos - begin()), std::move(data));
			size_type idx = it1 - _list.begin();
			return iterator(std::dynamic_pointer_cast<ICryptoContainerWrapper<baseType>>(_me.lock()), idx);
		}
		//virtual iterator insert(const_iterator pos, size_type count, const_reference data) override
		//{
		//	typename listType::iterator it1 = _list.insert(_list.begin() + (pos - begin()), count, data);
		//	size_type idx = it1 - _list.begin();
		//	return iterator(std::dynamic_pointer_cast<ICryptoContainerWrapper<baseType>>(_me.lock()), idx);
		//}
		//virtual iterator insert(const_iterator pos, const_iterator insertBegin, const_iterator insertEnd) override
		//{
		//	size_type idx1 = (pos - cbegin());
		//	size_type idx2 = (insertBegin - cbegin());
		//	size_type idx3 = (insertEnd - cbegin());
		//	typename listType::iterator it1 = _list.insert(_list.begin() + idx1, _list.cbegin() + idx2, _list.cbegin() + idx3);
		//	size_type idx = it1 - _list.begin();
		//	return iterator(std::dynamic_pointer_cast<ICryptoContainerWrapper<baseType>>(_me.lock()), idx);
		//}
		//virtual iterator insert(const_iterator pos, std::initializer_list<baseType> ilist) override
		//{
		//	size_type idx1 = pos - cbegin();
		//	typename listType::iterator it1 = _list.insert(_list.begin() + idx1, ilist);
		//	size_type idx = it1 - _list.begin();
		//	return iterator(std::dynamic_pointer_cast<ICryptoContainerWrapper<baseType>>(_me.lock()), idx);
		//}
		virtual iterator erase(const_iterator it) override
		{
			auto newEnd = _list.erase(_list.begin() + (it - begin()));
			return iterator(std::dynamic_pointer_cast<ICryptoContainerWrapper<baseType>>(_me.lock()), newEnd - _list.begin());
		}
		virtual iterator erase(const_iterator first, const_iterator last) override
		{
			auto newEnd = _list.erase(_list.begin() + (first - begin()), _list.begin() + (last - begin()));
			return iterator(std::dynamic_pointer_cast<ICryptoContainerWrapper<baseType>>(_me.lock()), newEnd - _list.begin());
		}
		virtual void push_back(const_reference value) override
		{
			_list.push_back(value);
		}
		virtual void push_back(baseType&& value) override
		{
			_list.push_back(std::move(value));
		}
		virtual void pop_back() override
		{
			_list.pop_back();
		}
		virtual void resize(size_type newSize) override
		{
			_list.resize(newSize);
		}
		virtual void resize(size_type newSize, const_reference value) override
		{
			_list.resize(newSize, value);
		}
		virtual void swapIndices(size_type left, size_type right)  override
		{
			auto it = _list.begin();

			baseType tmp = *(it + left);
			*(it + left) = *(it + right);
			*(it + right) = tmp;

			//		std::swap(it + left, it + right);
		}
		virtual std::shared_ptr<ICryptoContainerWrapper<baseType>> cloneContainer() const override
		{
			std::shared_ptr<ICryptoContainerWrapper<baseType>> tmp = std::shared_ptr<ICryptoContainerWrapper<baseType> >(new CryptoContainerWrapper<baseType>());
			std::dynamic_pointer_cast<CryptoContainerWrapper<baseType>>(tmp)->setSharedPtr(tmp);
			((CryptoContainerWrapper<baseType>*)tmp.get())->_list = _list;
			return tmp;
		}
		void setSharedPtr(std::shared_ptr<ICryptoContainerWrapper<baseType>> ptr) { _me = ptr; }
	protected:
		std::weak_ptr<ICryptoContainerWrapper<baseType>> _me;

	private:
		std::vector<baseType> _list;
	};

	template <typename T>
	std::shared_ptr<ICryptoContainerWrapper<T> > CreateContainer()
	{
		std::shared_ptr<ICryptoContainerWrapper<T>> tmp = std::shared_ptr<ICryptoContainerWrapper<T> >(new CryptoContainerWrapper<T>());
		std::dynamic_pointer_cast<CryptoContainerWrapper<T>>(tmp)->setSharedPtr(tmp);
		return tmp;
	}
}


typedef struct ReaderName
{
	ReaderName() : found(false), status(0), id(0) {}
	ReaderName(const ReaderName& obj) : name(obj.name), found(obj.found), status(obj.status), atr(obj.atr), id(obj.id) {}
	ReaderName(ReaderName&& obj) : name(std::move(obj.name)), found(obj.found), status(obj.status), atr(std::move(obj.atr)), id(obj.id) { obj.id = 0; obj.status = 0; found = false; }
	ReaderName& operator=(const ReaderName& obj) { if (&obj != this) { name = obj.name; found = obj.found; status = obj.status; atr = obj.atr; id = obj.id; } return *this; }
	ReaderName& operator=(ReaderName&& obj) { if (&obj != this) { name = std::move(obj.name); found = obj.found; status = obj.status; atr = std::move(obj.atr); id = obj.id; obj.found = false; obj.status = 0; obj.id = 0; } return *this; }
	bool operator==(const ReaderName& obj) const { return id == obj.id && name == obj.name; }

	tscrypto::tsCryptoString name;
	bool found;
	uint32_t status;
	tscrypto::tsCryptoData atr;
	uint32_t id;
	bool matchAgainstId(uint32_t testId) { return id == testId; }
} ReaderName;

typedef struct Consumer
{
	Consumer() : id(0) {}
	Consumer(const Consumer& obj) : func(obj.func), id(obj.id) {}
	Consumer(Consumer&& obj) : func(std::move(obj.func)), id(obj.id) { obj.id = 0; }
	Consumer& operator=(const Consumer& obj) { if (&obj != this) { func = obj.func; id = obj.id; } return *this; }
	Consumer& operator=(Consumer&& obj) { if (&obj != this) { func = std::move(obj.func); id = obj.id; obj.id = 0; } return *this; }
	bool operator==(const Consumer& obj) const { return id == obj.id; }

	std::shared_ptr<TSWC_ChangeConsumer> func;
	uint32_t id;
	bool matchById(uint32_t testId) { return id == testId; }
} Consumer;

//#ifdef _MSC_VER
//#pragma warning(push)
//#pragma warning(disable:4231)
//VEILSMARTCARD_TEMPLATE_EXTERN template class VEILSMARTCARD_EXPORT tscrypto::ICryptoContainerWrapper<ReaderName>;
//VEILSMARTCARD_TEMPLATE_EXTERN template class VEILSMARTCARD_EXPORT std::shared_ptr<tscrypto::ICryptoContainerWrapper<ReaderName>>;
//VEILSMARTCARD_TEMPLATE_EXTERN template class VEILSMARTCARD_EXPORT tscrypto::ICryptoContainerWrapper<Consumer>;
//VEILSMARTCARD_TEMPLATE_EXTERN template class VEILSMARTCARD_EXPORT std::shared_ptr<tscrypto::ICryptoContainerWrapper<Consumer>>;
//#pragma warning(pop)
//#endif // _MSC_VER
//
typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<ReaderName>> ReaderNameList;
extern ReaderNameList CreateReaderNameList();
typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<Consumer>> ConsumerList;
extern ConsumerList CreateConsumerList();

class ICkmWinscardHandle
{
public:
	virtual INT_PTR GetHandle() const = 0;
};

#include "CkmWinscardEventImpl.h"

using namespace tscrypto;
