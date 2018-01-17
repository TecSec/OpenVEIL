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

#ifndef __STANDARDLAYOUTLIST_H__
#define __STANDARDLAYOUTLIST_H__

#pragma once

namespace tscrypto {

	template <class DATA>
	class standardLayoutListNode
	{
	public:
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

		standardLayoutListNode() : next(nullptr)
		{
			static_assert(std::is_standard_layout<standardLayoutListNode<DATA>>::value, "standardLayoutListNode<DATA> is not a standard layout type.");
		}

		explicit standardLayoutListNode(const DATA &aData) : next(nullptr), Data(aData)
		{
		}

		standardLayoutListNode(DATA&& aData) : next(nullptr), Data(std::move(aData))
		{
		}
		standardLayoutListNode(const standardLayoutListNode<DATA> & object) : next(nullptr), Data(object.Data)
		{
		}
		standardLayoutListNode(standardLayoutListNode<DATA>&& object) : next(object.next), Data(std::move(object.Data))
		{
			object.next = nullptr;
		}
		~standardLayoutListNode()
		{
		}

		standardLayoutListNode<DATA> &operator= (const standardLayoutListNode<DATA> & object)
		{
			if (this != &object)
			{
				Data = object.Data;
			}
			return *this;
		}
		standardLayoutListNode<DATA> &operator= (standardLayoutListNode<DATA>&& object)
		{
			if (this != &object)
			{
				next = object.next;
				object.next = nullptr;
				Data = std::move(object.Data);
			}
			return *this;
		}

		standardLayoutListNode<DATA> *getNext(void) const
		{
			return next;
		}
		void setNext(standardLayoutListNode<DATA> *aNext)
		{
			next = aNext;
		}

		const DATA& getData(void) const
		{
			return Data;
		}
		DATA& getData(void)
		{
			return Data;
		}
		void setData(const DATA& aData)
		{
			Data = aData;
		}
		void setData(DATA&& aData)
		{
			Data = std::move(aData);
		}

	protected:
		standardLayoutListNode<DATA> *next;  // Pointer to next node
		DATA Data;							 // Pointer to the object contained in node.
	};

	template <class DATA, class NodeType = standardLayoutListNode<DATA>>
	class standardLayoutList
	{
	protected:
		typedef NodeType NODETYPE;
		mutable tscrypto::AutoCriticalSection m_lock;
		size_t m_entries;
		NODETYPE *StartOfList;

	public:
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

		standardLayoutList() : m_entries(0), StartOfList(nullptr)
		{
			static_assert(std::is_standard_layout<tscrypto::AutoCriticalSection>::value, "tscrypto::AutoCriticalSection is not a standard layout type.");
			static_assert(std::is_standard_layout<standardLayoutListNode<DATA>>::value, "standardLayoutList<DATA> is not a standard layout type.");
		}
		standardLayoutList(const standardLayoutList<DATA, NodeType> & object) : m_entries(0), StartOfList(nullptr)
		{
			TSAUTOLOCKER locker(object.m_lock);
			NODETYPE* src = object.StartOfList;
			while (src != nullptr)
			{

				DATA& d = src->getData();
				push_back(d); // force copy
				src = src->getNext();
			}
		}
		standardLayoutList(standardLayoutList<DATA, NodeType>&& object) : m_entries(object.m_entries), StartOfList(object.StartOfList)
		{
			object.m_entries = 0;
			object.StartOfList = nullptr;
		}
		standardLayoutList<DATA, NodeType> &operator= (const standardLayoutList<DATA, NodeType> &object)
		{
			if (&object != this)
			{
				TSAUTOLOCKER locker(m_lock);
				TSAUTOLOCKER locker2(object.m_lock);

				_clear();
				NODETYPE* src = object.StartOfList;
				while (src != nullptr)
				{
					DATA& d = src->getData();
					push_back(d); // force copy
					src = src->getNext();
				}
			}
			return *this;
		}
		standardLayoutList<DATA, NodeType> &operator= (standardLayoutList<DATA, NodeType>&& object)
		{
			if (&object != this)
			{
				TSAUTOLOCKER locker(object.m_lock);

				m_entries = object.m_entries;
				StartOfList = object.StartOfList;
				object.m_entries = 0;
				object.StartOfList = nullptr;
			}
			return *this;
		}

		~standardLayoutList()
		{
			TSAUTOLOCKER locker(m_lock);

			_clear();
		}

		void push_back(const DATA& aData)
		{
			NODETYPE *NodeToAdd;
			NODETYPE *CurrentNode;

			TSAUTOLOCKER locker(m_lock);

			CurrentNode = StartOfList;
			while (CurrentNode != 0 && CurrentNode->getNext() != 0)
			{
				CurrentNode = CurrentNode->getNext();
			}
			NodeToAdd = new NODETYPE(aData);
			if (NodeToAdd == nullptr)
				throw std::runtime_error("Out of memory");
			if (CurrentNode == 0)
			{
				StartOfList = NodeToAdd;
			}
			else
			{
				CurrentNode->setNext(NodeToAdd);
			}
			m_entries++;
		}
		void push_back(DATA&& aData)
		{
			NODETYPE *NodeToAdd;
			NODETYPE *CurrentNode;

			TSAUTOLOCKER locker(m_lock);

			CurrentNode = StartOfList;
			while (CurrentNode != 0 && CurrentNode->getNext() != 0)
			{
				CurrentNode = CurrentNode->getNext();
			}
			NodeToAdd = new NODETYPE(std::move(aData));
			if (NodeToAdd == nullptr)
				throw std::runtime_error("Out of memory");
			if (CurrentNode == 0)
			{
				StartOfList = NodeToAdd;
			}
			else
			{
				CurrentNode->setNext(NodeToAdd);
			}
			m_entries++;
		}
		bool remove(size_t index)
		{
			if (index >= m_entries)
				return false;

			TSAUTOLOCKER locker(m_lock);

			NODETYPE *CurrentNode = StartOfList;
			NODETYPE *PriorNode = nullptr;
			size_t idx = 0;

			while (CurrentNode != nullptr)
			{
				if (idx == index)
				{
					if (PriorNode == 0)
					{
						StartOfList = CurrentNode->getNext();
					}
					else
					{
						PriorNode->setNext(CurrentNode->getNext());
					}
					delete CurrentNode;
					m_entries--;

					return true;
				}
				idx++;
				PriorNode = CurrentNode;
				CurrentNode = CurrentNode->getNext();
			}

			return false;
		}
		void clear()
		{
			TSAUTOLOCKER locker(m_lock);
			_clear();
		}
		const DATA& at(size_t idx) const
		{
			TSAUTOLOCKER locker(m_lock);

			const NODETYPE *node = NodeAt(idx);
			if (node == nullptr)
				throw std::out_of_range("Index");
			return node->getData();
		}
		DATA& at(size_t idx)
		{
			TSAUTOLOCKER locker(m_lock);

			NODETYPE *node = NodeAt(idx);
			if (node == nullptr)
				throw std::out_of_range("Index");
			return node->getData();
		}
		const DATA& operator[] (size_t idx) const
		{
			return at(idx);
		}
		DATA& operator[] (size_t idx)
		{
			return at(idx);
		}
		size_t size() const
		{
			return m_entries;
		}

		bool empty() const
		{
			return StartOfList == nullptr || m_entries == 0;
		}
		bool swap(int left, int right)
		{
			TSAUTOLOCKER locker(m_lock);

			NODETYPE* leftNode = NodeAt(left);
			NODETYPE* rightNode = NodeAt(right);

			if (leftNode == nullptr || rightNode == nullptr)
				return false;

			DATA d = std::move(leftNode->getData());
			leftNode->getData() = std::move(rightNode->getData());
			rightNode->getData() = std::move(d);
			//swap(leftNode->getData(), rightNode->getData());
			return true;
		}

	protected:
		//NodeType *priorNode(DATA *node)
		//{
		//	NODETYPE *CurrentNode;
		//
		//	CurrentNode = StartOfList;
		//	while (CurrentNode != NULL && CurrentNode->getNext() != NULL && CurrentNode->getNext()->getData() != node)
		//	{
		//		CurrentNode = CurrentNode->getNext();
		//	}
		//	return CurrentNode;
		//}
		//const NodeType *priorNode(DATA *node) const
		//{
		//	const NODETYPE *CurrentNode;
		//
		//	CurrentNode = StartOfList;
		//	while (CurrentNode != NULL && CurrentNode->getNext() != NULL && CurrentNode->getNext()->getData() != node)
		//	{
		//		CurrentNode = CurrentNode->getNext();
		//	}
		//	return CurrentNode;
		//}
		//NodeType *getLastNode()
		//{
		//	NODETYPE *CurrentNode;
		//
		//	CurrentNode = StartOfList;
		//	while (CurrentNode != NULL && CurrentNode->getNext() != NULL)
		//	{
		//		CurrentNode = CurrentNode->getNext();
		//	}
		//	return CurrentNode;
		//}
		//const NodeType *getLastNode() const
		//{
		//	const NODETYPE *CurrentNode;
		//
		//	CurrentNode = StartOfList;
		//	while (CurrentNode != NULL && CurrentNode->getNext() != NULL)
		//	{
		//		CurrentNode = CurrentNode->getNext();
		//	}
		//	return CurrentNode;
		//}
		const NODETYPE *NodeAt(size_t idx) const
		{
			const NODETYPE *CurrentNode;
			size_t _entries = 0;

			if (idx >= size())
			{
				return nullptr;
			}

			CurrentNode = StartOfList;
			while (CurrentNode != 0)
			{
				if (idx == _entries)
				{
					return CurrentNode;
				}
				_entries++;
				CurrentNode = CurrentNode->getNext();
			}
			return nullptr;
		}
		NODETYPE *NodeAt(size_t idx)
		{
			NODETYPE *CurrentNode;
			size_t _entries = 0;

			if (idx >= size())
			{
				return nullptr;
			}

			CurrentNode = StartOfList;
			while (CurrentNode != 0)
			{
				if (idx == _entries)
				{
					return CurrentNode;
				}
				_entries++;
				CurrentNode = CurrentNode->getNext();
			}
			return nullptr;
		}
		void _clear()
		{
			NODETYPE *CurrentNode;

			TSAUTOLOCKER locker(m_lock);

			while (StartOfList != nullptr)
			{
				CurrentNode = StartOfList;
				StartOfList = StartOfList->getNext();
				delete CurrentNode;
			}
			m_entries = 0;
		}
	};

}

#endif //__STANDARDLAYOUTLIST_H__
