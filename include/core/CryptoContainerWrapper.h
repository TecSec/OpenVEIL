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

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \file   CryptoContainerWrapper.h
///
/// \brief  Interfaces for handling entropy. 
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __CRYPTOCONTAINERWRAPPER_H__
#define __CRYPTOCONTAINERWRAPPER_H__

#pragma once

namespace tscrypto {

	template <typename baseType>
	class ICryptoContainerWrapper
	{
	public:
		typedef ICryptoContainerWrapper<baseType> self_type;
		typedef baseType value_type;
		typedef size_t size_type;
		typedef ptrdiff_t difference_type;
		typedef value_type& reference;
		typedef const value_type& const_reference;
		typedef value_type* pointer;
		typedef const value_type* const_pointer;
		typedef std::shared_ptr<self_type> container_type;
		typedef std::shared_ptr<self_type> const_container_type;

		typedef CryptoIterator<self_type> iterator;
		typedef const_CryptoIterator<self_type> const_iterator;
		typedef std::reverse_iterator<iterator> reverse_iterator;
		typedef std::reverse_iterator<const_iterator> const_reverse_iterator;

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

		virtual ~ICryptoContainerWrapper()
		{}
		virtual self_type& operator=(const self_type& list) = 0;
		virtual self_type& operator=(self_type&& list) = 0;
		//virtual self_type& operator=(std::initializer_list<value_type> ilist) = 0;

		virtual void assign(size_type count, const_reference value) = 0;
		virtual void assign(const_iterator insertBegin, const_iterator insertEnd) = 0;
		//virtual void assign(std::initializer_list<value_type> ilist) = 0;

		virtual reference operator[](size_type index) = 0;
		virtual const_reference operator[](size_type index) const = 0;
		virtual reference at(size_type index) = 0;
		virtual const_reference at(size_type index) const = 0;
		virtual reference front() = 0;
		virtual const_reference front() const = 0;
		virtual reference back() = 0;
		virtual const_reference back() const = 0;
		virtual pointer data() = 0;
		virtual const_pointer data() const = 0;

		virtual iterator begin() = 0;
		virtual const_iterator begin() const = 0;
		virtual iterator end() = 0;
		virtual const_iterator end() const = 0;

		virtual const_iterator cbegin() const = 0;
		virtual const_iterator cend() const = 0;

		virtual reverse_iterator rbegin() = 0;
		virtual reverse_iterator rend() = 0;

		virtual const_reverse_iterator crbegin() const = 0;
		virtual const_reverse_iterator crend() const = 0;

		virtual bool empty() const = 0;
		virtual size_type size() const = 0;
		virtual size_type max_size() const = 0;
		virtual void reserve(size_type setTo) = 0;
		virtual size_type capacity() const = 0;
		virtual void shrink_to_fit() = 0;

		virtual void clear() = 0;
		virtual iterator insert(const_iterator pos, const_reference data) = 0;
		virtual iterator insert(const_iterator pos, value_type&& data) = 0;
		//virtual iterator insert(const_iterator pos, size_type count, const_reference data) = 0;
		//virtual iterator insert(const_iterator pos, const_iterator insertBegin, const_iterator insertEnd) = 0;
		//virtual iterator insert(const_iterator pos, std::initializer_list<value_type> ilist) = 0;

		virtual iterator erase(const_iterator it) = 0;
		virtual iterator erase(const_iterator first, const_iterator last) = 0;

		virtual void push_back(const_reference value) = 0;
		virtual void push_back(value_type&& value) = 0;

		virtual void pop_back() = 0;

		virtual void resize(size_type newSize) = 0;
		virtual void resize(size_type newSize, const_reference value) = 0;

		virtual void swapIndices(size_type left, size_type right) = 0;
		virtual std::shared_ptr<ICryptoContainerWrapper<baseType>> cloneContainer() const = 0;
	};

}
#endif // __CONTAINERWRAPPER_H__
