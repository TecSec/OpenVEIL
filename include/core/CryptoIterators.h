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

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \file   CryptoIterators.h
///
/// \brief  Interfaces for handling entropy. 
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __CRYPTOITERATORS_H__
#define __CRYPTOITERATORS_H__

#pragma once

namespace tscrypto {

	class OutOfRange;
	
	template<class containerType>
	class const_CryptoIterator
	{	// iterator for immutable collection
	public:
		typedef const_CryptoIterator<containerType> _iteratorType;
		typedef std::random_access_iterator_tag iterator_category;

		typedef typename containerType::value_type value_type;
		typedef typename containerType::size_type size_type;
		typedef typename containerType::difference_type difference_type;
		typedef typename containerType::const_pointer pointer;
		typedef typename containerType::const_reference reference;
		typedef typename containerType::const_container_type container_type;

		const_CryptoIterator() : _index(0)
		{
		}
		const_CryptoIterator(container_type cont) : _container(cont), _index(0)
		{
		}
		const_CryptoIterator(container_type cont, size_type index) : _container(cont), _index(index)
		{
		}
		const_CryptoIterator(const _iteratorType& obj) : _container(obj._container), _index(obj._index)
		{
		}
		const_CryptoIterator(_iteratorType&& obj) : _container(std::move(obj._container)), _index(obj._index)
		{
			obj._index = -1;
		}

		_iteratorType& operator=(const _iteratorType& obj)
		{
			if (std::addressof(obj) != this)
			{
				_container = obj._container;
				_index = obj._index;
			}
			return *this;
		}
		_iteratorType& operator=(_iteratorType&& obj)
		{
			if (std::addressof(obj) != this)
			{
				_container = std::move(obj._container);
				_index = obj._index;

				obj._index = 0;
			}
			return *this;
		}

		// Basic iterator support
		void swap(_iteratorType& obj)
		{
			if (!!_container && !!obj._container)
			{
				_container->swapIndices(_index, obj._index);
			}
		}

		reference operator*() const
		{
			if (!_container || _index >= (difference_type)_container->size())
				throw tscrypto::OutOfRange("");
			return (*_container)[_index];
		}
		_iteratorType& operator++()
		{ // prefix
			if (!_container || _index >= (difference_type)_container->size())
				throw tscrypto::OutOfRange("");
			_index++;
			return *this;
		}
		_iteratorType operator++(int)
		{ // postfix
			_iteratorType it = *this;
			++(*this);
			return it;
		}

		// Input Iterator
		bool operator==(const _iteratorType& obj) const
		{
			if (std::addressof(obj) == this)
				return true;
			if (!(_container == obj._container))
				return false;
			if (_index >= (difference_type)_container->size() && obj._index >= (difference_type)_container->size())
				return true;
			return _index == obj._index;
		}
		bool operator!=(const _iteratorType& obj) const
		{
			return !((*this) == obj);
		}
		pointer operator->() const
		{
			if (!_container || _index >= (difference_type)_container->size())
				throw tscrypto::OutOfRange("");
			return &((*_container)[_index]);
		}

		// Bidirectional Iterator
		_iteratorType& operator--()
		{ // prefix
			if (_index == 0)
				throw tscrypto::OutOfRange("");
			_index--;
			return *this;
		}
		_iteratorType operator--(int)
		{ // postfix
			_iteratorType it = *this;
			--(*this);
			return it;
		}

		// Random Access Iterator
		_iteratorType& operator+=(difference_type n)
		{
			if (!_container)
				throw tscrypto::OutOfRange("");
			_index += n;
			if (_index < 0)
			{
				_index = 0;
				throw tscrypto::OutOfRange("");
			}
			if (_index >= (difference_type)_container->size())
			{
				_index = (difference_type)_container->size();
				throw tscrypto::OutOfRange("");
			}
			return *this;
		}
		_iteratorType& operator-=(difference_type n)
		{
			return (*this) += -n;
		}
		difference_type operator-(const _iteratorType& right) const
		{
			if (!_container || !right._container || _container != right._container)
				throw tscrypto::OutOfRange("");
			return _index - right._index;
		}
		reference operator[](difference_type n) const
		{
			difference_type m = _index + n;

			if (!_container)
				throw tscrypto::OutOfRange("");
			if (m < 0)
			{
				throw tscrypto::OutOfRange("");
			}
			if (m >= (difference_type)_container->size())
			{
				throw tscrypto::OutOfRange("");
			}
			return (*_container)[m];
		}
		bool operator<(const _iteratorType& right) const
		{
			if (!_container) // one indication of end
				return false;
			if (_container != right._container)
				throw tscrypto::OutOfRange("");
			if (!right._container)
			{
				return _index < (difference_type)_container->size();
			}
			return _index < right._index;
		}
		bool operator<=(const _iteratorType& right) const
		{
			return ((*this) == right) || ((*this) < right);
		}
		bool operator>(const _iteratorType& right) const
		{
			return !((*this) <= right);
		}
		bool operator>=(const _iteratorType& right) const
		{
			return !((*this) < right);
		}
	protected:
		container_type _container;
		ptrdiff_t _index;
	};

	template <typename containerType>
	void swap(const_CryptoIterator<containerType>& left, const_CryptoIterator<containerType>& right)
	{
		left.swap(right);
	}
	template <typename containerType>
	const_CryptoIterator<containerType> operator+(const_CryptoIterator<containerType>& left, typename const_CryptoIterator<containerType>::difference_type right)
	{
		const_CryptoIterator<containerType> it = left;
		it += right;
		return it;
	}
	template <typename containerType>
	const_CryptoIterator<containerType> operator+(typename const_CryptoIterator<containerType>::difference_type left, const_CryptoIterator<containerType>& right)
	{
		const_CryptoIterator<containerType> it = right;
		it += left;
		return it;
	}
	template <typename containerType>
	const_CryptoIterator<containerType> operator-(const_CryptoIterator<containerType>& left, typename const_CryptoIterator<containerType>::difference_type right)
	{
		const_CryptoIterator<containerType> it = left;
		it -= right;
		return it;
	}
	template <typename containerType>
	const_CryptoIterator<containerType> operator-(typename const_CryptoIterator<containerType>::difference_type left, const_CryptoIterator<containerType>& right)
	{
		const_CryptoIterator<containerType> it = right;
		it -= left;
		return it;
	}


	template <class containerType>
	class CryptoIterator : public const_CryptoIterator<containerType>
	{ // Iterator for mutable collection
	public:
		typedef CryptoIterator<containerType> _iteratorType;
		typedef std::random_access_iterator_tag iterator_category;

		typedef typename containerType::value_type value_type;
		typedef typename containerType::difference_type difference_type;
		typedef typename containerType::pointer pointer;
		typedef typename containerType::reference reference;
		typedef typename containerType::container_type container_type;

		using const_CryptoIterator<containerType>::_container;
		using const_CryptoIterator<containerType>::_index;

		CryptoIterator() : const_CryptoIterator<containerType>()
		{}
		CryptoIterator(container_type cont) : const_CryptoIterator<containerType>(cont)
		{}
		CryptoIterator(container_type cont, typename const_CryptoIterator<containerType>::size_type index) : const_CryptoIterator<containerType>(cont, index)
		{}
		CryptoIterator(const CryptoIterator& obj) : const_CryptoIterator<containerType>(obj)
		{}
		CryptoIterator(CryptoIterator&& obj) : const_CryptoIterator<containerType>(std::move(obj))
		{}

		_iteratorType& operator=(const _iteratorType& obj)
		{
			if (std::addressof(obj) != this)
			{
				_container = obj._container;
				_index = obj._index;
			}
			return *this;
		}
		_iteratorType& operator=(_iteratorType&& obj)
		{
			if (std::addressof(obj) != this)
			{
				_container = std::move(obj._container);
				_index = obj._index;

				obj._index = 0;
			}
			return *this;
		}

		// Basic iterator support
		void swap(_iteratorType& obj)
		{
			if (!!_container && !!obj._container)
			{
				_container->swapIndices(_index, obj._index);
			}
		}

		reference operator*() const
		{
			if (!_container || _index >= (difference_type)_container->size())
				throw tscrypto::OutOfRange("");

			return ((reference)**(const_CryptoIterator<containerType> *)this);
		}
		_iteratorType& operator++()
		{ // prefix
			if (!_container || _index >= (difference_type)_container->size())
				throw tscrypto::OutOfRange("");
			_index++;
			return *this;
		}
		_iteratorType operator++(int)
		{ // postfix
			_iteratorType it = *this;
			++(*this);
			return it;
		}

		// Input Iterator
		pointer operator->()
		{
			if (!_container || _index >= (difference_type)_container->size())
				throw tscrypto::OutOfRange("");
			return &((*_container)[_index]);
		}

		// Bidirectional Iterator
		_iteratorType& operator--()
		{ // prefix
			if (_index == 0)
				throw tscrypto::OutOfRange("");
			_index--;
			return *this;
		}
		_iteratorType operator--(int)
		{ // postfix
			_iteratorType it = *this;
			--(*this);
			return it;
		}

		// Random Access Iterator
		_iteratorType& operator+=(difference_type n)
		{
			if (!_container)
				throw tscrypto::OutOfRange("");
			_index += n;
			if (_index < 0)
			{
				_index = 0;
				throw tscrypto::OutOfRange("");
			}
			if (_index >= (difference_type)_container->size())
			{
				_index = (difference_type)_container->size();
				throw tscrypto::OutOfRange("");
			}
			return *this;
		}
		_iteratorType& operator-=(difference_type n)
		{
			return (*this) += -n;
		}
		difference_type operator-(const _iteratorType& right) const
		{
			if (!_container || !right._container || _container != right._container)
				throw tscrypto::OutOfRange("");
			return _index - right._index;
		}
		reference operator[](difference_type n)
		{
			difference_type m = _index + n;

			if (!_container)
				throw tscrypto::OutOfRange("");
			if (m < 0)
			{
				throw tscrypto::OutOfRange("");
			}
			if (m >= (difference_type)_container->size())
			{
				throw tscrypto::OutOfRange("");
			}
			return (*_container)[m];
		}
	};

	template <typename containerType>
	void swap(CryptoIterator<containerType>& left, CryptoIterator<containerType>& right)
	{
		left.swap(right);
	}
	template <typename containerType>
	CryptoIterator<containerType> operator+(CryptoIterator<containerType>& left, typename CryptoIterator<containerType>::difference_type right)
	{
		CryptoIterator<containerType> it = left;
		it += right;
		return it;
	}
	template <typename containerType>
	CryptoIterator<containerType> operator+(typename CryptoIterator<containerType>::difference_type left, CryptoIterator<containerType>& right)
	{
		CryptoIterator<containerType> it = right;
		it += left;
		return it;
	}
	template <typename containerType>
	CryptoIterator<containerType> operator-(CryptoIterator<containerType>& left, typename CryptoIterator<containerType>::difference_type right)
	{
		CryptoIterator<containerType> it = left;
		it -= right;
		return it;
	}
	template <typename containerType>
	CryptoIterator<containerType> operator-(typename CryptoIterator<containerType>::difference_type left, CryptoIterator<containerType>& right)
	{
		CryptoIterator<containerType> it = right;
		it -= left;
		return it;
	}

}
#endif // __CRYPTOITERATORS_H__
