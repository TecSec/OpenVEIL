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


tsStringSignal::tsStringSignal()
{
	contents = new tsStringSignalList();
}

tsStringSignal::~tsStringSignal()
{
	if (contents != nullptr)
		delete (tsStringSignalList*)contents;
	contents = nullptr;
}

size_t tsStringSignal::Add(std::function<void(const tscrypto::tsCryptoStringBase&)> func)
{
	if (contents == nullptr)
		return 0;

	tsStringSignalItem item;
	item.cookie = InterlockedIncrement(&tsStringSignalCookie);
	item.func = func;
	((tsStringSignalList*)contents)->push_back(item);
	return item.cookie;
}

void tsStringSignal::Remove(size_t cookie)
{
	if (contents == nullptr)
		return;

	auto it = std::find_if(((tsStringSignalList*)contents)->begin(), ((tsStringSignalList*)contents)->end(), [cookie](tsStringSignalItem& item)->bool{ return item.cookie == (int)cookie; });
	if (it != ((tsStringSignalList*)contents)->end())
		((tsStringSignalList*)contents)->erase(it);
}

void tsStringSignal::Fire(const tscrypto::tsCryptoStringBase& param) const
{
	if (contents == nullptr)
		return;

	for (tsStringSignalItem& item : *((tsStringSignalList*)contents))
	{ 
		if (!!item.func) 
			item.func(param); 
	}
}
void tsStringSignal::clear()
{
	((tsStringSignalList*)contents)->clear();
}

//===================================================================================

struct tsIObjStringSignalItem
{
	int cookie;
	std::function<void(const tsmod::IObject*, const tscrypto::tsCryptoStringBase&)> func;
};
typedef std::vector<tsIObjStringSignalItem> tsIObjStringSignalList;
static uint32_t tsIObjStringSignalCookie = 1;

tsIObjStringSignal::tsIObjStringSignal()
{
	contents = new tsIObjStringSignalList();
}
tsIObjStringSignal::~tsIObjStringSignal()
{
	if (contents != nullptr)
		delete (tsIObjStringSignalList*)contents;
	contents = nullptr;
}

size_t tsIObjStringSignal::Add(std::function<void(const tsmod::IObject*, const tscrypto::tsCryptoStringBase&)> func)
{
	if (contents == nullptr)
		return 0;

	tsIObjStringSignalItem item;
	item.cookie = InterlockedIncrement(&tsIObjStringSignalCookie);
	item.func = func;
	((tsIObjStringSignalList*)contents)->push_back(item);
	return item.cookie;
}

void tsIObjStringSignal::Remove(size_t cookie)
{
	if (contents == nullptr)
		return;

	auto it = std::find_if(((tsIObjStringSignalList*)contents)->begin(), ((tsIObjStringSignalList*)contents)->end(), [cookie](tsIObjStringSignalItem& item)->bool{ return item.cookie == (int)cookie; });
	if (it != ((tsIObjStringSignalList*)contents)->end())
		((tsIObjStringSignalList*)contents)->erase(it);
}

void tsIObjStringSignal::Fire(const tsmod::IObject* object, const tscrypto::tsCryptoStringBase& param) const
{
	if (contents == nullptr)
		return;

	for (tsIObjStringSignalItem& item : *((tsIObjStringSignalList*)contents))
	{
		if (!!item.func) 
			item.func(object, param); 
	}
}
void tsIObjStringSignal::clear()
{
	((tsIObjStringSignalList*)contents)->clear();
}


//===================================================================================

struct tsVoidSignalItem
{
	int cookie;
	std::function<void()> func;
};
typedef std::vector<tsVoidSignalItem> tsVoidSignalList;
static uint32_t tsVoidSignalCookie = 1;

tsVoidSignal::tsVoidSignal()
{
	contents = new tsVoidSignalList();
}

tsVoidSignal::~tsVoidSignal()
{
	if (contents != nullptr)
		delete (tsVoidSignalList*)contents;
	contents = nullptr;
}

size_t tsVoidSignal::Add(std::function<void()> func)
{
	if (contents == nullptr)
		return 0;

	tsVoidSignalItem item;
	item.cookie = InterlockedIncrement(&tsVoidSignalCookie);
	item.func = func;
	((tsVoidSignalList*)contents)->push_back(item);
	return item.cookie;
}

void tsVoidSignal::Remove(size_t cookie)
{
	if (contents == nullptr)
		return;

	auto it = std::find_if(((tsVoidSignalList*)contents)->begin(), ((tsVoidSignalList*)contents)->end(), [cookie](tsVoidSignalItem& item)->bool{ return item.cookie == (int)cookie; });
	if (it != ((tsVoidSignalList*)contents)->end())
		((tsVoidSignalList*)contents)->erase(it);
}

void tsVoidSignal::Fire() const
{
	if (contents == nullptr)
		return;

	for (tsVoidSignalItem& item : *((tsVoidSignalList*)contents))
	{ 
		if (!!item.func) 
			item.func(); 
	}
}
void tsVoidSignal::clear()
{
	((tsVoidSignalList*)contents)->clear();
}


//===================================================================================

struct tsSignalItem
{
	int cookie;
	std::function<void(const tsmod::IObject*, ISignalArgs*)> func;
};
typedef std::vector<tsSignalItem> tsSignalList;
static uint32_t tsSignalCookie = 1;

tsSignal::tsSignal()
{
	contents = new tsSignalList();
}

tsSignal::~tsSignal()
{
	if (contents != nullptr)
		delete (tsSignalList*)contents;
	contents = nullptr;
}

size_t tsSignal::Add(std::function<void(const tsmod::IObject*, ISignalArgs*)> func)
{
	if (contents == nullptr)
		return 0;

	tsSignalItem item;
	item.cookie = InterlockedIncrement(&tsSignalCookie);
	item.func = func;
	((tsSignalList*)contents)->push_back(item);
	return item.cookie;
}

void tsSignal::Remove(size_t cookie)
{
	if (contents == nullptr)
		return;

	auto it = std::find_if(((tsSignalList*)contents)->begin(), ((tsSignalList*)contents)->end(), [cookie](tsSignalItem& item)->bool{ return item.cookie == (int)cookie; });
	if (it != ((tsSignalList*)contents)->end())
		((tsSignalList*)contents)->erase(it);
}

void tsSignal::Fire(const tsmod::IObject* object, ISignalArgs*args) const
{
	if (contents == nullptr)
		return;

	for (tsSignalItem& item : *((tsSignalList*)contents))
	{ 
		if (!!item.func) 
			item.func(object, args); 
	}
}
void tsSignal::clear()
{
	((tsSignalList*)contents)->clear();
}


//===================================================================================

struct tsPropChangeSignalItem
{
	int cookie;
	std::function<void(const tsmod::IObject*, IPropertyChangedEventArgs*)> func;
};
typedef std::vector<tsPropChangeSignalItem> tsPropChangeSignalList;
//static uint32_t tsPropChangeSignalCookie = 1;

tsPropChangeSignal::tsPropChangeSignal()
{
	contents = new tsPropChangeSignalList();
}

tsPropChangeSignal::~tsPropChangeSignal()
{
	if (contents != nullptr)
		delete (tsPropChangeSignalList*)contents;
	contents = nullptr;
}

size_t tsPropChangeSignal::Add(std::function<void(const tsmod::IObject*, IPropertyChangedEventArgs*)> func)
{
	if (contents == nullptr)
		return 0;

	tsPropChangeSignalItem item;
	item.cookie = InterlockedIncrement(&tsSignalCookie);
	item.func = func;
	((tsPropChangeSignalList*)contents)->push_back(item);
	return item.cookie;
}

void tsPropChangeSignal::Remove(size_t cookie)
{
	if (contents == nullptr)
		return;

	auto it = std::find_if(((tsPropChangeSignalList*)contents)->begin(), ((tsPropChangeSignalList*)contents)->end(), [cookie](tsPropChangeSignalItem& item)->bool{ return item.cookie == (int)cookie; });
	if (it != ((tsPropChangeSignalList*)contents)->end())
		((tsPropChangeSignalList*)contents)->erase(it);
}

void tsPropChangeSignal::Fire(const tsmod::IObject* object, IPropertyChangedEventArgs*args) const
{
	if (contents == nullptr)
		return;

	for (tsPropChangeSignalItem& item : *((tsPropChangeSignalList*)contents))
	{ 
		if (!!item.func) 
			item.func(object, args); 
	}
}
void tsPropChangeSignal::clear()
{
	((tsPropChangeSignalList*)contents)->clear();
}

