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

class PropertyMap : public IPropertyMap, public INotifyPropertyChange, public tsmod::IObject
{
public:
	PropertyMap(){}
	virtual ~PropertyMap(){}
	PropertyMap &operator=(const PropertyMap& obj)
	{
		if (this != &obj)
		{
			_map = obj._map;
			RaisePropertyChange("PropertyMap");
		}
		return *this;
	}

	virtual void OnConstructionFinished()
	{
		_propChange = TopServiceLocator()->get_instance<INotifyPropertyChange>("/NotifyPropertyChange");
	}
	virtual size_t count () const
	{
		return _map.count();
	}

	virtual tscrypto::tsCryptoString item(size_t index) const
	{
		return _map.item(index);
	}

	virtual tscrypto::tsCryptoString item(const tscrypto::tsCryptoString &name) const
	{
		return _map.item(name);
	}

	virtual int itemAsNumber(const tscrypto::tsCryptoString &name, int defaultValue) const
	{
		return _map.itemAsNumber(name, defaultValue);
	}

	virtual bool itemAsBoolean(const tscrypto::tsCryptoString &name, bool defaultValue) const
	{
		return _map.itemAsBoolean(name, defaultValue);
	}

	virtual bool hasItem(const tscrypto::tsCryptoString &name) const
	{
		return _map.hasItem(name);
	}

	virtual tscrypto::tsCryptoString name(size_t index) const
	{
		return _map.name(index);
	}

	virtual bool AddItem(const tscrypto::tsCryptoString &name, const tscrypto::tsCryptoString &value)
	{
		bool retVal = _map.AddItem(name, value);

		if (retVal)
			RaisePropertyChange(name);
		return retVal;
	}

	virtual bool AddItem(const tscrypto::tsCryptoString &name, int value)
	{
		bool retVal = _map.AddItem(name, value);

		if (retVal)
			RaisePropertyChange(name);
		return retVal;
	}

	virtual void ClearAll ()
	{
		_map.ClearAll();
		RaisePropertyChange("PropertyMap");
	}

	virtual void RemoveItem(size_t index)
	{
		tscrypto::tsCryptoString itemName = _map.name(index);

		_map.RemoveItem(index);
		if (itemName.size() > 0)
			RaisePropertyChange(itemName);
	}

	virtual void RemoveItem(const tscrypto::tsCryptoString &name)
	{
		bool hadItem = hasItem(name);
		_map.RemoveItem(name);
		if (hadItem)
			RaisePropertyChange(name);
	}

	virtual int AddNotification(std::function<void(const tscrypto::tsCryptoString&)> func)
	{
		return _propChange->AddNotification(func);
	}
	virtual void RemoveNotification(int cookie)
	{
		_propChange->RemoveNotification(cookie);
	}
	virtual void RaisePropertyChange(const tscrypto::tsCryptoString& list)
	{
		_propChange->RaisePropertyChange(list);
	}
	virtual tscrypto::tsCryptoString tag(size_t index) const
	{
		return _map.tag(index);
	}
	virtual void tag(size_t index, const tscrypto::tsCryptoString& setTo)
	{
		_map.tag(index, setTo);
	}
	virtual tscrypto::tsCryptoString tag(const tscrypto::tsCryptoString &name) const
	{
		return _map.tag(name);
	}
	virtual void tag(const tscrypto::tsCryptoString &name, const tscrypto::tsCryptoString& setTo)
	{
		_map.tag(name, setTo);
	}
	// Added 7.0.35
	bool parseUrlQueryString(const tscrypto::tsCryptoString& queryString)
	{
		tscrypto::tsCryptoString str;
		UrlParser parser;

		ClearAll();
		if (queryString.empty())
			return false;
		size_t pos = queryString.find('?');
		if (pos > 0 && pos < tscrypto::tsCryptoString::npos)
			return false;

		if (queryString.front() != '?')
		{
			str = "http://dummy?" + queryString;
		}
		else
		{
			str = "http://dummy" + queryString;
		}
		if (!parser.ParseFullUrl(str))
			return false;
		for (auto& nv : *parser.getParameters())
		{
			this->AddItem(nv.name, nv.value);
		}
		return true;
	}
	tscrypto::tsCryptoString createUrlQueryString() const
	{
		UrlParser parser;
		NameValueList list = CreateNameValueList();

		_map.foreach([list](const __tsAttributeMapItem& item) {
			list->push_back(NameValue(item.m_name, item.m_value));
		});
		parser.setParameters(list);
		parser.setHash("");
		parser.setScheme("");
		parser.setServer("");
		parser.setPath("");
		tscrypto::tsCryptoString str = parser.BuildUrl();
		if (str.front() == '/')
			str.erase(0, 1);
		return str;
	}

private:
	tsAttributeMap _map;
	std::shared_ptr<INotifyPropertyChange> _propChange;

	PropertyMap(const PropertyMap &obj) : _map(obj._map) {}
	PropertyMap(PropertyMap &&obj) : _map(std::move(obj._map)) {}

};

tsmod::IObject* CreatePropertyMap()
{
	return dynamic_cast<tsmod::IObject*>(new PropertyMap);
}