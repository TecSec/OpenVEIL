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

#include "stdafx.h"
#include "help/FileVEILHelp.h"

typedef struct wxHelpRegistryItem
{
	wxHelpRegistryItem(size_t winId, std::function<void()> func) : windowId(winId), helpFunc(func)
	{
	}
	wxHelpRegistryItem(size_t winId, const tscrypto::tsCryptoString & _url) : windowId(winId), url(_url)
	{
	}

	size_t windowId;
	tscrypto::tsCryptoString url;
	std::function<void()> helpFunc;
} HelpRegistryItem;

class wxHelpRegistry : public IVEILHttpHelpRegistry, public tsmod::IObject
{
public:
	wxHelpRegistry() : _port(80)
	{
		_scheme = "http";
		_prefix = "/help/";
		RegisterHttpHelp(winid_AudienceSelector, "IDH_Audience_Selector.htm");
		RegisterHttpHelp(winid_GeneralSettings, "IDH_General_Tab.htm");
		RegisterHttpHelp(winid_FileSettings, "IDH_Fileveil_Tab.htm");
		//RegisterHttpHelp(winid_TokenSelector, "FileVEIL.chm", IDH_);
	}
	virtual ~wxHelpRegistry() {}


protected:
	std::vector<HelpRegistryItem> _items;
	uint16_t _port;
	tscrypto::tsCryptoString _scheme;
	tscrypto::tsCryptoString _prefix;

	// Inherited via IVEILHelpRegistry
	virtual void DisplayHelpForWindowId(size_t windowId, XP_WINDOW wnd) override
	{
		for (auto& i : _items)
		{
			if (i.windowId == windowId)
			{
				if (!!i.helpFunc)
				{
					i.helpFunc();
					return;
				}
				else
				{
					tsCryptoString url;
					UrlParser parser;

					parser.setScheme(_scheme);
					parser.setServer("localhost");
					parser.setPort(_port);
					parser.setPath(_prefix + i.url);

					url = parser.BuildUrl();

					if (!tsLaunchBrowser(url.c_str()))
					{
						wxTsMessageBox("We were unable to display the help.", "ERROR", wxOK | wxICON_HAND);
					}
					return;
				}
			}
		}
		wxTsMessageBox("We were unable to display the help.", "ERROR", wxOK | wxICON_HAND);
	}

	virtual void RegisterHelpFunction(size_t windowId, std::function<void()> func) override
	{
		_items.erase(std::remove_if(_items.begin(), _items.end(), [windowId](HelpRegistryItem& item) ->bool { return item.windowId == windowId; }), _items.end());
		_items.push_back(wxHelpRegistryItem(windowId, func));
	}

	virtual void RegisterHttpHelp(size_t windowId, const tscrypto::tsCryptoString & url) override
	{
		_items.erase(std::remove_if(_items.begin(), _items.end(), [windowId](HelpRegistryItem& item) ->bool { return item.windowId == windowId; }), _items.end());
		_items.push_back(wxHelpRegistryItem(windowId, url));
	}

	virtual void SetHelpPort(uint16_t setTo) override
	{
		_port = setTo;
		if (_port == 0)
			_port = 80;
	}

	virtual void SetHelpScheme(const tscrypto::tsCryptoString & scheme) override
	{
		_scheme = scheme;
		if (_scheme.empty())
			_scheme = "http";
		else if (_scheme.back() == ':')
			_scheme.pop_back();
	}

	virtual void SetHelpPrefix(const tscrypto::tsCryptoString & setTo) override
	{
		_prefix = setTo;
		if (_prefix.size() != 0)
		{
			if (_prefix.front() != '/')
				_prefix.insert(0, '/');
			if (_prefix.back() != '/')
				_prefix.append('/');
		}
		else
			_prefix = "/";
	}
};

tsmod::IObject* CreateWxHelpRegistry()
{
	return dynamic_cast<tsmod::IObject*>(new wxHelpRegistry());
}