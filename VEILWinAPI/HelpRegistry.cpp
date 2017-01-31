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
#include "resource.h"
#include "help/FileVEILHelp.h"

typedef struct HelpRegistryItem
{
	HelpRegistryItem(size_t winId, std::function<void()> func) : windowId(winId), helpFunc(func), helpId(0)
	{}
	HelpRegistryItem(size_t winId, const tscrypto::tsCryptoString & filename, size_t id) : windowId(winId), helpFilename(filename), helpId(id)
	{}
	size_t windowId;
	tscrypto::tsCryptoString helpFilename;
	size_t helpId;
	std::function<void()> helpFunc;
} HelpRegistryItem;

class HelpRegistry : public IVEILHelpRegistry, public tsmod::IObject
{
public:
	HelpRegistry()
	{
		RegisterCHMHelp(winid_AudienceSelector, "FileVEIL.chm", IDH_AUDIENCE_SELECTOR);
		RegisterCHMHelp(winid_GeneralSettings, "FileVEIL.chm", IDH_GENERAL_TAB);
		RegisterCHMHelp(winid_FileSettings, "FileVEIL.chm", IDH_FILEVEIL_TAB);
		//RegisterCHMHelp(winid_TokenSelector, "FileVEIL.chm", IDH_);
	}
	virtual ~HelpRegistry() {}


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
					tscrypto::tsCryptoString path;


					if (xp_GetSpecialFolder(sft_TecSecFolder, path))
					{
						path += i.helpFilename;
						if (i.helpId == 0)
							TS_HtmlHelp(wnd, path, HH_DISPLAY_TOC, i.helpId);
						else
							TS_HtmlHelp(wnd, path, HH_HELP_CONTEXT, i.helpId);
					}
					else
					{
						if (!xp_PathSearch(i.helpFilename, path))
						{
							MessageBoxA((HWND)wnd, ("We were unable to locate the requested help file."), ("Error"), MB_OK);
						}
						else
						{
							if (i.helpId == 0)
								TS_HtmlHelp(wnd, path, HH_DISPLAY_TOC, i.helpId);
							else
								TS_HtmlHelp(wnd, path, HH_HELP_CONTEXT, i.helpId);
						}
					}
					return;
				}
			}
		}
		MessageBoxA((HWND)wnd, "We were unable to locate the requested help.", "Error", MB_OK);
	}

	virtual void RegisterHelpFunction(size_t windowId, std::function<void()> func) override
	{
		_items.erase(std::remove_if(_items.begin(), _items.end(), [windowId](HelpRegistryItem& item) ->bool { return item.windowId == windowId; }), _items.end());
		_items.push_back(HelpRegistryItem(windowId, func));
	}

	virtual void RegisterCHMHelp(size_t windowId, const tscrypto::tsCryptoString & filename, size_t helpId) override
	{
		_items.erase(std::remove_if(_items.begin(), _items.end(), [windowId](HelpRegistryItem& item) ->bool { return item.windowId == windowId; }), _items.end());
		_items.push_back(HelpRegistryItem(windowId, filename, helpId));
	}
protected:
	std::vector<HelpRegistryItem> _items;
};

tsmod::IObject* CreateHelpRegistry()
{
	return dynamic_cast<tsmod::IObject*>(new HelpRegistry());
}