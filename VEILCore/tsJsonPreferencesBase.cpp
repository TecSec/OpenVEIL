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

static const char *gEntries[] = { "&$.Debug" };

class HIDDEN JsonPreferenceChangeEvent : public CkmChangeEventCore, public IJsonPreferenceChangeEvent, public tsmod::IObject
{
public:
	JsonPreferenceChangeEvent(std::shared_ptr<tsJsonPreferencesBase> obj) :
		m_obj(obj) {};
	virtual ~JsonPreferenceChangeEvent() {}

	virtual CKMChangeType   GetChangeType()
	{
		return CKMChange_Preferences;
	}
	//
	virtual tsJsonPreferencesBase* GetPreferencesObject()
	{
		return m_obj.get();
	}
private:
	std::shared_ptr<tsJsonPreferencesBase> m_obj;
};


tsJsonPreferencesBase::tsJsonPreferencesBase(JsonConfigLocation loc1, JsonConfigLocation loc2, JsonConfigLocation loc3)
	:
	m_valuesLoaded(false),
	_location1(loc1),
	_location2(loc2),
	_location3(loc3)
{
	_preferenceItems = CreateContainer<JsonPreferenceItem>();
	m_notifierList = CreateContainer<std::shared_ptr<IPreferenceChangeNotify>>();

	memset(&m_policyFileInfo, 0, sizeof(m_policyFileInfo));
	memset(&m_firstFileInfo, 0, sizeof(m_firstFileInfo));
	memset(&m_secondFileInfo, 0, sizeof(m_secondFileInfo));
	memset(&m_thirdFileInfo, 0, sizeof(m_thirdFileInfo));
}

tsJsonPreferencesBase::~tsJsonPreferencesBase(void)
{
	if (!!m_changeScanner)
	{
		m_changeScanner->Disconnect();
		m_changeScanner.reset();
	}
}

void tsJsonPreferencesBase::Disconnect()
{
	if (!!m_changeScanner)
	{
		m_changeScanner->Disconnect();
	}
}

bool tsJsonPreferencesBase::MonitorRunning() const
{
	return !!m_changeScanner;
}

void tsJsonPreferencesBase::StartMonitor()
{
	if (!!m_changeScanner)
	{
		return;
	}

	prepareForMonitoring();

	m_changeScanner = ::TopServiceLocator()->Finish<ChangeTracker>(new ChangeTracker(std::dynamic_pointer_cast<ICkmChangeProducer>(_me.lock())));
}

void tsJsonPreferencesBase::prepareForMonitoring()
{
	m_policyFilename = filePath(ConfigName(), jc_Policy);
	if (ThirdLocation() != jc_NotFound)
		m_thirdFilename = filePath(ConfigName(), ThirdLocation());
	if (SecondLocation() != jc_NotFound)
		m_secondFilename = filePath(ConfigName(), SecondLocation());
	if (Location() != jc_NotFound)
		m_firstFilename = filePath(ConfigName(), Location());

	if (m_policyFilename.length() > 0)
	{
#ifdef _WIN32
		GetFileAttributesExA(m_policyFilename.c_str(), GetFileExInfoStandard, &m_policyFileInfo);
#else
		stat(m_policyFilename.c_str(), &m_policyFileInfo);
#endif // _WIN32
	}
	if (m_firstFilename.length() > 0)
	{
#ifdef _WIN32
		GetFileAttributesExA(m_firstFilename.c_str(), GetFileExInfoStandard, &m_firstFileInfo);
#else
		stat(m_firstFilename.c_str(), &m_firstFileInfo);
#endif // _WIN32
	}
	if (m_secondFilename.length() > 0)
	{
#ifdef _WIN32
		GetFileAttributesExA(m_secondFilename.c_str(), GetFileExInfoStandard, &m_secondFileInfo);
#else
		stat(m_secondFilename.c_str(), &m_secondFileInfo);
#endif // _WIN32
	}
	if (m_thirdFilename.length() > 0)
	{
#ifdef _WIN32
		GetFileAttributesExA(m_thirdFilename.c_str(), GetFileExInfoStandard, &m_thirdFileInfo);
#else
		stat(m_thirdFilename.c_str(), &m_thirdFileInfo);
#endif // _WIN32
	}
}

#ifdef _WIN32
static bool infoDifferent(const WIN32_FILE_ATTRIBUTE_DATA &left, const WIN32_FILE_ATTRIBUTE_DATA &right)
{
	if (left.dwFileAttributes != right.dwFileAttributes ||
		left.ftCreationTime.dwHighDateTime != right.ftCreationTime.dwHighDateTime ||
		left.ftCreationTime.dwLowDateTime != right.ftCreationTime.dwLowDateTime ||
		left.ftLastAccessTime.dwHighDateTime != right.ftLastAccessTime.dwHighDateTime ||
		left.ftLastAccessTime.dwLowDateTime != right.ftLastAccessTime.dwLowDateTime ||
		left.ftLastWriteTime.dwHighDateTime != right.ftLastWriteTime.dwHighDateTime ||
		left.ftLastWriteTime.dwLowDateTime != right.ftLastWriteTime.dwLowDateTime ||
		left.nFileSizeHigh != right.nFileSizeHigh ||
		left.nFileSizeLow != right.nFileSizeLow)
	{
		return true;
	}

	return false;
}
#else
static bool infoDifferent(const struct stat& left, const struct stat& right)
{
	return memcmp(&left, &right, sizeof(struct stat)) != 0;
}
#endif // _WIN32

void tsJsonPreferencesBase::FireGlobalChangeEvent()
{
	if (!!gChangeMonitor)
	{
		std::shared_ptr<ICkmChangeEvent> evt = ::TopServiceLocator()->Finish<ICkmChangeEvent>(new JsonPreferenceChangeEvent(std::dynamic_pointer_cast<tsJsonPreferencesBase>(_me.lock())));
		gChangeMonitor->RaiseChange(evt);
	}
}

void tsJsonPreferencesBase::ScanForChanges()
{
	static uint32_t procesing = 0;
	bool changeDetected = false;

	if (!areValuesLoaded())
		return;

	if (InterlockedIncrement(&procesing) != 1)
	{
		InterlockedDecrement(&procesing);
		return;
	}
	auto cleanup1 = finally([](){InterlockedDecrement(&procesing); });
#ifdef _WIN32
	if (m_policyFilename.length() != 0)
	{
		WIN32_FILE_ATTRIBUTE_DATA test;

		memset(&test, 0, sizeof(test));
		GetFileAttributesExA(m_policyFilename.c_str(), GetFileExInfoStandard, &test);
		changeDetected = infoDifferent(test, m_policyFileInfo);
	}
	if (!changeDetected && m_firstFilename.length() != 0)
	{
		WIN32_FILE_ATTRIBUTE_DATA test;

		memset(&test, 0, sizeof(test));
		GetFileAttributesExA(m_firstFilename.c_str(), GetFileExInfoStandard, &test);
		changeDetected = infoDifferent(test, m_firstFileInfo);
	}
	if (!changeDetected && m_secondFilename.length() != 0)
	{
		WIN32_FILE_ATTRIBUTE_DATA test;

		memset(&test, 0, sizeof(test));
		GetFileAttributesExA(m_secondFilename.c_str(), GetFileExInfoStandard, &test);
		changeDetected = infoDifferent(test, m_secondFileInfo);
	}
	if (!changeDetected && m_thirdFilename.length() != 0)
	{
		WIN32_FILE_ATTRIBUTE_DATA test;

		memset(&test, 0, sizeof(test));
		GetFileAttributesExA(m_thirdFilename.c_str(), GetFileExInfoStandard, &test);
		changeDetected = infoDifferent(test, m_thirdFileInfo);
	}
	if (changeDetected)
	{
		setDefaultValues();
		loadValues();

		if (m_policyFilename.length() > 0)
		{
			GetFileAttributesExA(m_policyFilename.c_str(), GetFileExInfoStandard, &m_policyFileInfo);
		}
		if (m_firstFilename.length() > 0)
		{
			GetFileAttributesExA(m_firstFilename.c_str(), GetFileExInfoStandard, &m_firstFileInfo);
		}
		if (m_secondFilename.length() > 0)
		{
			GetFileAttributesExA(m_secondFilename.c_str(), GetFileExInfoStandard, &m_secondFileInfo);
		}
		if (m_thirdFilename.length() > 0)
		{
			GetFileAttributesExA(m_thirdFilename.c_str(), GetFileExInfoStandard, &m_thirdFileInfo);
		}

		for (std::shared_ptr<IPreferenceChangeNotify>& notifier : *m_notifierList)
		{
			if (!!notifier)
			{
				notifier->OnPrefChange();
			}
		}
		FireGlobalChangeEvent();
	}
#else
	if (m_policyFilename.length() != 0)
	{
		struct stat test;

		memset(&test, 0, sizeof(test));
		stat(m_policyFilename.c_str(), &test);
		changeDetected = infoDifferent(test, m_policyFileInfo);
	}
	if (!changeDetected && m_firstFilename.length() != 0)
	{
		struct stat test;

		memset (&test, 0, sizeof(test));
		stat(m_firstFilename.c_str(), &test);
		changeDetected = infoDifferent(test, m_firstFileInfo);
	}
	if (!changeDetected && m_secondFilename.length() != 0)
	{
		struct stat test;

		memset (&test, 0, sizeof(test));
		stat(m_secondFilename.c_str(), &test);
		changeDetected = infoDifferent(test, m_secondFileInfo);
	}
	if (!changeDetected && m_thirdFilename.length() != 0)
	{
		struct stat test;

		memset (&test, 0, sizeof(test));
		stat(m_thirdFilename.c_str(), &test);
		changeDetected = infoDifferent(test, m_thirdFileInfo);
	}
	if (changeDetected)
	{
		setDefaultValues();
		loadValues();

		if (m_policyFilename.length() > 0)
		{
			stat(m_policyFilename.c_str(), &m_policyFileInfo);
		}
		if (m_firstFilename.length() > 0)
		{
			stat(m_firstFilename.c_str(), &m_firstFileInfo);
		}
		if (m_secondFilename.length() > 0)
		{
			stat(m_secondFilename.c_str(), &m_secondFileInfo);
		}
		if (m_thirdFilename.length() > 0)
		{
			stat(m_thirdFilename.c_str(), &m_thirdFileInfo);
		}

		for (std::shared_ptr<IPreferenceChangeNotify>& notifier : *m_notifierList)
		{
			if (!!notifier)
			{
				notifier->OnPrefChange();
			}
		}
		FireGlobalChangeEvent();
	}
#endif // _WIN32
}

void tsJsonPreferencesBase::registerPrefsChangeNotification(std::shared_ptr<IPreferenceChangeNotify> handler)
{
	m_notifierList->erase(std::remove_if(m_notifierList->begin(), m_notifierList->end(), [&handler](std::shared_ptr<IPreferenceChangeNotify> notify) { return notify == handler;}), m_notifierList->end());
//	m_notifierList->remove(handler);
	m_notifierList->push_back(handler);
	StartMonitor();

	if (!areValuesLoaded())
	{
		loadValues();
	}
}

void tsJsonPreferencesBase::unregisterPrefsChangeNotification(std::shared_ptr<IPreferenceChangeNotify> handler)
{
	m_notifierList->erase(std::remove_if(m_notifierList->begin(), m_notifierList->end(), [&handler](std::shared_ptr<IPreferenceChangeNotify> notify) { return notify == handler;}), m_notifierList->end());
//	m_notifierList->remove(handler);
}

bool tsJsonPreferencesBase::loadValues(JsonConfigLocation location)
{
	bool retVal = true;

	if (configExistsHere(ConfigName(), location) == jc_NotFound)
		return true;

	JSONObject cfg;

	cfg = ReadJSONObject(ConfigName(), location);

	if (UseEntries())
		retVal = loadPreferencesForLocation(location, cfg) | retVal;
	retVal = loadValuesForLocation(location, cfg) | retVal;
	return retVal;
}

tsJsonPreferencesBase* tsJsonPreferencesBase::loadValues()
{
	bool retVal = false;

	if (m_valuesLoaded)
		return this;

	_preferenceItems->clear();
	m_policyFilename = filePath(ConfigName(), jc_Policy);
	if (ThirdLocation() != jc_NotFound)
		m_thirdFilename = filePath(ConfigName(), ThirdLocation());
	if (SecondLocation() != jc_NotFound)
		m_secondFilename = filePath(ConfigName(), SecondLocation());
	if (Location() != jc_NotFound)
		m_firstFilename = filePath(ConfigName(), Location());

	setDefaultValues();

	if (m_policyFilename.size() > 0 && configExistsHere(ConfigName(), jc_Policy) == jc_Policy)
	{
		retVal = loadValues(jc_Policy) | retVal;
	}

	retVal = loadValues(Location()) | retVal;

	if (SecondLocation() != jc_NotFound)
		retVal = loadValues(SecondLocation()) | retVal;

	if (ThirdLocation() != jc_NotFound)
		retVal = loadValues(ThirdLocation()) | retVal;

	m_valuesLoaded = true;
	return this;
}

static bool IsNumber(const tscrypto::tsCryptoString& str)
{
	if (str.size() == 0)
		return false;

	for (size_t i = 0; i < str.size(); i++)
	{
		char c = str[i];
		if (c < '0' || c > '9' || (c == '-' && i > 0))
			return false;
	}
	return true;
}
bool tsJsonPreferencesBase::saveConfigurationChanges(JsonConfigLocation location)
{
	bool retVal = true;

	if (UseEntries())
	{
		int count = getPreferenceItemCount();
		//bool hasOneForLocation = false;

		//for (int i = 0; !hasOneForLocation && i < count; i++)
		//{
		//	hasOneForLocation = (_preferenceItems[i].Location == location);
		//}
		//if (hasOneForLocation)
		{
			JSONObject cfg;

			cfg = ReadJSONObject(ConfigName(), location);

			//
			// First remove all tracked entries
			//
			count = getEntrySearchCount();
			for (int i = 0; i < count; i++)
			{
				JsonPreferenceItem pref(getEntrySearch(i), "", location);

				JsonSearchResultList list = cfg.JSONPathQuery(pref.ItemPath());

				for (JSONElement* node : *list)
				{
					node->DeleteMeFromParent();
				}
			}

			//
			// Now add the entries that we currently have
			//
			count = getPreferenceItemCount();

			for (int i = 0; i < count; i++)
			{
				if (location != jc_Policy && _preferenceItems->at(i).Location == location)
				{
					if (_preferenceItems->at(i).isNode())
					{
						JSONElement* node = cfg.findSingleItem(_preferenceItems->at(i).ItemPath(), true);
						tscrypto::tsCryptoString Results;

						if (node == nullptr)
						{
							return false;
						}
						node->clear();
						JSONObject o;

						if (!o.FromJSON(_preferenceItems->at(i).Value.c_str()))
							return false;
						if (node->ElementType() == jet_Object)
						{
							*(reinterpret_cast<JSONObject*>(node)) = o;
						}
						else
						{
							(reinterpret_cast<JSONField*>(node))->Value(o);
						}
					}
					else
					{
						JSONElement* node = cfg.findSingleItem(_preferenceItems->at(i).ItemPath(), true);

						if (node == nullptr)
						{
							return false;
						}
						if (node == nullptr)
							return false;

						if (node->ElementType() == jet_Object)
						{
							JSONObject o;

							if (!o.FromJSON(_preferenceItems->at(i).Value.c_str()))
								return false;
							*(reinterpret_cast<JSONObject*>(node)) = o;
						}
						else
						{
							if (!_preferenceItems->at(i).Value.empty() && _preferenceItems->at(i).Value[0] == '{')
							{
								JSONObject o;

								if (!o.FromJSON(_preferenceItems->at(i).Value.c_str()))
									(reinterpret_cast<JSONField*>(node))->Value(_preferenceItems->at(i).Value);
								else
									(reinterpret_cast<JSONField*>(node))->Value(o);
							}
							else
							{
								tscrypto::tsCryptoString val(_preferenceItems->at(i).Value);

								if (TsStriCmp(val, "true") == 0)
									(reinterpret_cast<JSONField*>(node))->Value(true);
								else if (TsStriCmp(val, "false") == 0)
									(reinterpret_cast<JSONField*>(node))->Value(false);
								else if (IsNumber(val))
									(reinterpret_cast<JSONField*>(node))->Value(TsStrToInt64(val));
								else
									(reinterpret_cast<JSONField*>(node))->Value(_preferenceItems->at(i).Value);

							}
						}
					}
				}
			}
			if (!WriteJSONObject(ConfigName(), location, cfg))
				return false;
		}
	}
	else
		retVal = saveConfigurationChangesForLocation(location) | retVal;
	return retVal;
}

bool tsJsonPreferencesBase::saveConfigurationChanges()
{
	bool retVal = true;

	switch (Location())
	{
	case jc_System:
		retVal = saveConfigurationChanges(jc_System) & retVal;
		break;
	case jc_ModuleFolder:
		retVal = saveConfigurationChanges(jc_ModuleFolder) & retVal;
		break;
	case jc_Public:
		retVal = saveConfigurationChanges(jc_Public) & retVal;
		break;
	case jc_User:
		retVal = saveConfigurationChanges(jc_User) & retVal;
		break;
	}

	if (SecondLocation() != jc_NotFound)
		retVal = saveConfigurationChanges(SecondLocation()) & retVal;

	if (ThirdLocation() != jc_NotFound)
		retVal = saveConfigurationChanges(ThirdLocation()) & retVal;

	return retVal;
}

JsonConfigLocation tsJsonPreferencesBase::DefaultSaveLocation() const
{
	switch (Location())
	{
	case jc_ModuleFolder:
		return jc_ModuleFolder;
	case jc_System:
		return jc_System;
	case jc_Public:
		return jc_Public;
	case jc_User:
	default:
		return jc_User;
	}
}

bool tsJsonPreferencesBase::areValuesLoaded() const
{
	return m_valuesLoaded;
}

bool tsJsonPreferencesBase::OverwriteEntry(const tscrypto::tsCryptoString &entryName, JsonConfigLocation currentLocation, JsonConfigLocation newLocation) const
{
	MY_UNREFERENCED_PARAMETER(entryName);

	if (currentLocation == jc_Policy)
		return false;
	if (LocationLevel(newLocation) > 0 && (currentLocation == jc_NotFound || LocationLevel(currentLocation) >= LocationLevel(newLocation)))
		return true;
	return false;
}

int tsJsonPreferencesBase::getEntrySearchCount() const
{
	return sizeof(gEntries) / sizeof(gEntries[0]);
}

tscrypto::tsCryptoString tsJsonPreferencesBase::getEntrySearch(int index) const
{
	if (index < 0 || index >= getEntrySearchCount())
		return "";

	return gEntries[index];
}

int tsJsonPreferencesBase::getPreferenceItemCount() const
{
	return (int)_preferenceItems->size();
}

JsonPreferenceItem tsJsonPreferencesBase::getPreferenceItem(int index) const
{
	return _preferenceItems->at(index);
}

JsonPreferenceItem tsJsonPreferencesBase::findPreferenceItem(const tscrypto::tsCryptoString &path) const
{
	int count = getPreferenceItemCount();

	for (int i = 0; i < count; i++)
	{
		JsonPreferenceItem item = getPreferenceItem(i);
		if (TsStriCmp(item.Path, path) == 0)
			return item;
	}
	return JsonPreferenceItem(path, "", jc_NotFound);
}

bool tsJsonPreferencesBase::setPreferenceItem(const JsonPreferenceItem &item)
{
	int count = getPreferenceItemCount();

	for (int i = 0; i < count; i++)
	{
		JsonPreferenceItem itm = getPreferenceItem(i);
		if (TsStriCmp(itm.Path, item.Path) == 0)
		{
			if (OverwriteEntry(item.Path, itm.Location, item.Location))
			{
				_preferenceItems->at(i) = item;
			}
			else
				return false;
		}
	}
	_preferenceItems->push_back(item);
	return true;
}

int tsJsonPreferencesBase::LocationLevel(JsonConfigLocation location) const
{
	if (location == Location())
		return 1;
	if (location == SecondLocation() && SecondLocation() != jc_NotFound)
		return 2;
	if (location == ThirdLocation() && ThirdLocation() != jc_NotFound)
		return 3;
	return 0;
}

bool tsJsonPreferencesBase::loadPreferencesForLocation(JsonConfigLocation location, JSONObject &config)
{
	int count = getEntrySearchCount();

	for (int i = 0; i < count; i++)
	{
		tscrypto::tsCryptoString searchItem = getEntrySearch(i);
		JSONElement* node;
		auto it = std::find_if(_preferenceItems->begin(), _preferenceItems->end(), [&searchItem](JsonPreferenceItem& item){ return item.Path == searchItem || item.ItemPath() == searchItem; });

		if (it == _preferenceItems->end())
		{
			JsonPreferenceItem item(searchItem, "", location);
			node = config.findSingleItem(item.ItemPath(), false);

			if (node != nullptr)
			{

				item.Value = node->ToString();
				_preferenceItems->push_back(item);
			}
		}
	}
	return true;
}

bool tsJsonPreferencesBase::buildAndTestPath(JsonConfigLocation location, const tscrypto::tsCryptoString &appName, tscrypto::tsCryptoString &pathStr)
{
	tscrypto::tsCryptoString path;

	pathStr.clear();
	switch (location)
	{
	case jc_Policy:
		if (!xp_GetSpecialFolder(sft_PolicyData, path))
		{
			path.clear();
			return false;
		}
		break;

	case jc_System:
		if (!xp_GetSpecialFolder(sft_CommonApplicationData, path))
		{
			path.clear();
			LOG(FrameworkError, "Unable to access the common application directory.");
			//                CkmError("Unable to access the common application directory.");
			return false;
		}
		break;
	case jc_User:
		if (!xp_GetSpecialFolder(sft_UserConfigFolder, path))
		{
			path.clear();
			LOG(FrameworkError, "Unable to access the user config directory.");
			//                CkmError("Unable to access the user data directory.");
			return false;
		}
		break;
	case jc_Public:
		if (!xp_GetSpecialFolder(sft_PublicDataFolder, path))
		{
			path.clear();
			LOG(FrameworkError, "Unable to access the public data directory.");
			//                CkmError("Unable to access the public data directory.");
			return false;
		}
		break;
	case jc_ModuleFolder:
		if (!xp_GetModuleFileName(XP_MODULE_INVALID, path))
		{
			path.clear();
			LOG(FrameworkError, "Unable to access the Module data directory.");
			//                CkmError("Unable to access the Module data directory.");
			return false;
		}
		else
		{
			tscrypto::tsCryptoString dir;
			tscrypto::tsCryptoString file;
			tscrypto::tsCryptoString ext;

			xp_SplitPath(path, dir, file, ext);
			path = dir;
		}
		break;
	default:
		return false;
	}
	path += appName;
	//#ifdef _WIN32
	//	path += ".config";
	//#else
	path += ".ovc";
	//#endif

	pathStr = path;

	return (xp_FileExists(path) != FALSE);
}

JsonConfigLocation tsJsonPreferencesBase::configExistsHere(const tscrypto::tsCryptoString &appName, JsonConfigLocation location)
{
	tscrypto::tsCryptoString path;

	switch (location)
	{
	case jc_Policy:
		if (buildAndTestPath(jc_Policy, appName, path))
			return jc_Policy;
		break;
	case jc_System:
		if (buildAndTestPath(jc_System, appName, path))
			return jc_System;
		break;
	case jc_User:
		if (buildAndTestPath(jc_User, appName, path))
			return jc_User;
		break;
	case jc_Public:
		if (buildAndTestPath(jc_Public, appName, path))
			return jc_Public;
		break;
	case jc_ModuleFolder:
		if (buildAndTestPath(jc_ModuleFolder, appName, path))
			return jc_ModuleFolder;
		break;
	default:
		break;
	}
	return jc_NotFound;
}

tscrypto::tsCryptoString tsJsonPreferencesBase::filePath(const tscrypto::tsCryptoString &appName, JsonConfigLocation location)
{
	tscrypto::tsCryptoString path;

	switch (location)
	{
	case jc_Policy:
		buildAndTestPath(jc_Policy, appName, path);
		return path;
	case jc_System:
		buildAndTestPath(jc_System, appName, path);
		return path;
	case jc_User:
		buildAndTestPath(jc_User, appName, path);
		return path;
	case jc_Public:
		buildAndTestPath(jc_Public, appName, path);
		return path;
	case jc_ModuleFolder:
		buildAndTestPath(jc_ModuleFolder, appName, path);
		return path;
	default:
		break;
	}
	path.clear();
	return path;
}

JSONObject tsJsonPreferencesBase::ReadJSONObject(const tscrypto::tsCryptoString& configName, JsonConfigLocation location)
{
	JSONObject tmp;
	tscrypto::tsCryptoData contents;
	tscrypto::tsCryptoString path;
	tscrypto::tsCryptoString results;
	int64_t len;

	JsonConfigLocation foundHere = configExistsHere(configName, location);
	if (foundHere != jc_NotFound)
	{
		switch (foundHere)
		{
		case jc_Policy:
			buildAndTestPath(jc_Policy, configName, path);
			break;
		case jc_System:
			buildAndTestPath(jc_System, configName, path);
			break;
		case jc_User:
			buildAndTestPath(jc_User, configName, path);
			break;
		case jc_Public:
			buildAndTestPath(jc_Public, configName, path);
			break;
		case jc_ModuleFolder:
			buildAndTestPath(jc_ModuleFolder, configName, path);
			break;
		}
	}
	else
	{
		switch (location)
		{
		case jc_Policy:
			buildAndTestPath(jc_Policy, configName, path);
			break;
		case jc_System:
			buildAndTestPath(jc_System, configName, path);
			break;
		case jc_User:
			buildAndTestPath(jc_User, configName, path);
			break;
		case jc_Public:
			buildAndTestPath(jc_Public, configName, path);
			break;
		case jc_ModuleFolder:
			buildAndTestPath(jc_ModuleFolder, configName, path);
			break;
		default:
			break;
		}
	}

	XP_FILE file = XP_FILE_INVALID;

	int retryCount;

	if (!xp_FileExists(path.c_str()))
	{
		//CkmDebug(DBG_INFO1, "Unable to open the application configuration file for read '%s'.  The file does not exist.", path.c_str());
		return tmp;
	}
	for (retryCount = 0; retryCount < 10; retryCount++)
	{
		file = xp_CreateFile(path.c_str(), XP_GENERIC_READ, XP_FILE_SHARE_READ, NULL, XP_OPEN_EXISTING, XP_FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == XP_FILE_INVALID)
		{
			if (xp_GetLastError() != ERROR_SHARING_VIOLATION)
			{
				LOG(FrameworkError, "Unable to open the application configuration file for read " << path.c_str());
				//				CkmDebug(DBG_INFO1, "Unable to open the application configuration file for read '%s'.", path.c_str());
				return tmp;
			}
			XP_Sleep(100);
		}
		else
		{
			break;
		}
	}

	if (file == XP_FILE_INVALID)
	{
		LOG(FrameworkError, "Unable to open the application configuration file " << path.c_str() << " for read due to share violation.");
		//        CkmDebug(DBG_INFO1, "Unable to open the application configuration file '%s' for read due to share violation.", path.c_str());
		return tmp;
	}

	len = xp_GetFileSize64FromHandle(file);
	if (len == 0 || len > 1000000)
	{
		xp_CloseFile(file);
		return tmp;
	}
	contents.resize((unsigned int)len);
	uint32_t bytesRead;

	if (!xp_ReadFile(file, contents.rawData(), (uint32_t)len, &bytesRead, NULL) || bytesRead != (uint32_t)len)
	{
		LOG(FrameworkError, "Unable to read application configuration data " << path.c_str());
		//        CkmError("Unable to read application configuration data '%s'.", path.c_str());
		xp_CloseFile(file);
		return tmp;
	}
	xp_CloseFile(file);
	if (!tmp.FromJSON(contents.ToUtf8String().c_str()))
	{
		LOG(FrameworkError, "Unable to parse application configuration data.");
		//        CkmError("Unable to parse application configuration data.");
		tmp.clear();
	}
	return tmp;
}
bool tsJsonPreferencesBase::WriteJSONObject(const tscrypto::tsCryptoString& configName, JsonConfigLocation location, const JSONObject& obj)
{
	tscrypto::tsCryptoString path;

	switch (location)
	{
	case jc_Policy:
		buildAndTestPath(jc_Policy, configName, path);
		break;
	case jc_System:
		buildAndTestPath(jc_System, configName, path);
		break;
	case jc_User:
		buildAndTestPath(jc_User, configName, path);
		break;
	case jc_Public:
		buildAndTestPath(jc_Public, configName, path);
		break;
	case jc_ModuleFolder:
		buildAndTestPath(jc_ModuleFolder, configName, path);
		break;
	default:
		return false;
	}


	return xp_WriteText(path, obj.ToJSON());
}

void tsJsonPreferencesBase::ReadValueAsBool(JsonConfigLocation& loc, bool& value, const char *name, const JSONObject& config, JsonConfigLocation lookingAtLoc, bool defaultValue)
{
	if (loc == jc_Policy)
		return;

	const JSONElement* item = config.findSingleItem(name);
	if (item == nullptr)
		return;
	if (item->ElementType() != jet_Field)
		return;
	loc = lookingAtLoc;
	value = (reinterpret_cast<const JSONField*>(item))->AsBool(defaultValue);
}

void tsJsonPreferencesBase::ReadValueAsInt(JsonConfigLocation& loc, int& value, const char *name, const JSONObject& config, JsonConfigLocation lookingAtLoc, int defaultValue)
{
	if (loc == jc_Policy)
		return;

	const JSONElement* item = config.findSingleItem(name);
	if (item == nullptr)
		return;
	if (item->ElementType() != jet_Field)
		return;
	loc = lookingAtLoc;
	value = (int)(reinterpret_cast<const JSONField*>(item))->AsNumber(defaultValue);
}
void tsJsonPreferencesBase::ReadValueAsText(JsonConfigLocation& loc, tscrypto::tsCryptoString& value, const char *name, const JSONObject& config, JsonConfigLocation lookingAtLoc)
{
	if (loc == jc_Policy)
		return;

	const JSONElement* item = config.findSingleItem(name);
	if (item == nullptr)
		return;
	loc = lookingAtLoc;
	value = item->ToString();
}


bool tsJsonPreferencesBase::SaveBoolValue(JsonConfigLocation &loc, bool& value, const char* name, JSONObject& config, JsonConfigLocation locationToProcess)
{
	if (loc == locationToProcess)
	{
		JSONElement* element = config.findSingleItem(name, true);

		if (element == nullptr || element->ElementType() != jet_Field)
			return false;
		(reinterpret_cast<JSONField*>(element))->Value(value);
	}
	return true;
}

bool tsJsonPreferencesBase::SaveIntValue(JsonConfigLocation &loc, int& value, const char* name, JSONObject& config, JsonConfigLocation locationToProcess)
{
	if (loc == locationToProcess)
	{
		JSONElement* element = config.findSingleItem(name, true);

		if (element == nullptr || element->ElementType() != jet_Field)
			return false;
		(reinterpret_cast<JSONField*>(element))->Value((int64_t)value);
	}
	return true;
}

bool tsJsonPreferencesBase::SaveTextValue(JsonConfigLocation &loc, tscrypto::tsCryptoString& value, const char* name, JSONObject& config, JsonConfigLocation locationToProcess)
{
	if (loc == locationToProcess)
	{
		JSONElement* element = config.findSingleItem(name, true);

		if (element == nullptr)
			return false;
		if (element->ElementType() == jet_Field)
		{
			JSONField* fld = reinterpret_cast<JSONField*>(element);

			if (!value.empty() && value[0] == '{')
			{
				if (fld->Type() == JSONField::jsonNull)
				{
					JSONObject o;

					if (o.FromJSON(value.c_str()))
					{
						fld->Value(o);
					}
					else
						fld->Value(value);
				}
				else
					fld->Value(value);
			}
			else
				fld->Value(value);
		}
		else
		{
			JSONObject* obj = reinterpret_cast<JSONObject*>(element);

			obj->clear();
			return obj->FromJSON(value.c_str()) > 0;
		}
	}
	return true;
}

#pragma region SimpleJsonDebugPreferences
SimpleJsonDebugPreferences::SimpleJsonDebugPreferences(const tscrypto::tsCryptoString& configFileName, const char *root, JsonConfigLocation loc1, JsonConfigLocation loc2, JsonConfigLocation loc3) :
_configName(configFileName),
tsJsonPreferencesBase(loc1),
_root(root)
{
	if (loc2 != jc_NotFound)
		_location2 = loc2;
	if (loc3 != jc_NotFound)
		_location3 = loc3;
}

SimpleJsonDebugPreferences::~SimpleJsonDebugPreferences(void)
{
}

int SimpleJsonDebugPreferences::getEntrySearchCount() const
{
	return 1;
}
tscrypto::tsCryptoString SimpleJsonDebugPreferences::getEntrySearch(int index) const
{
	if (index < 0 || index >= getEntrySearchCount())
		return "";

	if (_root.size() > 0)
	{
		tscrypto::tsCryptoString name;

		name << "&$." << _root << ".Debug";
		return name;
	}
	return "&$.Debug";
}

tscrypto::tsCryptoString SimpleJsonDebugPreferences::GetDebugSettingsName()
{
	return getEntrySearch(0);
}

DEFINE_TEXT_PREF_CODE(SimpleJsonDebugPreferences, GetDebugSettingsName(), Debug, "")

std::shared_ptr<tsJsonPreferencesBase> SimpleJsonDebugPreferences::Create(const tscrypto::tsCryptoString& configFileName, const char *root, JsonConfigLocation loc1, JsonConfigLocation loc2, JsonConfigLocation loc3)
{
	std::shared_ptr<tsJsonPreferencesBase> obj = std::shared_ptr<tsJsonPreferencesBase>(new SimpleJsonDebugPreferences(configFileName, root, loc1, loc2, loc3));

	if (!obj)
		return nullptr;
	std::dynamic_pointer_cast<SimpleJsonDebugPreferences>(obj)->Me = obj;
	return obj;
}
#pragma endregion
