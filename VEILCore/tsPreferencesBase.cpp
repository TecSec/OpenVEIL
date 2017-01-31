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

#ifdef SUPPORT_XML_LOGGING

static const char *gEntries[] = { "&Debug" };

PUSH_WARNINGS
IGNORE_WARNING(TS_DEPRECATED_WARNING)

class HIDDEN CkmPreferenceChangeEvent : public CkmChangeEventCore, public ICkmPreferenceChangeEvent, public tsmod::IObject
{
public:
	CkmPreferenceChangeEvent(std::shared_ptr<tsPreferencesBase> obj) :
		m_obj(obj) {};
	virtual ~CkmPreferenceChangeEvent() {}

	virtual CKMChangeType   GetChangeType()
	{
		return CKMChange_Preferences;
	}
	//
	virtual tsPreferencesBase* GetPreferencesObject()
	{
		return m_obj.get();
	}
private:
	std::shared_ptr<tsPreferencesBase> m_obj;
};


tsPreferencesBase::tsPreferencesBase(tsAppConfig::ConfigLocation location) :
m_lRefCount(0),
m_valuesLoaded(false),
_location1(tsAppConfig::NotFound),
_location2(tsAppConfig::NotFound),
_location3(tsAppConfig::NotFound)
{
	m_notifierList = CreateContainer<std::shared_ptr<IPreferenceChangeNotify>>();
	_preferenceItems = CreateContainer<PreferenceItem>();
	switch (location)
	{
	case tsAppConfig::PublicUser:
		_location1 = tsAppConfig::Public;
		_location2 = tsAppConfig::User;
		break;
	case tsAppConfig::SystemPublicUser:
		_location1 = tsAppConfig::System;
		_location2 = tsAppConfig::Public;
		_location3 = tsAppConfig::User;
		break;
	case tsAppConfig::UserPublicSystem:
		_location1 = tsAppConfig::User;
		_location2 = tsAppConfig::Public;
		_location3 = tsAppConfig::System;
		break;
	case tsAppConfig::UserPublic:
		_location1 = tsAppConfig::User;
		_location2 = tsAppConfig::Public;
		break;
	default:
		_location1 = location;
		break;
	}
	memset(&m_policyFileInfo, 0, sizeof(m_policyFileInfo));
	memset(&m_userFileInfo, 0, sizeof(m_userFileInfo));
	memset(&m_publicFileInfo, 0, sizeof(m_publicFileInfo));
	memset(&m_systemFileInfo, 0, sizeof(m_systemFileInfo));
}

tsPreferencesBase::~tsPreferencesBase(void)
{
	if (!!m_changeScanner)
	{
		m_changeScanner->Disconnect();
		m_changeScanner.reset();
	}
}

void tsPreferencesBase::Disconnect()
{
	if (!!m_changeScanner)
	{
		m_changeScanner->Disconnect();
	}
}

bool tsPreferencesBase::MonitorRunning() const
{
	return !!m_changeScanner;
}

void tsPreferencesBase::StartMonitor()
{
	if (!!m_changeScanner)
	{
		return;
	}

	prepareForMonitoring();

	m_changeScanner = ::TopServiceLocator()->Finish<ChangeTracker>(new ChangeTracker(std::dynamic_pointer_cast<ICkmChangeProducer>(_me.lock())));
}

void tsPreferencesBase::prepareForMonitoring()
{
	m_policyFilename = tsAppConfig::filePath(ConfigName(), tsAppConfig::Policy);
	if (ThirdLocation() != tsAppConfig::NotFound)
		m_systemFilename = tsAppConfig::filePath(ConfigName(), ThirdLocation());
	if (SecondLocation() != tsAppConfig::NotFound)
		m_publicFilename = tsAppConfig::filePath(ConfigName(), SecondLocation());
	if (Location() != tsAppConfig::NotFound)
		m_userFilename = tsAppConfig::filePath(ConfigName(), Location());

	if (m_policyFilename.length() > 0)
	{
#ifdef _WIN32
		GetFileAttributesExA(m_policyFilename.c_str(), GetFileExInfoStandard, &m_policyFileInfo);
#else
		stat(m_policyFilename.c_str(), &m_policyFileInfo);
#endif // _WIN32
	}
	if (m_userFilename.length() > 0)
	{
#ifdef _WIN32
		GetFileAttributesExA(m_userFilename.c_str(), GetFileExInfoStandard, &m_userFileInfo);
#else
		stat(m_userFilename.c_str(), &m_userFileInfo);
#endif // _WIN32
	}
	if (m_publicFilename.length() > 0)
	{
#ifdef _WIN32
		GetFileAttributesExA(m_publicFilename.c_str(), GetFileExInfoStandard, &m_publicFileInfo);
#else
		stat(m_publicFilename.c_str(), &m_publicFileInfo);
#endif // _WIN32
	}
	if (m_systemFilename.length() > 0)
	{
#ifdef _WIN32
		GetFileAttributesExA(m_systemFilename.c_str(), GetFileExInfoStandard, &m_systemFileInfo);
#else
		stat(m_systemFilename.c_str(), &m_systemFileInfo);
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

void tsPreferencesBase::FireGlobalChangeEvent()
{
	if (!!gChangeMonitor)
	{
		std::shared_ptr<ICkmChangeEvent> evt = ::TopServiceLocator()->Finish<ICkmChangeEvent>(new CkmPreferenceChangeEvent(std::dynamic_pointer_cast<tsPreferencesBase>(_me.lock())));
		gChangeMonitor->RaiseChange(evt);
	}
}

void tsPreferencesBase::ScanForChanges()
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
	if (!changeDetected && m_systemFilename.length() != 0)
	{
		WIN32_FILE_ATTRIBUTE_DATA test;

		memset(&test, 0, sizeof(test));
		GetFileAttributesExA(m_systemFilename.c_str(), GetFileExInfoStandard, &test);
		changeDetected = infoDifferent(test, m_systemFileInfo);
	}
	if (!changeDetected && m_publicFilename.length() != 0)
	{
		WIN32_FILE_ATTRIBUTE_DATA test;

		memset(&test, 0, sizeof(test));
		GetFileAttributesExA(m_publicFilename.c_str(), GetFileExInfoStandard, &test);
		changeDetected = infoDifferent(test, m_publicFileInfo);
	}
	if (!changeDetected && m_userFilename.length() != 0)
	{
		WIN32_FILE_ATTRIBUTE_DATA test;

		memset(&test, 0, sizeof(test));
		GetFileAttributesExA(m_userFilename.c_str(), GetFileExInfoStandard, &test);
		changeDetected = infoDifferent(test, m_userFileInfo);
	}
	if (changeDetected)
	{
		setDefaultValues();
		loadValues();

		if (m_policyFilename.length() > 0)
		{
			GetFileAttributesExA(m_policyFilename.c_str(), GetFileExInfoStandard, &m_policyFileInfo);
		}
		if (m_userFilename.length() > 0)
		{
			GetFileAttributesExA(m_userFilename.c_str(), GetFileExInfoStandard, &m_userFileInfo);
		}
		if (m_publicFilename.length() > 0)
		{
			GetFileAttributesExA(m_publicFilename.c_str(), GetFileExInfoStandard, &m_publicFileInfo);
		}
		if (m_systemFilename.length() > 0)
		{
			GetFileAttributesExA(m_systemFilename.c_str(), GetFileExInfoStandard, &m_systemFileInfo);
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
	if (!changeDetected && m_systemFilename.length() != 0)
	{
		struct stat test;

		memset (&test, 0, sizeof(test));
		stat(m_systemFilename.c_str(), &test);
		changeDetected = infoDifferent(test, m_systemFileInfo);
	}
	if (!changeDetected && m_publicFilename.length() != 0)
	{
		struct stat test;

		memset (&test, 0, sizeof(test));
		stat(m_publicFilename.c_str(), &test);
		changeDetected = infoDifferent(test, m_publicFileInfo);
	}
	if (!changeDetected && m_userFilename.length() != 0)
	{
		struct stat test;

		memset (&test, 0, sizeof(test));
		stat(m_userFilename.c_str(), &test);
		changeDetected = infoDifferent(test, m_userFileInfo);
	}
	if (changeDetected)
	{
		setDefaultValues();
		loadValues();

		if (m_policyFilename.length() > 0)
		{
			stat(m_policyFilename.c_str(), &m_policyFileInfo);
		}
		if (m_userFilename.length() > 0)
		{
			stat(m_userFilename.c_str(), &m_userFileInfo);
		}
		if (m_publicFilename.length() > 0)
		{
			stat(m_publicFilename.c_str(), &m_publicFileInfo);
		}
		if (m_systemFilename.length() > 0)
		{
			stat(m_systemFilename.c_str(), &m_systemFileInfo);
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

void tsPreferencesBase::registerPrefsChangeNotification(std::shared_ptr<IPreferenceChangeNotify> handler)
{
	m_notifierList->erase(std::remove_if(m_notifierList->begin(), m_notifierList->end(), [&handler](std::shared_ptr<IPreferenceChangeNotify> notify) { return notify == handler;}), m_notifierList->end());
	//m_notifierList->remove(handler);
	m_notifierList->push_back(handler);
	StartMonitor();

	if (!areValuesLoaded())
	{
		loadValues();
	}
	}

void tsPreferencesBase::unregisterPrefsChangeNotification(std::shared_ptr<IPreferenceChangeNotify> handler)
{
	m_notifierList->erase(std::remove_if(m_notifierList->begin(), m_notifierList->end(), [&handler](std::shared_ptr<IPreferenceChangeNotify> notify) { return notify == handler;}), m_notifierList->end());
	//m_notifierList->remove(handler);
}

bool tsPreferencesBase::loadValues(tsAppConfig::ConfigLocation location)
{
	bool retVal = true;

	if (tsAppConfig::configExistsHere(ConfigName(), location) == tsAppConfig::NotFound)
		return true;

	tsAppConfig cfg(ConfigName(), location);

	if (UseEntries())
		retVal = loadPreferencesForLocation(location, cfg) | retVal;
	retVal = loadValuesForLocation(location, cfg) | retVal;
	return retVal;
}

tsPreferencesBase* tsPreferencesBase::loadValues()
{
	bool retVal = false;

	if (m_valuesLoaded)
		return this;

	_preferenceItems->clear();
	m_policyFilename = tsAppConfig::filePath(ConfigName(), tsAppConfig::Policy);
	if (ThirdLocation() != tsAppConfig::NotFound)
		m_systemFilename = tsAppConfig::filePath(ConfigName(), ThirdLocation());
	if (SecondLocation() != tsAppConfig::NotFound)
		m_publicFilename = tsAppConfig::filePath(ConfigName(), SecondLocation());
	if (Location() != tsAppConfig::NotFound)
		m_userFilename = tsAppConfig::filePath(ConfigName(), Location());

	setDefaultValues();

	if (m_policyFilename.size() > 0 && tsAppConfig::configExistsHere(ConfigName(), tsAppConfig::Policy) == tsAppConfig::Policy)
	{
		retVal = loadValues(tsAppConfig::Policy) | retVal;
	}

	switch (Location())
	{
	case tsAppConfig::System:
		retVal = loadValues(tsAppConfig::System) | retVal;
		break;
	case tsAppConfig::ModuleFolder:
		retVal = loadValues(tsAppConfig::ModuleFolder) | retVal;
		break;
	case tsAppConfig::Public:
		retVal = loadValues(tsAppConfig::Public) | retVal;
		break;
	case tsAppConfig::User:
		retVal = loadValues(tsAppConfig::User) | retVal;
		break;
	case tsAppConfig::SystemPublicUser:
		retVal = loadValues(tsAppConfig::System) | retVal;
		retVal = loadValues(tsAppConfig::Public) | retVal;
		retVal = loadValues(tsAppConfig::User) | retVal;
		break;
	case tsAppConfig::UserPublicSystem:
		retVal = loadValues(tsAppConfig::User) | retVal;
		retVal = loadValues(tsAppConfig::Public) | retVal;
		retVal = loadValues(tsAppConfig::System) | retVal;
		break;
	case tsAppConfig::UserPublic:
		retVal = loadValues(tsAppConfig::User) | retVal;
		retVal = loadValues(tsAppConfig::Public) | retVal;
		break;
	case tsAppConfig::PublicUser:
		retVal = loadValues(tsAppConfig::Public) | retVal;
		retVal = loadValues(tsAppConfig::User) | retVal;
		break;
	}

	if (SecondLocation() != tsAppConfig::NotFound)
		retVal = loadValues(SecondLocation()) | retVal;

	if (ThirdLocation() != tsAppConfig::NotFound)
		retVal = loadValues(ThirdLocation()) | retVal;

	m_valuesLoaded = true;
	return this;
}

bool tsPreferencesBase::saveConfigurationChanges(tsAppConfig::ConfigLocation location)
{
	bool retVal = true;

	if (UseEntries())
	{
		int count = getPreferenceItemCount();
		bool hasOneForLocation = false;

		for (int i = 0; !hasOneForLocation && i < count; i++)
		{
			hasOneForLocation = (_preferenceItems->at(i).Location == location);
		}
		if (hasOneForLocation)
		{
			tsAppConfig cfg(ConfigName(), location);

			//
			// First remove all tracked entries
			//
			count = getEntrySearchCount();
			for (int i = 0; i < count; i++)
			{
				PreferenceItem pref(getEntrySearch(i), "", location);

				tsXmlNodeList list = cfg.findNodes("./" + pref.AttributePath());

				for (std::shared_ptr<tsXmlNode>& node : *list)
				{
					node->Parent().lock()->RemoveChild(node); 
				}
			}

			//
			// Now add the entries that we currently have
			//
			count = getPreferenceItemCount();

			for (int i = 0; i < count; i++)
			{
				if (location != tsAppConfig::Policy && _preferenceItems->at(i).Location == location)
				{
					if (_preferenceItems->at(i).isAttribute())
					{
						std::shared_ptr<tsXmlNode> node = cfg.findNode(_preferenceItems->at(i).AttributePath(), true);
						if (node == NULL)
							return false;
						if (!node->Attributes().AddItem(_preferenceItems->at(i).AttributeName(), _preferenceItems->at(i).Value))
							return false;
					}
					else if (_preferenceItems->at(i).isNode())
					{
						std::shared_ptr<tsXmlNode> node = cfg.findNode(_preferenceItems->at(i).AttributePath(), true);
						tscrypto::tsCryptoString Results;

						if (node == NULL)
							return false;
						node->ClearAll();
						if (!node->Parse(_preferenceItems->at(i).Value, Results, false, false))
							return false;
					}
					else
					{
						if (!cfg.setNodeText(_preferenceItems->at(i).Path, _preferenceItems->at(i).Value))
							return false;
					}
				}
			}
			cfg.Save();
		}
		else if (location != tsAppConfig::Policy && tsAppConfig::configExistsHere(ConfigName(), location) != tsAppConfig::NotFound)
		{
			xp_DeleteFile(tsAppConfig::filePath(ConfigName(), location));
		}
	}
	else
		retVal = saveConfigurationChangesForLocation(location) | retVal;
	return retVal;
}

bool tsPreferencesBase::saveConfigurationChanges()
{
	bool retVal = true;

	switch (Location())
	{
	case tsAppConfig::System:
		retVal = saveConfigurationChanges(tsAppConfig::System) & retVal;
		break;
	case tsAppConfig::ModuleFolder:
		retVal = saveConfigurationChanges(tsAppConfig::ModuleFolder) & retVal;
		break;
	case tsAppConfig::Public:
		retVal = saveConfigurationChanges(tsAppConfig::Public) & retVal;
		break;
	case tsAppConfig::User:
		retVal = saveConfigurationChanges(tsAppConfig::User) & retVal;
		break;
	case tsAppConfig::SystemPublicUser:
		retVal = saveConfigurationChanges(tsAppConfig::User) & retVal;
		retVal = saveConfigurationChanges(tsAppConfig::Public) & retVal;
		retVal = saveConfigurationChanges(tsAppConfig::System) & retVal;
		break;
	case tsAppConfig::UserPublicSystem:
		retVal = saveConfigurationChanges(tsAppConfig::System) & retVal;
		retVal = saveConfigurationChanges(tsAppConfig::Public) & retVal;
		retVal = saveConfigurationChanges(tsAppConfig::User) & retVal;
		break;
	case tsAppConfig::UserPublic:
		retVal = saveConfigurationChanges(tsAppConfig::Public) & retVal;
		retVal = saveConfigurationChanges(tsAppConfig::User) & retVal;
		break;
	case tsAppConfig::PublicUser:
		retVal = saveConfigurationChanges(tsAppConfig::User) & retVal;
		retVal = saveConfigurationChanges(tsAppConfig::Public) & retVal;
		break;
	}

	if (SecondLocation() != tsAppConfig::NotFound)
		retVal = saveConfigurationChanges(SecondLocation()) & retVal;

	if (ThirdLocation() != tsAppConfig::NotFound)
		retVal = saveConfigurationChanges(ThirdLocation()) & retVal;

	return retVal;
}

tsAppConfig::ConfigLocation tsPreferencesBase::DefaultSaveLocation() const
{
	switch (Location())
	{
	case tsAppConfig::ModuleFolder:
		return tsAppConfig::ModuleFolder;
	case tsAppConfig::System:
	case tsAppConfig::SystemPublicUser:
		return tsAppConfig::System;
	case tsAppConfig::PublicUser:
	case tsAppConfig::Public:
		return tsAppConfig::Public;
	case tsAppConfig::UserPublic:
	case tsAppConfig::UserPublicSystem:
	case tsAppConfig::User:
	default:
		return tsAppConfig::User;
	}
}

bool tsPreferencesBase::areValuesLoaded() const
{
	return m_valuesLoaded;
}

bool tsPreferencesBase::OverwriteEntry(const tscrypto::tsCryptoString &entryName, tsAppConfig::ConfigLocation currentLocation, tsAppConfig::ConfigLocation newLocation) const
{
	UNREFERENCED_PARAMETER(entryName);

	if (currentLocation == tsAppConfig::Policy)
		return false;
	if (LocationLevel(newLocation) > 0 && (currentLocation == tsAppConfig::NotFound || LocationLevel(currentLocation) >= LocationLevel(newLocation)))
		return true;
	return false;
}

int tsPreferencesBase::getEntrySearchCount() const
{
	return sizeof(gEntries) / sizeof(gEntries[0]);
}

tscrypto::tsCryptoString tsPreferencesBase::getEntrySearch(int index) const
{
	if (index < 0 || index >= getEntrySearchCount())
		return "";

	return gEntries[index];
}

int tsPreferencesBase::getPreferenceItemCount() const
{
	return (int)_preferenceItems->size();
}

PreferenceItem tsPreferencesBase::getPreferenceItem(int index) const
{
	return _preferenceItems->at(index);
}

PreferenceItem tsPreferencesBase::findPreferenceItem(const tscrypto::tsCryptoString &path) const
{
	int count = getPreferenceItemCount();

	for (int i = 0; i < count; i++)
	{
		PreferenceItem item = getPreferenceItem(i);
		if (TsStriCmp(item.Path, path) == 0)
			return item;
	}
	return PreferenceItem(path, "", tsAppConfig::NotFound);
}

bool tsPreferencesBase::setPreferenceItem(const PreferenceItem &item)
{
	int count = getPreferenceItemCount();

	for (int i = 0; i < count; i++)
	{
		PreferenceItem itm = getPreferenceItem(i);
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

int tsPreferencesBase::LocationLevel(tsAppConfig::ConfigLocation location) const
{
	if (location == Location())
		return 1;
	if (location == SecondLocation() && SecondLocation() != tsAppConfig::NotFound)
		return 2;
	if (location == ThirdLocation() && ThirdLocation() != tsAppConfig::NotFound)
		return 3;
	return 0;
}

bool tsPreferencesBase::loadPreferencesForLocation(tsAppConfig::ConfigLocation location, tsAppConfig &config)
{
	int count = getEntrySearchCount();

	for (int i = 0; i < count; i++)
	{
		tscrypto::tsCryptoString searchItem = getEntrySearch(i);
		std::shared_ptr<tsXmlNode> node;

		PreferenceItem item(searchItem, "", location);
		node = config.findNode(item.AttributePath(), false);

		if (node != nullptr)
		{
			if (item.isNode())
			{
				tscrypto::tsCryptoString tmp;

				if (node->BuildXML(tmp, true))
				{
					item.Value = tmp;
				}
			}
			else if (item.isAttribute())
			{
				if (!node->Attributes().hasItem(item.AttributeName()))
					continue;
				item.Value = node->Attributes().item(item.AttributeName());
			}
			else
			{
				item.Value = node->NodeText();
			}
			_preferenceItems->push_back(item);
		}
	}
	return true;
}


#pragma region SimpleDebugPreferences
SimpleDebugPreferences::SimpleDebugPreferences(const tscrypto::tsCryptoString& configFileName, tsAppConfig::ConfigLocation loc1, tsAppConfig::ConfigLocation loc2, tsAppConfig::ConfigLocation loc3) :
_configName(configFileName),
tsPreferencesBase(loc1)
{
	if (loc2 != tsAppConfig::NotFound)
		_location2 = loc2;
	if (loc3 != tsAppConfig::NotFound)
		_location3 = loc3;
}

SimpleDebugPreferences::~SimpleDebugPreferences(void)
{
}

std::shared_ptr<tsPreferencesBase> SimpleDebugPreferences::Create(const tscrypto::tsCryptoString& configFileName, tsAppConfig::ConfigLocation loc1, tsAppConfig::ConfigLocation loc2, tsAppConfig::ConfigLocation loc3)
{
	std::shared_ptr<tsPreferencesBase> obj = ::TopServiceLocator()->Finish<tsPreferencesBase>(new SimpleDebugPreferences(configFileName, loc1, loc2, loc3));

	if (!obj)
		return nullptr;
	std::dynamic_pointer_cast<SimpleDebugPreferences>(obj)->Me = obj;
	return obj;
}
#pragma endregion

POP_WARNINGS

#endif // SUPPORT_XML_LOGGING
