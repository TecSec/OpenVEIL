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

/*!
* \file tsJsonPreferencesBase.h
* \brief base class used to read/write configuration files and monitor the files for changes.
*/

#ifndef __TSJSONPREFERENCESBASE_H__
#define __TSJSONPREFERENCESBASE_H__

#pragma once

typedef enum {
	jc_NotFound, ///< The configuration file was not found
	jc_System, ///< Stored in the system folder
	jc_Public, ///< Stored in the public (all users) documents folder
	jc_User,  ///< Stored in the current user's documents folder
	jc_Policy, ///< Stored in the Windows Policy folders
	jc_ModuleFolder ///< Stored in the TSFrameword dll folder - useful in combination with the NonManifest version of the CKM Framework
} JsonConfigLocation;

struct VEILCORE_API JsonPreferenceItem
{
public:
    /**
     * \brief Default constructor.
     */
	JsonPreferenceItem() : Location(jc_NotFound){}
    /**
     * \brief Constructor.
     *
     * \param path	   Full pathname of the file.
     * \param value    The value.
     * \param location The location.
     */
	JsonPreferenceItem(const tscrypto::tsCryptoString &path, const tscrypto::tsCryptoString &value, JsonConfigLocation location) :
        Path(path), Value(value), Location(location){}
    /**
     * \brief Constructor.
     *
     * \param obj The object.
     */
	JsonPreferenceItem(const JsonPreferenceItem& obj) : Path(obj.Path), Value(obj.Value), Location(obj.Location) {}
    /**
     * \brief Assignment operator.
     *
     * \param obj The object.
     *
     * \return A shallow copy of this object.
     */
	JsonPreferenceItem &operator=(const JsonPreferenceItem& obj){ if (&obj != this){ Path = obj.Path; Value = obj.Value; Location = obj.Location; }return *this; }

    tscrypto::tsCryptoString Path; ///< Full pathname of the preference item
    tscrypto::tsCryptoString Value;	///< The value
	JsonConfigLocation Location; ///< The location

	/**
	 * \brief Query if this object references a node as an XML string.
	 *
	 * \return true if node, false if not.
	 */
	bool isNode() const { return Path[0] == '&'; }
    /**
     * \brief Query if this object is entry.
     *
     * \return true if entry, false if not.
     */
    bool isEntry() const { return !isNode() && Path.size() > 0; }
    /**
     * \brief Gets the attribute path.
     *
     * \return .
     */
    tscrypto::tsCryptoString ItemPath() const {
		if (isNode()) return &Path.c_str()[1];
		return Path;
	}
    /**
     * \brief Gets the value as number.
     *
     * \return .
     */
    int valueAsNumber() const { return TsStrToInt(Value); }
    /**
     * \brief Gets the value as int 64.
     *
     * \return .
     */
    int64_t valueAsInt64() const { return TsStrToInt64(Value); }
    /**
     * \brief Determines if we can value as bool.
     *
     * \return true if it succeeds, false if it fails.
     */
    bool valueAsBool() const { return TsStrToInt64(Value) != 0 || TsStriCmp(Value, "true") == 0; }
    /**
     * \brief Sets value as number.
     *
     * \param setTo The set to.
     */
    void setValueAsNumber(int setTo) { 	char buff[20]; Value.clear(); tscrypto::TsSnPrintf(buff, sizeof(buff) / sizeof(char), ("%d"), setTo); Value = buff; }
    /**
     * \brief Sets value as int 64.
     *
     * \param setTo The set to.
     */
    void setValueAsInt64(int64_t setTo) { 	char buff[60]; Value.clear(); tscrypto::TsSnPrintf(buff, sizeof(buff) / sizeof(char), ("%lld"), setTo); Value = buff; }
    /**
     * \brief Sets value as bool.
     *
     * \param setTo true to set to.
     */
    void setValueAsBool(bool setTo) { 	Value = setTo ? "true" : "false"; }
	bool operator==(const JsonPreferenceItem& obj) const { return TsStrCmp(Path, obj.Path) == 0; }
};

class tsJsonPreferencesBase;

#if defined(_WIN32) || defined(VEILCORE_EXPORTS)
#pragma warning(push)
#pragma warning(disable:4231)
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::ICryptoContainerWrapper<JsonPreferenceItem>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<tscrypto::ICryptoContainerWrapper<JsonPreferenceItem>>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::ICryptoContainerWrapper<std::shared_ptr<IPreferenceChangeNotify>>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<tscrypto::ICryptoContainerWrapper<std::shared_ptr<IPreferenceChangeNotify>>>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::weak_ptr<tsJsonPreferencesBase>;
#pragma warning(pop)
#endif // defined

typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<JsonPreferenceItem>> JsonPreferenceItemList;
typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<std::shared_ptr<IPreferenceChangeNotify>>> PreferenceChangeNotifyList;

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \class tsJsonPreferencesBase
///
/// <summary>This base class is used to provide access to JSON configuration files and monitor the files for changes.</summary>
///
/// <remarks>This class will read JSON configuration information from multiple configuration files and
/// 		 merge them together.  Up to four configuration files can bee read using this class.
/// 		 First the policy location is checked.  Then the primary, secondary and third locations
/// 		 (if not set to NotFound) are read in and merged.  Only entries that are not already found are
/// 		 merged into the whole.  This means that each entry is first come first served by default.</remarks>
////////////////////////////////////////////////////////////////////////////////////////////////////
class VEILCORE_API tsJsonPreferencesBase : public tsmod::IObject
{
protected:
	/**
	* \brief Constructor that sets the configuration locations
	*
	* \param location The location of the configuration files to use.
	*/
	tsJsonPreferencesBase(JsonConfigLocation location, JsonConfigLocation loc2 = jc_NotFound, JsonConfigLocation loc3 = jc_NotFound);
public:

	/// <summary>Scans for changes.</summary>
	virtual void ScanForChanges();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Registers the preferences change notification interface passed into handler.</summary>
	///
	/// <param name="handler">[in] the notification handler.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void registerPrefsChangeNotification(std::shared_ptr<IPreferenceChangeNotify> handler);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Unregisters the preferences change notification interface passed into handler.</summary>
	///
	/// <param name="handler">[in,out] the notification handler.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void unregisterPrefsChangeNotification(std::shared_ptr<IPreferenceChangeNotify> handler);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Saves the configuration changes.</summary>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool saveConfigurationChanges();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Determine if the configuration information is loaded.</summary>
	///
	/// <returns>true if values loaded, false if not.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool areValuesLoaded() const;
	/**
	* \brief Gets attribute entry search count.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual int getEntrySearchCount() const;
	/**
	* \brief Gets attribute entry search.
	*
	* \param index Zero-based index of the.
	*
	* \return The attribute entry search.
	*/
	virtual tscrypto::tsCryptoString getEntrySearch(int index) const;
	/**
	* \brief Gets preference item count.
	*
	* \return The preference item count.
	*/
	virtual int getPreferenceItemCount() const;
	/**
	* \brief Gets preference item.
	*
	* \param index Zero-based index of the item to retrieve.
	*
	* \return The preference item.
	*/
	virtual JsonPreferenceItem getPreferenceItem(int index) const;
	/**
	* \brief Searches for the first preference item that matches the specified path.
	*
	* \param path Full pathname of the file.
	*
	* \return The found preference item.
	*/
	virtual JsonPreferenceItem findPreferenceItem(const tscrypto::tsCryptoString &path) const;
	/**
	* \brief Sets preference item.
	*
	* \param item  The item.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool setPreferenceItem(const JsonPreferenceItem &item);
	/**
	* \brief Location level.
	*
	* \param location The location.
	*
	* \return .
	*/
	virtual int LocationLevel(JsonConfigLocation location) const;
	/**
	* \brief Loads the values.
	*
	* \return this object instance.
	*
	* This function controls the loading of the different configuration files. Normally this
	* function should not be overloaded.  Overload the loadValuesForLocation function instead.
	*
	* Make sure that when this function is overloaded that you call the base class.
	*/
	virtual tsJsonPreferencesBase *loadValues();
	/**
	* \brief Determines if the monitor is running.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool MonitorRunning() const;
	/// <summary>Starts the configuration change monitor.</summary>
	void StartMonitor();

	virtual tscrypto::tsCryptoString GetDebugSettingsName() { return "&$.Debug"; }

	static void ReadValueAsBool(JsonConfigLocation& loc, bool& value, const char *name, const tscrypto::JSONObject& config, JsonConfigLocation lookingAtLoc, bool defaultValue = false);
	static void ReadValueAsInt(JsonConfigLocation& loc, int& value, const char *name, const tscrypto::JSONObject& config, JsonConfigLocation lookingAtLoc, int defaultValue = 0);
	static void ReadValueAsText(JsonConfigLocation& loc, tscrypto::tsCryptoString& value, const char *name, const tscrypto::JSONObject& config, JsonConfigLocation lookingAtLoc);

	static bool SaveBoolValue(JsonConfigLocation &loc, bool& value, const char* name, tscrypto::JSONObject& config, JsonConfigLocation locationToProcess);
	static bool SaveIntValue(JsonConfigLocation &loc, int& value, const char* name, tscrypto::JSONObject& config, JsonConfigLocation locationToProcess);
	static bool SaveTextValue(JsonConfigLocation &loc, tscrypto::tsCryptoString& value, const char* name, tscrypto::JSONObject& config, JsonConfigLocation locationToProcess);

	static bool buildAndTestPath(JsonConfigLocation location, const tscrypto::tsCryptoString &appName, tscrypto::tsCryptoString &pathStr);
	static JsonConfigLocation configExistsHere(const tscrypto::tsCryptoString &appName, JsonConfigLocation location);
	static tscrypto::tsCryptoString filePath(const tscrypto::tsCryptoString &appName, JsonConfigLocation location);

protected:
	/// <summary>Destructor.</summary>
	virtual ~tsJsonPreferencesBase(void);

	/// <summary>Sets default values.</summary> <remarks>Make sure that when this function is overloaded that you call the base class.</remarks>
	virtual void setDefaultValues() { m_valuesLoaded = false; };

	/**
	* \brief Loads values for the given configuration location.
	*
	* \param location The configuration location to check.
	* \param config   The configuration.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool loadValuesForLocation(JsonConfigLocation location, const tscrypto::JSONObject &config) = 0;
	/**
	* \brief Loads the values.
	*
	* \param location The location.
	* \param config   The configuration.
	*
	* \return true if it succeeds, false if it fails.
	*/
	bool loadValues(JsonConfigLocation location);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the base configuration file name.</summary>
	///
	/// <returns>the configuration file name</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tscrypto::tsCryptoString ConfigName() { return "default"; }
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the location of the primary configuration file</summary>
	///
	/// <returns>primary configuration file location</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual JsonConfigLocation Location() const { return _location1; }
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the second configuration file location</summary>
	///
	/// <returns>second configuration file location</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual JsonConfigLocation SecondLocation() const { return _location2; }
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the third location.</summary>
	///
	/// <returns>third configuration file location</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual JsonConfigLocation ThirdLocation() const { return _location3; }
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Saves the configuration changes for the given location.</summary>
	///
	/// <param name="location">The location to save.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool saveConfigurationChangesForLocation(JsonConfigLocation location) = 0;
	/**
	* \brief Saves the configuration changes.
	*
	* \param location The location.
	*
	* \return true if it succeeds, false if it fails.
	*/
	bool saveConfigurationChanges(JsonConfigLocation location);
	/**
	* \brief Loads preferences for location.
	*
	* \param location The location.
	* \param config   The configuration.
	*
	* \return true if it succeeds, false if it fails.
	*/
	bool loadPreferencesForLocation(JsonConfigLocation location, tscrypto::JSONObject &config);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the location that will be used for new entries in the .</summary>
	///
	/// <returns>the default save location</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual JsonConfigLocation DefaultSaveLocation() const;

	/// <summary>Disconnects this object.</summary>
	virtual void Disconnect();
	/// <summary>Configures this object for change monitoring.</summary>
	virtual void prepareForMonitoring();
	/**
	* \brief Overwrite entry.
	*
	* \param entryName		  Name of the entry.
	* \param currentLocation The current location.
	* \param newLocation	  The new location.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool OverwriteEntry(const tscrypto::tsCryptoString &entryName, JsonConfigLocation currentLocation, JsonConfigLocation newLocation) const;
	/**
	* \brief Determines if we must use entries.
	*
	* \return true if entries are to be automatically used, false if not.
	*/
	virtual bool UseEntries() const = 0;
	/**
	* \brief Raises the global change event.
	*/
	void FireGlobalChangeEvent();

	static tscrypto::JSONObject ReadJSONObject(const tscrypto::tsCryptoString& configName, JsonConfigLocation location);
	static bool WriteJSONObject(const tscrypto::tsCryptoString& configName, JsonConfigLocation location, const tscrypto::JSONObject& obj);
protected:
	tscrypto::tsCryptoString m_policyFilename;  /*!< \brief Path and file name for the policy configuration file */
	tscrypto::tsCryptoString m_firstFilename;    /*!< \brief Path and file name for the first level configuration file */
	tscrypto::tsCryptoString m_secondFilename;  /*!< \brief Path and file name for the second level configuration file */
	tscrypto::tsCryptoString m_thirdFilename;  /*!< \brief Path and file name for the third level configuration file */
#ifdef _WIN32
	WIN32_FILE_ATTRIBUTE_DATA m_policyFileInfo;  /*!< \brief directory information for the policy configuration file that is used to detect changes */
	WIN32_FILE_ATTRIBUTE_DATA m_firstFileInfo;    /*!< \brief directory information for the first level configuration file that is used to detect changes */
	WIN32_FILE_ATTRIBUTE_DATA m_secondFileInfo;  /*!< \brief directory information for the second level configuration file that is used to detect changes */
	WIN32_FILE_ATTRIBUTE_DATA m_thirdFileInfo;  /*!< \brief directory information for the third level configuration file that is used to detect changes */
#else
	struct stat m_policyFileInfo;
	struct stat m_firstFileInfo;
	struct stat m_secondFileInfo;
	struct stat m_thirdFileInfo;
#endif
	PreferenceChangeNotifyList m_notifierList; /*!< \brief The list of objects that are to be notified when a change is detected */
	bool m_valuesLoaded;	/*!< \brief Indicates that the configuration values have been loaded */
	JsonPreferenceItemList _preferenceItems; ///< \brief The preference items found by this class
	JsonConfigLocation _location1;
	JsonConfigLocation _location2;
	JsonConfigLocation _location3;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Holds the change scanner.</summary>
	///
	/// <value>The change scanner.</value>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<ChangeTracker> m_changeScanner;
	std::weak_ptr<tsJsonPreferencesBase> Me;
};

#pragma region Support macros
#define DEFINE_BOOL_PREF_CODE(className,path,name,defaultValue) \
	bool className::get##name(){ loadValues(); JsonPreferenceItem item = this->findPreferenceItem(path); if (item.Location == jc_NotFound)return defaultValue; return item.valueAsBool(); } \
	void className::set##name(bool setTo){ loadValues(); JsonPreferenceItem item = this->findPreferenceItem(path); if (item.Location != jc_Policy){ item.setValueAsBool(setTo); item.Location = DefaultSaveLocation(); setPreferenceItem(item); } } \
	JsonConfigLocation className::name##Location(){ loadValues(); JsonPreferenceItem item = this->findPreferenceItem(path); return item.Location; }

#define DEFINE_INT_PREF_CODE(className,path,name,defaultValue) \
	int className::get##name(){loadValues();JsonPreferenceItem item = this->findPreferenceItem(path);if (item.Location == jc_NotFound)return defaultValue;return item.valueAsNumber();} \
	void className::set##name(int setTo){loadValues();JsonPreferenceItem item = this->findPreferenceItem(path);if (item.Location != jc_Policy){item.setValueAsNumber(setTo);item.Location = DefaultSaveLocation();setPreferenceItem(item);}} \
	JsonConfigLocation className::name##Location(){loadValues();JsonPreferenceItem item = this->findPreferenceItem(path);return item.Location;}

#define DEFINE_TEXT_PREF_CODE(className,path,name,defaultValue) \
	tscrypto::tsCryptoString className::get##name(){loadValues();JsonPreferenceItem item = this->findPreferenceItem(path);if (item.Location == jc_NotFound)return defaultValue;return item.Value;} \
	void className::set##name(const tscrypto::tsCryptoString &setTo){loadValues();JsonPreferenceItem item = this->findPreferenceItem(path);if (item.Location != jc_Policy){item.Value = setTo;item.Location = DefaultSaveLocation();setPreferenceItem(item);}} \
	JsonConfigLocation className::name##Location(){loadValues();JsonPreferenceItem item = this->findPreferenceItem(path);return item.Location;}

#define DEFINE_ENUM_PREF_CODE(className,path,name,enumName,defaultValue) \
	enumName className::get##name(){loadValues();JsonPreferenceItem item = this->findPreferenceItem(path);if (item.Location == jc_NotFound)return defaultValue;return (enumName)item.valueAsNumber();} \
	void className::set##name(enumName setTo){loadValues();JsonPreferenceItem item = this->findPreferenceItem(path);if (item.Location != jc_Policy){item.setValueAsNumber(setTo);item.Location = DefaultSaveLocation();setPreferenceItem(item);}} \
	JsonConfigLocation className::name##Location(){loadValues();JsonPreferenceItem item = this->findPreferenceItem(path);return item.Location;}


#define DEFINE_DATA_PREF_CODE(className,path,name) \
	tscrypto::tsCryptoData className::get##name(){loadValues();JsonPreferenceItem item = this->findPreferenceItem(path);if (item.Location == jc_NotFound)return tscrypto::tsCryptoData();return item.Value.Base64ToData();} \
	void className::set##name(const tscrypto::tsCryptoData &setTo){loadValues();JsonPreferenceItem item = this->findPreferenceItem(path);if (item.Location != jc_Policy){item.Value = setTo.ToBase64();item.Location = DefaultSaveLocation();setPreferenceItem(item);}} \
	JsonConfigLocation className::name##Location(){loadValues();JsonPreferenceItem item = this->findPreferenceItem(path);return item.Location;}


#define DECLARE_BOOL_PREF_CODE(name) \
	bool get##name(); \
	void set##name(bool setTo); \
	JsonConfigLocation name##Location();

#define DECLARE_INT_PREF_CODE(name) \
	int get##name(); \
	void set##name(int setTo); \
	JsonConfigLocation name##Location();

#define DECLARE_BASE_TYPE_PREF_CODE(name,type) \
	type get##name(); \
	void set##name(type setTo); \
	JsonConfigLocation name##Location();

#define DECLARE_TEXT_PREF_CODE(name) \
	tscrypto::tsCryptoString get##name(); \
	void set##name(const tscrypto::tsCryptoString& setTo); \
	JsonConfigLocation name##Location();

#define DECLARE_DATA_PREF_CODE(name) \
	tscrypto::tsCryptoData get##name(); \
	void set##name(const tscrypto::tsCryptoData& setTo); \
	JsonConfigLocation name##Location();

#pragma endregion


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Provides access to and change monitoring for debug preferences.</summary>
///
/// <seealso cref="CKMPreferencesBase"/>
////////////////////////////////////////////////////////////////////////////////////////////////////
class VEILCORE_API SimpleJsonDebugPreferences : public tsJsonPreferencesBase
{
public:
	static std::shared_ptr<tsJsonPreferencesBase> Create(const tscrypto::tsCryptoString& configFileName, const char *root = "", JsonConfigLocation loc1 = jc_System, JsonConfigLocation loc2 = jc_NotFound, JsonConfigLocation loc3 = jc_NotFound);
	/// <summary>Destructor.</summary>
	virtual ~SimpleJsonDebugPreferences(void);

protected:
	/// <summary>Default constructor.</summary>
	SimpleJsonDebugPreferences(const tscrypto::tsCryptoString& configFileName, const char *root = "", JsonConfigLocation loc1 = jc_System, JsonConfigLocation loc2 = jc_NotFound, JsonConfigLocation loc3 = jc_NotFound);

	/// <summary>Sets the default values for these options.</summary>
	//virtual void setDefaultValues();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the configuration name.</summary>
	///
	/// <returns>the configuration name..</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoString ConfigName() { return _configName; }

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Saves the configuration changes for the specified location.</summary>
	///
	/// <param name="location">The location.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool saveConfigurationChangesForLocation(JsonConfigLocation location){ MY_UNREFERENCED_PARAMETER(location); return true; }
	//virtual bool saveConfigurationChangesForLocation(JsonConfigLocation location);
	/**
	 * \brief Loads configuration values for the specified location.
	 *
	 * \param location The location.
	 * \param config   The configuration.
	 *
	 * \return true if it succeeds, false if it fails.
	 */
	virtual bool loadValuesForLocation(JsonConfigLocation location, const tscrypto::JSONObject &config) { MY_UNREFERENCED_PARAMETER(location); MY_UNREFERENCED_PARAMETER(config); return true; }
	//virtual bool loadValuesForLocation(JsonConfigLocation location, const tscrypto::JSONObject &config);
	/**
	 * \brief Determines if we can use entries.
	 *
	 * \return true if it succeeds, false if it fails.
	 */
	virtual bool UseEntries(void) const { return true; }
	/**
	* \brief Gets attribute entry search count.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual int getEntrySearchCount() const;
	/**
	* \brief Gets attribute entry search.
	*
	* \param index Zero-based index of the.
	*
	* \return The attribute entry search.
	*/
	virtual tscrypto::tsCryptoString getEntrySearch(int index) const;
	virtual tscrypto::tsCryptoString GetDebugSettingsName();

	DECLARE_TEXT_PREF_CODE(Debug)
protected:
    tscrypto::tsCryptoString _configName;
	tscrypto::tsCryptoString _root;
};

/*! @brief Reports the Ckm Enabled Application that was changed */
class VEILCORE_API IJsonPreferenceChangeEvent : public ICkmChangeEvent
{
public:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the CKM enabled application name that was changed.</summary>
	///
	/// <param name="name">[in,out] The name.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsJsonPreferencesBase* GetPreferencesObject() = 0;
};



#endif // __TSJSONPREFERENCESBASE_H__

