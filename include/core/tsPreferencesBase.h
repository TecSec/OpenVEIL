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
* \file tsPreferencesBase.h
* \brief base class used to read/write configuration files and monitor the files for changes.
*/

#ifndef __TSPREFERENCESBASE_H__
#define __TSPREFERENCESBASE_H__

#pragma once

#ifdef SUPPORT_XML_LOGGING
PUSH_WARNINGS
IGNORE_WARNING(TS_DEPRECATED_WARNING)

struct DEPRECATED VEILCORE_API PreferenceItem
{
public:
	static void *operator new(std::size_t count) {
		return tscrypto::cryptoNew(count);
	}
	static void *operator new[](std::size_t count) {
		return tscrypto::cryptoNew(count);
	}
	static void operator delete(void *ptr) { tscrypto::cryptoDelete(ptr); }
	static void operator delete[](void *ptr) { tscrypto::cryptoDelete(ptr); }

    /**
     * \brief Default constructor.
     */
		PreferenceItem() : Location(tsAppConfig::NotFound) {}
    /**
     * \brief Constructor.
     *
     * \param path	   Full pathname of the file.
     * \param value    The value.
     * \param location The location.
     */
    PreferenceItem(const tscrypto::tsCryptoString &path, const tscrypto::tsCryptoString &value, tsAppConfig::ConfigLocation location) :
		Path(path), Value(value), Location(location) {}
    /**
     * \brief Constructor.
     *
     * \param obj The object.
     */
    PreferenceItem(const PreferenceItem& obj) : Path(obj.Path), Value(obj.Value), Location(obj.Location) {}
    /**
     * \brief Assignment operator.
     *
     * \param obj The object.
     *
     * \return A shallow copy of this object.
     */
	PreferenceItem &operator=(const PreferenceItem& obj) { if (&obj != this) { Path = obj.Path;Value = obj.Value;Location = obj.Location; }return *this; }

    tscrypto::tsCryptoString Path; ///< Full pathname of the preference item
    tscrypto::tsCryptoString Value;	///< The value
    tsAppConfig::ConfigLocation Location; ///< The location

    /**
     * \brief Query if this object is attribute.
     *
     * \return true if attribute, false if not.
     */
    bool isAttribute() const { return Path.find(']') == (int)Path.size() - 1 && Path.find('[') != tsCryptoString:npos && Path.find(']') > Path.find('['); }
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
    bool isEntry() const { return !isAttribute() && !isNode() && Path.size() > 0; }
    /**
     * \brief Gets the attribute path.
     *
     * \return .
     */
    tscrypto::tsCryptoString AttributePath() const {
        if (isEntry()) return Path;
		if (isNode()) return &Path.c_str()[1];
        return (*Path.split("["))[0];
    }
    tscrypto::tsCryptoString AttributeName() const {
        if (isEntry() || isNode()) return "";
        return (*(*Path.split("["))[1].split("]"))[0];
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
    bool valueAsBool() const { return TsStrToInt64(Value) != 0; }
    /**
     * \brief Sets value as number.
     *
     * \param setTo The set to.
     */
    void setValueAsNumber(int setTo) { 	char buff[20]; Value.clear(); TsSnPrintf(buff, sizeof(buff) / sizeof(char), ("%d"), setTo); Value = buff; }
    /**
     * \brief Sets value as int 64.
     *
     * \param setTo The set to.
     */
    void setValueAsInt64(int64_t setTo) { 	char buff[60]; Value.clear(); TsSnPrintf(buff, sizeof(buff) / sizeof(char), ("%lld"), setTo); Value = buff; }
    /**
     * \brief Sets value as bool.
     *
     * \param setTo true to set to.
     */
    void setValueAsBool(bool setTo) { 	Value = setTo ? "1" : "0"; }
	bool operator==(const PreferenceItem& obj) const { return TsStrCmp(Path, obj.Path) == 0; }
};

class tsPreferencesBase;

PUSH_WARNINGS
IGNORE_WARNING(TS_DEPRECATED_WARNING)

#if defined(_WIN32) || defined(VEILCORE_EXPORTS)
#pragma warning(push)
#pragma warning(disable:4231)
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::ICryptoContainerWrapper<PreferenceItem>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<tscrypto::ICryptoContainerWrapper<PreferenceItem>>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::weak_ptr<tsPreferencesBase>;
#pragma warning(pop)
#endif // defined

POP_WARNINGS

typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<PreferenceItem>> PreferenceItemList;

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \class tsPreferencesBase
///
/// <summary>This base class is used to provide access to configuration files and monitor the files for changes.</summary>
///
/// <remarks>This class will read configuration information from multiple configuration files and
/// 		 merge them together.  Up to four configuration files can bee read using this class.
/// 		 First the policy location is checked.  Then the primary, secondary and third locations
/// 		 (if not set to NotFound) are read in and merged.  Only entries that are not already found are
/// 		 merged into the whole.  This means that each entry is first come first served by default.</remarks>
////////////////////////////////////////////////////////////////////////////////////////////////////
class DEPRECATED VEILCORE_API tsPreferencesBase : public tsmod::IObject
{
protected:
	/**
	 * \brief Constructor that sets the configuration locations
	 *
	 * \param location The location of the configuration files to use.
	 */
	tsPreferencesBase(tsAppConfig::ConfigLocation location);
public:
  static void *operator new(std::size_t count) {
	return tscrypto::cryptoNew(count);
  }
  static void *operator new[](std::size_t count) {
	return tscrypto::cryptoNew(count);
  }
  static void operator delete(void *ptr) { tscrypto::cryptoDelete(ptr); }
  static void operator delete[](void *ptr) { tscrypto::cryptoDelete(ptr); }

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
    virtual PreferenceItem getPreferenceItem(int index) const;
    /**
    * \brief Searches for the first preference item that matches the specified path.
    *
    * \param path Full pathname of the file.
    *
    * \return The found preference item.
    */
    virtual PreferenceItem findPreferenceItem(const tscrypto::tsCryptoString &path) const;
    /**
    * \brief Sets preference item.
    *
    * \param item  The item.
    *
    * \return true if it succeeds, false if it fails.
    */
    virtual bool setPreferenceItem(const PreferenceItem &item);
    /**
    * \brief Location level.
    *
    * \param location The location.
    *
    * \return .
    */
    virtual int LocationLevel(tsAppConfig::ConfigLocation location) const;
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
    virtual tsPreferencesBase *loadValues();
	/**
	 * \brief Determines if the monitor is running.
	 *
	 * \return true if it succeeds, false if it fails.
	 */
	virtual bool MonitorRunning() const;
    /// <summary>Starts the configuration change monitor.</summary>
	void StartMonitor();
  protected:
    /// <summary>Destructor.</summary>
    virtual ~tsPreferencesBase(void);

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
    virtual bool loadValuesForLocation(tsAppConfig::ConfigLocation location, const tsAppConfig &config) = 0;
    /**
     * \brief Loads the values.
     *
     * \param location The location.
     * \param config   The configuration.
     *
     * \return true if it succeeds, false if it fails.
     */
    bool loadValues(tsAppConfig::ConfigLocation location);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the base configuration file name.</summary>
    ///
    /// <returns>the configuration file name</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoString ConfigName() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the location of the primary configuration file</summary>
    ///
    /// <returns>primary configuration file location</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsAppConfig::ConfigLocation Location() const { return _location1; }
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the second configuration file location</summary>
    ///
    /// <returns>second configuration file location</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsAppConfig::ConfigLocation SecondLocation() const { return _location2; }
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the third location.</summary>
    ///
    /// <returns>third configuration file location</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsAppConfig::ConfigLocation ThirdLocation() const { return _location2; }
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Saves the configuration changes for the given location.</summary>
    ///
    /// <param name="location">The location to save.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool saveConfigurationChangesForLocation(tsAppConfig::ConfigLocation location) = 0;
    /**
     * \brief Saves the configuration changes.
     *
     * \param location The location.
     *
     * \return true if it succeeds, false if it fails.
     */
    bool saveConfigurationChanges(tsAppConfig::ConfigLocation location);
    /**
     * \brief Loads preferences for location.
     *
     * \param location The location.
     * \param config   The configuration.
     *
     * \return true if it succeeds, false if it fails.
     */
    bool loadPreferencesForLocation(tsAppConfig::ConfigLocation location, tsAppConfig &config);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the location that will be used for new entries in the .</summary>
    ///
    /// <returns>the default save location</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsAppConfig::ConfigLocation DefaultSaveLocation() const;

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
    virtual bool OverwriteEntry(const tscrypto::tsCryptoString &entryName, tsAppConfig::ConfigLocation currentLocation, tsAppConfig::ConfigLocation newLocation) const;
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

  protected:
    long m_lRefCount;
    tscrypto::tsCryptoString m_policyFilename;  /*!< \brief Path and file name for the policy configuration file */
    tscrypto::tsCryptoString m_systemFilename;  /*!< \brief Path and file name for the system level configuration file */
    tscrypto::tsCryptoString m_publicFilename;  /*!< \brief Path and file name for the public level configuration file */
    tscrypto::tsCryptoString m_userFilename;    /*!< \brief Path and file name for the user level configuration file */
  #ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA m_policyFileInfo;  /*!< \brief directory information for the policy configuration file that is used to detect changes */
    WIN32_FILE_ATTRIBUTE_DATA m_userFileInfo;    /*!< \brief directory information for the system level configuration file that is used to detect changes */
    WIN32_FILE_ATTRIBUTE_DATA m_publicFileInfo;  /*!< \brief directory information for the public level configuration file that is used to detect changes */
    WIN32_FILE_ATTRIBUTE_DATA m_systemFileInfo;  /*!< \brief directory information for the user level configuration file that is used to detect changes */
  #else
    struct stat m_policyFileInfo;
    struct stat m_userFileInfo;
    struct stat m_publicFileInfo;
    struct stat m_systemFileInfo;
  #endif
	PreferenceChangeNotifyList m_notifierList; /*!< \brief The list of objects that are to be notified when a change is detected */
    bool m_valuesLoaded;	/*!< \brief Indicates that the configuration values have been loaded */
	PreferenceItemList _preferenceItems; ///< \brief The preference items found by this class
	tsAppConfig::ConfigLocation _location1;
	tsAppConfig::ConfigLocation _location2;
	tsAppConfig::ConfigLocation _location3;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Holds the change scanner.</summary>
    ///
    /// <value>The change scanner.</value>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    std::shared_ptr<ChangeTracker> m_changeScanner;
	std::weak_ptr<tsPreferencesBase> Me;
};


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Provides access to and change monitoring for debug preferences.</summary>
///
/// <seealso cref="CKMPreferencesBase"/>
////////////////////////////////////////////////////////////////////////////////////////////////////
class DEPRECATED VEILCORE_API SimpleDebugPreferences : public tsPreferencesBase
{
public:
	static std::shared_ptr<tsPreferencesBase> Create(const tscrypto::tsCryptoString& configFileName, tsAppConfig::ConfigLocation loc1 = tsAppConfig::System, tsAppConfig::ConfigLocation loc2 = tsAppConfig::NotFound, tsAppConfig::ConfigLocation loc3 = tsAppConfig::NotFound);

protected:
	/// <summary>Default constructor.</summary>
	SimpleDebugPreferences(const tscrypto::tsCryptoString& configFileName, tsAppConfig::ConfigLocation loc1 = tsAppConfig::System, tsAppConfig::ConfigLocation loc2 = tsAppConfig::NotFound, tsAppConfig::ConfigLocation loc3 = tsAppConfig::NotFound);
	/// <summary>Destructor.</summary>
	virtual ~SimpleDebugPreferences(void);

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
	virtual bool saveConfigurationChangesForLocation(tsAppConfig::ConfigLocation location) { UNREFERENCED_PARAMETER(location); return true; }
	//virtual bool saveConfigurationChangesForLocation(tsAppConfig::ConfigLocation location);
	/**
	 * \brief Loads configuration values for the specified location.
	 *
	 * \param location The location.
	 * \param config   The configuration.
	 *
	 * \return true if it succeeds, false if it fails.
	 */
	virtual bool loadValuesForLocation(tsAppConfig::ConfigLocation location, const tsAppConfig &config) { UNREFERENCED_PARAMETER(location); UNREFERENCED_PARAMETER(config); return true; }
	//virtual bool loadValuesForLocation(tsAppConfig::ConfigLocation location, const tsAppConfig &config);
	/**
	 * \brief Determines if we can use entries.
	 *
	 * \return true if it succeeds, false if it fails.
	 */
	virtual bool UseEntries(void) const { return true; }

protected:
    tscrypto::tsCryptoString _configName;
};

/*! @brief Reports the Ckm Enabled Application that was changed */
class DEPRECATED HIDDEN ICkmPreferenceChangeEvent : public ICkmChangeEvent
{
public:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the CKM enabled application name that was changed.</summary>
	///
	/// <param name="name">[in,out] The name.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsPreferencesBase* GetPreferencesObject() = 0;
};
POP_WARNINGS

#endif // SUPPORT_XML_LOGGING

#endif // __TSPREFERENCESBASE_H__

