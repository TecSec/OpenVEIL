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

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \file   tsAppConfig.h
///
/// \brief  Defines the class that reads and writes an XML configuration file
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef tsAppConfig_H_INCLUDED
#define tsAppConfig_H_INCLUDED


/// <summary>reads and writes an XML configuration file</summary>
///
/// <remarks>All changes made with this class are held in memory.  To persist these changes you
/// 		 must call the tsAppConfig::Save function.</remarks>
class VEILCORE_API tsAppConfig
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

    /// <summary>Specifies the symbolic location(s) of the configuration file</summary>
    typedef enum {
		System, ///< Stored in the system folder
		Public, ///< Stored in the public (all users) documents folder
		User,  ///< Stored in the current user's documents folder
		SystemPublicUser, ///< Stored in the first of System, Public or User folder (obsolete - use classes based on tsPreferencesBase)
		UserPublicSystem, ///< Stored in the first of User, Public or System folder (obsolete - use classes based on tsPreferencesBase)
		UserPublic, ///< Stored in the first of User or Public folder (obsolete - use classes based on tsPreferencesBase)
		PublicUser, ///< Stored in the first of Public or User folder (obsolete - use classes based on tsPreferencesBase)
		NotFound, ///< The configuration file was not found
		Policy, ///< Stored in the Windows Policy folders
		ModuleFolder ///< Stored in the TSFrameword dll folder - useful in combination with the NonManifest version of the CKM Framework
	} ConfigLocation;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Determines the location of the configuration file</summary>
	///
	/// <param name="appName"> Name of the application.</param>
	/// <param name="location">The location set to search</param>
	///
	/// <returns>The location of where the file was found or NotFound otherwise</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	static ConfigLocation configExistsHere(const tscrypto::tsCryptoString &appName, ConfigLocation location);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Combines the application name and location to create the full filename for the configuration file.</summary>
	///
	/// <param name="appName"> Name of the application.</param>
	/// <param name="location">The location to use</param>
	///
	/// <returns>the full filename for the configuration file</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	static tscrypto::tsCryptoString filePath(const tscrypto::tsCryptoString &appName, ConfigLocation location);

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Object allocation operator.</summary>
    /////
    ///// <param name="bytes">The number of bytes to allocate.</param>
    /////
    ///// <returns>The allocated object.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //void *operator new(size_t bytes);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Object de-allocation operator.</summary>
    /////
    ///// <param name="ptr">[in,out] If non-null, the pointer to delete.</param>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //void operator delete(void *ptr);

public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Constructor.</summary>
    ///
    /// <param name="appName"> Name of the application.</param>
    /// <param name="location">The location.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsAppConfig(const tscrypto::tsCryptoString &appName, ConfigLocation location);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Constructor.</summary>
    ///
    /// <param name="appName">  Name of the application.</param>
    /// <param name="location"> The location.</param>
    /// <param name="buildHere">The build here.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsAppConfig(const tscrypto::tsCryptoString &appName, ConfigLocation location, ConfigLocation buildHere);
    /// <summary>Destructor.</summary>
    ~tsAppConfig();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the top level node as parsed from the XML configuration file.</summary>
    ///
    /// <returns>null if it fails, else the top level node</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> Root();
    /**
     * \brief Gets the root.
     *
     * \return null if it fails, else.
     */
	std::shared_ptr<tsXmlNode> Root() const;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Searches for the first node that matches the search path</summary>
    ///
    /// <param name="nodeName">Search path  of the node to find</param>
    /// <param name="buildIt"> true to build the node if it does not exist.</param>
    ///
    /// <returns>null if it fails, else the found node.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> findNode(const tscrypto::tsCryptoString &nodeName, bool buildIt);
    /**
     * \brief Searches for the first node that matches the search path.
     *
     * \param nodeName Name of the node.
     *
     * \return null if it fails, else the found node.
     */
	std::shared_ptr<tsXmlNode> findNode(const tscrypto::tsCryptoString &nodeName) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Searches for the all nodes that match the search criteria.</summary>
	///
	/// <param name="xpath">The search criteria.</param>
	///
	/// <returns>The found nodes.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsXmlNodeList findNodes(const tscrypto::tsCryptoString &xpath);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Searches for the all nodes that match the search criteria.</summary>
	///
	/// <param name="xpath">The search criteria.</param>
	///
	/// <returns>The found nodes.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsXmlNodeList findNodes(const tscrypto::tsCryptoString &xpath) const;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Adds a node to the XML configuration file and optionally allows you to add duplicates.</summary>
	///
	/// <param name="nodeName">Name of the node.</param>
	/// <param name="bUnique"> true to allow duplicate node names unique.</param>
	///
	/// <returns>null if it fails, else the node added to the configuration</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> addNode(const tscrypto::tsCryptoString &nodeName, bool bUnique);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Adds a node to the configuration or returns the existing node</summary>
    ///
    /// <param name="nodeName">Name of the node desired</param>
    ///
    /// <returns>null if it fails, else the node of that name</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> addNode(const tscrypto::tsCryptoString &nodeName);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes a named node from the configuration</summary>
    ///
    /// <param name="nodeName">Name of the node.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    void deleteNode(const tscrypto::tsCryptoString &nodeName);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Saves the current state (in memory) to the actual configuration file</summary>
    ///
    /// <remarks>All changes made with this class are held in memory.  To persist these changes you
    /// 		 must call this function.</remarks>
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    bool Save();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Retrieves the string value of an attribute from the named node</summary>
    ///
    /// <param name="nodeName">Name of the node.</param>
    /// <param name="itemName">Name of the attribute.</param>
    ///
    /// <returns>The value of the attribute</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tscrypto::tsCryptoString getNodeItem(const tscrypto::tsCryptoString &nodeName, const tscrypto::tsCryptoString &itemName) const;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Retrieves the integer value of an attribute from the named node or the default value.</summary>
    ///
    /// <param name="nodeName">	   Name of the node.</param>
    /// <param name="itemName">	   Name of the attribute.</param>
    /// <param name="defaultValue">The default value.</param>
    ///
    /// <returns>The integer value of the attribute or the default value if the node does not exist.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    int getNodeItemAsNumber(const tscrypto::tsCryptoString &nodeName, const tscrypto::tsCryptoString &itemName, int defaultValue) const;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Retrieves the boolean value of an attribute from the named node or the default value.</summary>
    ///
    /// <param name="nodeName">	   Name of the node.</param>
    /// <param name="itemName">	   Name of the attribute.</param>
    /// <param name="defaultValue">The default value.</param>
    ///
    /// <returns>The boolean value of the attribute or the default value if the node does not exist.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    bool getNodeItemAsBool(const tscrypto::tsCryptoString &nodeName, const tscrypto::tsCryptoString &itemName, bool defaultValue) const;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets or creates an attribute in the named node and sets the string value</summary>
    ///
    /// <param name="nodeName">Name of the node.</param>
    /// <param name="itemName">Name of the attribute.</param>
    /// <param name="value">   The value to set.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	bool setNodeItem(const tscrypto::tsCryptoString &nodeName, const tscrypto::tsCryptoString &itemName, const tscrypto::tsCryptoString &value);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets or creates an attribute in the named node and sets the integer value.</summary>
    ///
    /// <param name="nodeName">Name of the node.</param>
    /// <param name="itemName">Name of the attribute.</param>
    /// <param name="value">   The value to set.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	bool setNodeItemAsNumber(const tscrypto::tsCryptoString &nodeName, const tscrypto::tsCryptoString &itemName, int value);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets or creates an attribute in the named node and sets the boolean value.</summary>
    ///
    /// <param name="nodeName">Name of the node.</param>
    /// <param name="itemName">Name of the attribute.</param>
    /// <param name="value">   The value to set.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	bool setNodeItemAsBool(const tscrypto::tsCryptoString &nodeName, const tscrypto::tsCryptoString &itemName, bool value);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the text value for the named node</summary>
	///
	/// <param name="itemName"> Name of the item.</param>
	/// <param name="itemValue">The value to set.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool setNodeText(const tscrypto::tsCryptoString &itemName, const tscrypto::tsCryptoString &itemValue);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the integer value for the named node</summary>
	///
	/// <param name="itemName"> Name of the item.</param>
	/// <param name="itemValue">The value to set.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool setNodeTextAsNumber(const tscrypto::tsCryptoString &itemName, int value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the boolean value for the named node</summary>
	///
	/// <param name="itemName"> Name of the item.</param>
	/// <param name="itemValue">The value to set.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool setNodeTextAsBool(const tscrypto::tsCryptoString &itemName, bool value);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the node text for the named node.</summary>
	///
	/// <param name="itemName">Name of the node.</param>
	///
	/// <returns>The node text.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tscrypto::tsCryptoString getNodeText(const tscrypto::tsCryptoString &itemName) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the node text as an integer for the named node.</summary>
	///
	/// <param name="itemName">	   Name of the node.</param>
	/// <param name="defaultValue">The default value if the node does not exist or the text is empty.</param>
	///
	/// <returns>The node text as an integer.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int getNodeTextAsNumber(const tscrypto::tsCryptoString &itemName, int defaultValue) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the node text as a boolean for the named node.</summary>
	///
	/// <param name="itemName">	   Name of the node.</param>
	/// <param name="defaultValue">The default value if the node does not exist or the text is empty.</param>
	///
	/// <returns>The node text as a boolean.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool getNodeTextAsBool(const tscrypto::tsCryptoString &itemName, bool defaultValue) const;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the configuration file path.</summary>
	///
	/// <returns>The full path and file name for this configuration file</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tscrypto::tsCryptoString configFilePath() const;
protected:
	std::shared_ptr<tsXmlNode> m_root;
    tscrypto::tsCryptoString   m_path;
};

#endif // tsAppConfig_H_INCLUDED
