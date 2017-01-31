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

/*! @file tsXmlNode.h
 * @brief This file defines an object that contains the information for a single XML node
*/

#if !defined(AFX_TSXMLNODE_H__4A8A5CCE_A10B_4D5D_9D5A_7E47EB7D18F1__INCLUDED_)
#define AFX_TSXMLNODE_H__4A8A5CCE_A10B_4D5D_9D5A_7E47EB7D18F1__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

//#include "tsXmlError.h"
#include "tsXmlParser.h"

#define IDS_E_XML_GENERAL_ERROR 3000  /*!< \brief XML Error Number: Indicates that a general error has occurred */
#define IDS_E_XML_CANT_GENERATE 3001  /*!< \brief XML Error Number: Indicates that an error occurred while generating some value */
#define IDS_E_XML_CANT_DECRYPT  3002  /*!< \brief XML Error Number: Indicates that an error occurred while decrypting some value */

class tsXmlNode;

#define ATTRIBUTE_RSEARCH 'A' /*!< \brief The character to search for in reverse to find attribute nodes */
#define ATTRIBUTE_SUFFIX "Att" /*!< \grief The full string to search for in reverse to find attribute nodes */

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr < tsXmlNode >;

VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::ICryptoContainerWrapper<std::shared_ptr<tsXmlNode>>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<tscrypto::ICryptoContainerWrapper<std::shared_ptr<tsXmlNode>>>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::ICryptoContainerWrapper<std::shared_ptr<tsXmlError>>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<tscrypto::ICryptoContainerWrapper<std::shared_ptr<tsXmlError>>>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::weak_ptr < tsXmlNode >;
#pragma warning(pop)
#endif // defined

/// <summary>Defines an alias representing list of XML nodes.</summary>
typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<std::shared_ptr<tsXmlNode>>> tsXmlNodeList;
/// <summary>Defines an alias representing list of XML errors.</summary>
typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<std::shared_ptr<tsXmlError>>> tsXmlErrorList;

//
// Manages a collection of namespaces
//
class VEILCORE_API NamespaceSupport
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

	NamespaceSupport();
	~NamespaceSupport();
	virtual void extractNamespaceAttributes(tsAttributeMap &attrs);
	tscrypto::tsCryptoString getDefaultNamespace() const;
	tscrypto::tsCryptoString getEBNamespaceName() const;
	tscrypto::tsCryptoString getSoap12NamespaceName() const;
	bool EbNamespaceIsDefault() const;
	void addNamespacesToAttributeList(tsAttributeMap &attrs);
	void addNamespace(const tscrypto::tsCryptoStringBase& name, const tscrypto::tsCryptoStringBase& value);
	void removeDefaultNamespace();

private:
	tsAttributeMap m_namespaces;
};

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>This class holds the data for one parsed XML node.</summary>
///
/// <seealso cref="T:tsXmlParserCallback"/>
////////////////////////////////////////////////////////////////////////////////////////////////////
class VEILCORE_API tsXmlNode : public tsXmlParserCallback, public tsmod::IObject
{
public:
	typedef enum attributeNodeType { attribute, textNode, suffixedWithAtt } attributeNodeType;

	//IMPLEMENT_GENERIC_INDEXED_ITERATORS(tsXmlNode, int, ChildrenCount, ChildAt);

	/// <summary>Destructor.</summary>
	virtual ~tsXmlNode();

	static std::shared_ptr<tsXmlNode> Create();

protected:
	/// <summary>Default constructor.</summary>
	tsXmlNode();
public:
	/**
	 * \brief Removes all namespaces.
	 */
	void RemoveAllNamespaces();
	/**
	 * \brief Converts this object tree into the JSON format.
	 *
	 * \param attributesAreVariables true if attributes are variables.
	 *
	 * \return a JSONField that contains this node and all of its children.
	 */
	tscrypto::JSONField ToJSON(bool attributesAreVariables) const;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Creates a child node in this node using the specified name and attributes.</summary>
	///
	/// <param name="name">The name.</param>
	/// <param name="map"> The attributes.</param>
	///
	/// <returns>null if it fails, else the newly created child node.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual std::shared_ptr<tsXmlNode> StartSubnode(const tscrypto::tsCryptoStringBase &name, const tsAttributeMap &map);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Creates a child node in this node using the specified name.</summary>
	///
	/// <param name="name">The name.</param>
	///
	/// <returns>null if it fails, else the newly created child node.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual std::shared_ptr<tsXmlNode> StartSubnode(const tscrypto::tsCryptoStringBase &name);
	/**
	 * \brief Starts text subnode.
	 *
	 * \param name The name.
	 * \param text The text contents of the new subnode.
	 *
	 * \return null if it fails, else a tsXmlNode*.
	 */
	virtual std::shared_ptr<tsXmlNode> StartTextSubnode(const tscrypto::tsCryptoStringBase &name, const tscrypto::tsCryptoStringBase& text);
	virtual std::shared_ptr<tsXmlNode> StartTextSubnode(const tscrypto::tsCryptoStringBase &name, bool setTo);
	virtual std::shared_ptr<tsXmlNode> StartTextSubnode(const tscrypto::tsCryptoStringBase &name, const char* setTo);
	virtual std::shared_ptr<tsXmlNode> StartTextSubnode(const tscrypto::tsCryptoStringBase &name, int setTo);
	virtual std::shared_ptr<tsXmlNode> StartTextSubnode(const tscrypto::tsCryptoStringBase &name, int64_t setTo);
	virtual std::shared_ptr<tsXmlNode> StartTextSubnode(const tscrypto::tsCryptoStringBase &name, size_t setTo);
	virtual std::shared_ptr<tsXmlNode> StartTextSubnode(const tscrypto::tsCryptoStringBase &name, const tscrypto::tsCryptoData& setTo);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the parent XML node.</summary>
	///
	/// <returns>null if this is the top node, else the parent.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::weak_ptr<tsXmlNode> Parent() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the node name.</summary>
	///
	/// <returns>The node name.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const tscrypto::tsCryptoString &NodeName() const;
	tscrypto::tsCryptoString NodeNamespace() const;
	tscrypto::tsCryptoString NodeLocalName() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the node name.</summary>
	///
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void NodeName(const tscrypto::tsCryptoStringBase &);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the node text.</summary>
	///
	/// <returns>The node text.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tscrypto::tsCryptoString NodeText() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the node text as a number.</summary>
	///
	/// <returns>the node text as a number.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int NodeTextAsNumber() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the node text as a number.</summary>
	///
	/// <param name="setTo">The value to set.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void NodeTextAsNumber(int setTo);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the node text as a boolean.</summary>
	///
	/// <returns>the node text as a boolean.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool NodeTextAsBool() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the node text as a boolean.</summary>
	///
	/// <param name="setTo">The value to set.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void NodeTextAsBool(bool setTo);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Determines if this node should be indented for human readability.</summary>
	///
	/// <returns>true if indentation is required, false otherwise.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool UseFormattedOutput() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the UseFormattedOutput flag.</summary>
	///
	/// <param name="setTo">true if indentation is required, false otherwise.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void UseFormattedOutput(bool setTo);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the node text</summary>
	///
	/// <param name="setTo">The value to set.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool NodeText(const tscrypto::tsCryptoStringBase &setTo);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Appends text to this node.</summary>
	///
	/// <param name="setTo">The value to append.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool AppendText(const tscrypto::tsCryptoStringBase &setTo);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Copies the information and optionally the children from the specified object into this object.</summary>
	///
	/// <param name="srcNode">	  [in] The source node to copy.</param>
	/// <param name="bDoChildren">(optional) If true copy the children.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void CopyFrom(std::shared_ptr<tsXmlNode> srcNode, bool bDoChildren = true);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the attributes.</summary>
	///
	/// <returns>The attributes.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsAttributeMap &Attributes();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the attributes.</summary>
	///
	/// <returns>The attributes.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const tsAttributeMap &Attributes() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Performs the task identified by this node.</summary>
	///
	/// <param name="Results">[in,out] The results.</param>
	/// <param name="useAttributesForErrors">Error attribute flag.</param?
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool Run(tscrypto::tsCryptoStringBase &Results, bool useAttributesForErrors);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Validate this node for its intended task.</summary>
	///
	/// <param name="Results">[in,out] The results.</param>
	/// <param name="useAttributesForErrors">Error attribute flag.</param?
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool Validate(tscrypto::tsCryptoStringBase &Results, bool useAttributesForErrors);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the list of children.</summary>
	///
	/// <returns>null if it fails, else a list of child XML nodes.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsXmlNodeList& Children();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the list of children.</summary>
	///
	/// <returns>null if it fails, else a list of child XML nodes.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const tsXmlNodeList& Children() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns the child at the specified index.</summary>
	///
	///
	/// <returns>null if it fails, else the child.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> ChildAt(const size_t);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns the child at the specified index.</summary>
	///
	///
	/// <returns>null if it fails, else the child.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> ChildAt(const size_t) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns if this node has been processed.  Used in the CkmEBClient runtime component
	/// and applications like EnterpriseBuilder.</summary>
	///
	/// <returns>true if it has been processed, false otherwise.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool Processed() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Query if this object has errors.</summary>
	///
	/// <returns>true if errors, false if not.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool HasErrors() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Query if this object has warnings.</summary>
	///
	/// <returns>true if warnings, false if not.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool HasWarnings() const;
	/// <summary>Clears all data from this node including errors, warnings and children.</summary>
	void ClearAll();
	/// <summary>Clears the errors from this node.</summary>
	void ClearErrors();
	/// <summary>Clears the warnings from this node.</summary>
	void ClearWarnings();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the number of children.</summary>
	///
	/// <returns>The number of children in this node.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	size_t ChildrenCount() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the error list.</summary>
	///
	/// <param name="recursive">true to process recursively, false to process locally only.</param>
	///
	/// <returns>The error list.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsXmlErrorList GetErrorList(bool recursive) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the warning list.</summary>
	///
	/// <param name="recursive">true to process recursively, false to process locally only.</param>
	///
	/// <returns>The warning list.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsXmlErrorList GetWarningList(bool recursive) const;
	/// <summary>Clears the children.</summary>
	virtual void ClearChildren();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Extracts the child at the specified index and prepares it to be included into a
	/// different XML tree.</summary>
	///
	///
	/// <returns>null if it fails, else the extracted child.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> ExtractChild(const size_t);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Removes and deletes the child at the specified index.</summary>
	///
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void RemoveChild(const size_t);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Removes and deletes the specified child.</summary>
	///
	/// <param name="pChild">The child to delete.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void RemoveChild(std::shared_ptr<tsXmlNode> pChild);
	void AddChild(std::shared_ptr<tsXmlNode> pChild);
	//	virtual bool RequiresHash();
	//	void RequiresHash(bool setTo);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Determines if this node requires protection.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool RequiresProtection() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets a flag that indicates that this node requires protection</summary>
	///
	/// <param name="setTo">true to set to.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void RequiresProtection(bool setTo);
	//    void HashValue(const tsByteString &hash);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets a flag that causes this node to create a Document Object Model.</summary>
		///
		/// <remarks>If the make DOM flag is false then any child nodes are not parsed as XML but are
		/// stored as text within this node.</remarks>
		///
		////////////////////////////////////////////////////////////////////////////////////////////////////
	void MakeDOM(bool);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns the make DOM flag</summary>
	///
	/// <returns>true if a DOM shall be created (default), false otherwise.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool MakeDOM() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the error count.</summary>
	///
	/// <returns>The number of errors in this node.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	size_t ErrorCount() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns the error at the specified index</summary>
	///
	/// <returns>null if it fails, else the error object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const std::shared_ptr<tsXmlError> ErrorAt(size_t) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Convert all errors for this node and its children into a string and return it.</summary>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool MigrateErrors(tscrypto::tsCryptoStringBase&);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the warning count.</summary>
	///
	/// <returns>The number of warnings.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	size_t WarningCount() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns the warning at the specified index</summary>
	///
	/// <returns>null if it fails, else the error object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const std::shared_ptr<tsXmlError> WarningAt(size_t) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Convert all warnings for this node and its children into a string and return it.</summary>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool MigrateWarnings(tscrypto::tsCryptoStringBase&);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Determines if this node wants any contained XML in the XMLContents property.</summary>
	///
	/// <returns>true if the inner XML shall be put into the XMLContents property, false otherwise.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool WantsXMLContents() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the flag to indicate that inner XML shall be put into the XMLContents property.</summary>
	///
	/// <param name="setTo">true if the inner XML shall be put into the XMLContents property, false
	/// otherwise.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void WantsXMLContents(bool setTo);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the XML contents.</summary>
	///
	/// <returns>the XML contents.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const tscrypto::tsCryptoString &XMLContents() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the XML contents.</summary>
	///
	/// <param name="setTo">The contents to set.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool XMLContents(const tscrypto::tsCryptoStringBase &setTo);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Determines if this node wants text contents.</summary>
	///
	/// <returns>true if text contents are to be put into the NodeText property, false otherwise.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool WantsTextContents() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the flag to indicate that this node wants text contents</summary>
	///
	/// <param name="setTo">true if text contents are to be put into the NodeText property, false otherwise.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void WantsTextContents(bool setTo);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Adds an error to this node.</summary>
	///
	/// <param name="comp">The component.</param>
	/// <param name="meth">The method.</param>
	/// <param name="desc">The description.</param>
	/// <param name="num"> The error number.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void AddError(const tscrypto::tsCryptoStringBase &comp, const tscrypto::tsCryptoStringBase &meth, const tscrypto::tsCryptoStringBase &desc, int32_t num = 2000);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Adds an error to the front of the error list for this node.</summary>
	///
	/// <param name="comp">The component.</param>
	/// <param name="meth">The method.</param>
	/// <param name="desc">The description.</param>
	/// <param name="num"> The error number.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void AddFirstError(const tscrypto::tsCryptoStringBase &comp, const tscrypto::tsCryptoStringBase &meth, const tscrypto::tsCryptoStringBase &desc, int32_t num);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Adds an error to the specified string.</summary>
	///
	/// <param name="Results">[in,out] The string that shall have the error appended.</param>
	/// <param name="Number"> The error number.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void _AddError(tscrypto::tsCryptoStringBase &Results, int32_t Number, ...);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the has errors flag.</summary>
	///
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void HasErrors(bool);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the has warnings flag.</summary>
	///
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void HasWarnings(bool);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns an indication if reauthentication is required.</summary>
	///
	/// <returns>true if reauthentication is required.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool NeedsReauthentication() const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Child by searching for the first child with an attribute names 'TSID' containing the indicated value.</summary>
	///
	/// <returns>null if not found, else the child</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> ChildByTSID(const tscrypto::tsCryptoStringBase&) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Child by searching for the first child with a node name matching the indicated value.</summary>
	///
	/// <param name="name">The node name to search for.</param>
	///
	/// <returns>null if not found, else the child</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> ChildByName(const tscrypto::tsCryptoStringBase &name) const;
	tsXmlNodeList ChildrenByName(const tscrypto::tsCryptoStringBase &name) const;
	/**
	 * \brief Gets the text from the named child node.
	 *
	 * <param name="name">The child node text.</param>
	 *
	 * \return The named child node text.
	 */
	tscrypto::tsCryptoString GetNamedChildNodeText(const tscrypto::tsCryptoStringBase &name) const;
	/**
	 * \brief Sets the text in the named child or creates a new child node.
	 *
	 * \param name  The name.
	 * \param value The value.
	 */
	void SetNamedChildNodeText(const tscrypto::tsCryptoStringBase& name, const tscrypto::tsCryptoStringBase& value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Child by searching for the first child with a node name matching the indicated value
	/// and with a matching attribute name and value.</summary>
	///
	/// <param name="name">			 The node name to search for.</param>
	/// <param name="attributeName"> Name of the attribute.</param>
	/// <param name="attributeValue">The attribute value.</param>
	///
	/// <returns>null if not found, else the child.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> ChildByNameWithAttributeValue(const tscrypto::tsCryptoStringBase &name, const tscrypto::tsCryptoStringBase &attributeName, const tscrypto::tsCryptoStringBase &attributeValue) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Child by searching for the first child with a node name matching the indicated value
	/// and with a matching attribute name and value.</summary>
	///
	/// <param name="name">			 The node name to search for.</param>
	/// <param name="attributeName"> Name of the attribute.</param>
	/// <param name="attributeValue">The attribute value.</param>
	///
	/// <returns>null if not found, else the child.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> ChildByNameWithAttributeValueExact(const tscrypto::tsCryptoStringBase &name, const tscrypto::tsCryptoStringBase &attributeName, const tscrypto::tsCryptoStringBase &attributeValue) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Search for the first child whos name matches the specified name by searching all
	/// children and their children recursively.</summary>
	///
	/// <param name="name">The node name.</param>
	///
	/// <returns>null if it fails, else.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> ChildByNameRecursive(const tscrypto::tsCryptoStringBase &name) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Child by searching for the first child with an attribute names 'TSID' containing the
	/// indicated value.</summary>
	///
	/// <returns>null if not found, else the child.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> ChildByTSID(const tscrypto::tsCryptoStringBase&);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Child by searching for the first child with a node name matching the indicated value.</summary>
	///
	/// <param name="name">The node name to search for.</param>
	///
	/// <returns>null if not found, else the child.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> ChildByName(const tscrypto::tsCryptoStringBase &name);
	tsXmlNodeList ChildrenByName(const tscrypto::tsCryptoStringBase &name);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Child by searching for the first child with a node name matching the indicated value
	/// and with a matching attribute name and value.</summary>
	///
	/// <param name="name">			 The node name to search for.</param>
	/// <param name="attributeName"> Name of the attribute.</param>
	/// <param name="attributeValue">The attribute value.</param>
	///
	/// <returns>null if not found, else the child.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> ChildByNameWithAttributeValue(const tscrypto::tsCryptoStringBase &name, const tscrypto::tsCryptoStringBase &attributeName, const tscrypto::tsCryptoStringBase &attributeValue);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Child by searching for the first child with a node name matching the indicated value
	/// and with a matching attribute name and value.</summary>
	///
	/// <param name="name">			 The node name to search for.</param>
	/// <param name="attributeName"> Name of the attribute.</param>
	/// <param name="attributeValue">The attribute value.</param>
	///
	/// <returns>null if not found, else the child.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> ChildByNameWithAttributeValueExact(const tscrypto::tsCryptoStringBase &name, const tscrypto::tsCryptoStringBase &attributeName, const tscrypto::tsCryptoStringBase &attributeValue);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Search for the first child whos name matches the specified name by searching all
	/// children and their children recursively.</summary>
	///
	/// <param name="name">The node name.</param>
	///
	/// <returns>null if it fails, else.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	std::shared_ptr<tsXmlNode> ChildByNameRecursive(const tscrypto::tsCryptoStringBase &name);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Called by the XML parser when a node start tag is detected.</summary>
	///
	/// <param name="NodeName">  Name of the node.</param>
	/// <param name="InnerXML">  The inner XML.</param>
	/// <param name="singleNode">true if this is a single node.</param>
	///
	/// <returns>The parser error code for this tag.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsXmlParserCallback::resultCodes StartResponse(const tscrypto::tsCryptoStringBase &NodeName, const tscrypto::tsCryptoStringBase &InnerXML, bool singleNode);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Called by the XML parser when node text is detected.</summary>
	///
	/// <param name="newVal">The node text.</param>
	///
	/// <returns>The parser error code for this tag.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsXmlParserCallback::resultCodes ResponseText(const tscrypto::tsCryptoStringBase &newVal);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Called by the XML parser when the end node is detected.</summary>
	///
	/// <param name="NodeName">Name of the node.</param>
	///
	/// <returns>The parser error code for this tag.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsXmlParserCallback::resultCodes EndResponse(const tscrypto::tsCryptoStringBase &NodeName);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Builds an XML string from this node and all of its children.</summary>
	///
	/// <param name="parameter1">[in,out] The destination for the XML string.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool BuildXML(tscrypto::tsCryptoStringBase &, bool useAttributesForErrors);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Called by the parser when a process instruction is detected.</summary>
	///
	/// <param name="contents">The contents of the instruction.</param>
	/// <param name="Results"> [in,out] The results.</param>
	///
	/// <returns>The parser error code for this tag.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsXmlParserCallback::resultCodes ProcessInstruction(const tscrypto::tsCryptoStringBase &contents, tscrypto::tsCryptoStringBase &Results);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Called by the XML parser to create a child node in this node.</summary>
	///
	/// <param name="NodeName">  Name of the child node.</param>
	/// <param name="attributes">[in,out] The attributes.</param>
	/// <param name="InnerXML">  The inner XML.</param>
	/// <param name="SingleNode">true if it is a single node.</param>
	/// <param name="Results">   [in,out] The results.</param>
	///
	/// <returns>The parser error code for this tag.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsXmlParserCallback::resultCodes StartNode(const tscrypto::tsCryptoStringBase &NodeName,
		tsAttributeMap &attributes,
		const tscrypto::tsCryptoStringBase &InnerXML,
		bool SingleNode,
		tscrypto::tsCryptoStringBase &Results);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Called by the parser when a child end node is detected.</summary>
	///
	/// <param name="NodeName">Name of the child node.</param>
	/// <param name="Results"> [in,out] The results.</param>
	///
	/// <returns>The parser error code for this tag.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsXmlParserCallback::resultCodes EndNode(const tscrypto::tsCryptoStringBase &NodeName, tscrypto::tsCryptoStringBase &Results);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Called by the XML parser when a comment is detected.</summary>
	///
	/// <param name="Contents">The comment.</param>
	/// <param name="Results"> [in,out] The results.</param>
	///
	/// <returns>The parser error code for this tag.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsXmlParserCallback::resultCodes Comment(const tscrypto::tsCryptoStringBase &Contents, tscrypto::tsCryptoStringBase &Results);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Called by the XML parser when a CDATA element is detected.</summary>
	///
	/// <param name="Contents">The CDATA.</param>
	/// <param name="Results"> [in,out] The results.</param>
	///
	/// <returns>The parser error code for this tag.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsXmlParserCallback::resultCodes CData(const tscrypto::tsCryptoStringBase &Contents, tscrypto::tsCryptoStringBase &Results);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Called by the XML parser when a Node text is detected.</summary>
	///
	/// <param name="Contents">The node text.</param>
	/// <param name="Results"> [in,out] The results.</param>
	///
	/// <returns>The parser error code for this tag.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsXmlParserCallback::resultCodes Text(const tscrypto::tsCryptoStringBase &Contents, tscrypto::tsCryptoStringBase &Results);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Adds a parse error to the 'Results' string.</summary>
	///
	/// <param name="ErrorStr">The error string.</param>
	/// <param name="Results"> [in,out] The results.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void AddParseError(const tscrypto::tsCryptoStringBase &ErrorStr, tscrypto::tsCryptoStringBase &Results);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Used to verify the hash value for a node.</summary>
	///
	/// <param name="parameter1">The node name.</param>
	/// <param name="parameter2">[in,out] The node attributes.</param>
	/// <param name="parameter3">The inner XML.</param>
	///
	/// <returns>The parser error code for this tag.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsXmlParserCallback::resultCodes VerifyHash(const tscrypto::tsCryptoStringBase &, tsAttributeMap &, const tscrypto::tsCryptoStringBase &);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets a flag to force hash checks.</summary>
	///
	/// <param name="setTo">true if hash checks are required.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void ForceHashChecks(bool setTo);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Determines if hash checks are required.</summary>
	///
	/// <returns>true if hash checks are required.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool ForceHashChecks(void) const;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Parses.</summary>
	///
	/// <param name="sXML">				The XML.</param>
	/// <param name="Results">			[in,out] The results.</param>
	/// <param name="nodesToAttributes">true to nodes to attributes.</param>
	/// <param name="processErrors">	true to process errors.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool Parse(const tscrypto::tsCryptoStringBase &sXML, tscrypto::tsCryptoStringBase &Results, bool nodesToAttributes, bool processErrors);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns true if this node's children shall have TSID attributes.</summary>
	///
	/// <returns>true if TSID attributes are required, false otherwise.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool AddTsIDs(void) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the flag that indicates if this node's children shall have TSID attributes.</summary>
	///
	/// <param name="setTo">true if TSID attributes are required, false otherwise.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void AddTsIDs(bool setTo);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Searches for the all nodes that are found using the xpath search.</summary>
	///
	/// <param name="xpathQuery">The xpath query.</param>
	///
	/// <returns>The found nodes.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsXmlNodeList findNodes(const tscrypto::tsCryptoStringBase &xpathQuery) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Searches for the all nodes that are found using the xpath search.</summary>
	///
	/// <param name="xpathQuery">The xpath query.</param>
	///
	/// <returns>The found nodes.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsXmlNodeList findNodes(const tscrypto::tsCryptoStringBase &xpathQuery);

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

	/// <summary>Recursively scan the children of this node and convert attribute nodes into attributes.</summary>
	void ConvertNodesToAttributes();
	/// <summary>Recursively scan the children of this node and converts error nodes into errors in the error list.</summary>
	void ConvertErrorNodes();
	/**
	 * \brief Gets the attribute node type.
	 *
	 * \return An attributeNodeType.
	 */
	attributeNodeType AttributeNodeType() const;
	/**
	 * \brief Attribute node type.
	 *
	 * \param setTo The set to.
	 */
	void AttributeNodeType(attributeNodeType setTo);
protected:
	/**
	 * \brief Creates a node.
	 *
	 * \param name		 The name.
	 * \param Attributes The attributes.
	 *
	 * \return null if it fails, else the new node.
	 */
	virtual std::shared_ptr<tsXmlNode> CreateNode(const tscrypto::tsCryptoStringBase &name, const tsAttributeMap &Attributes);
	/**
	 * \brief Creates an error node.
	 *
	 * \return null if it fails, else the new error node.
	 */
	virtual std::shared_ptr<tsXmlError> CreateErrorNode();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Encrypt this node based on the authentication information in the EB client channel.</summary>
	///
	/// <remarks>This function just returns false.  The subclassing object must override this function
	/// if encryption is required.</remarks>
	///
	/// <param name="contents">[in,out] The contents.</param>
	/// <param name="Results"> [in,out] The results.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool EncryptForChannel(tscrypto::tsCryptoStringBase &contents, tscrypto::tsCryptoStringBase &Results);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Decrypt this data based on the authentication information in the EB client channel.</summary>
	///
	/// <remarks>This function just returns false.  The subclassing object must override this function
	/// if encryption is required.</remarks>
	///
	/// <param name="Results">[in,out] The results.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool DecryptForChannel(tscrypto::tsCryptoStringBase &Results);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Configures this node's parent and attributes.</summary>
	///
	/// <param name="parent">	 [in,out] If non-null, the parent.</param>
	/// <param name="attributes">The attributes.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool StartNode(std::shared_ptr<tsXmlNode> parent, const tsAttributeMap &attributes);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Removes any TSID attribute from the attribute set passed in and then assigns the next
	/// TSID to this attribute set.</summary>
	///
	/// <param name="parameter1">[in,out] The attribute set.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void AddTSID(tsAttributeMap&);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Builds a start node string and returns it in 'output'.</summary>
	///
	/// <param name="output">[in,out] The output.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void BuildStartNodeXML(tscrypto::tsCryptoStringBase &output) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Builds an end node string and returns it in 'output'.</summary>
	///
	/// <param name="output">[in,out] The output.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void BuildEndNodeXML(tscrypto::tsCryptoStringBase &output) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Builds a start node string and appends it to 'output'.</summary>
	///
	/// <param name="output">[in,out] The output.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void AppendStartNodeXML(tscrypto::tsCryptoStringBase &output) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Builds a single node string and appends it to 'output'.</summary>
	///
	/// <param name="output">[in,out] The output.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void AppendSingleNodeXML(tscrypto::tsCryptoStringBase &output) const;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Builds an end node string and appends it to 'output'.</summary>
	///
	/// <param name="output">[in,out] The output.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void AppendEndNodeXML(tscrypto::tsCryptoStringBase &output) const;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Validates all children nodes in this node.</summary>
	///
	/// <param name="Results">[in,out] The results.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool ValidateChildren(tscrypto::tsCryptoStringBase &Results);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Called during the Run function before the children nodes are run.</summary>
	///
	/// <param name="Results">[in,out] The results.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool InternalRunStart(tscrypto::tsCryptoStringBase &Results);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Called during the Run function after the children nodes are run.</summary>
	///
	/// <param name="Results">[in,out] The results.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool InternalRunEnd(tscrypto::tsCryptoStringBase &Results);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Called by Validate to validate this node.</summary>
	///
	/// <param name="Results">[in,out] The results.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool InternalValidate(tscrypto::tsCryptoStringBase &Results);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns true if this node is runnable.</summary>
	///
	/// <returns>true if this node is runnable, false if this node is a data node.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool RunnableNode();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Determines if we should continue processing nodes if an error is detected.</summary>
	///
	/// <returns>true if errors should be ignored, false otherwise.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool CheckErrorHandling() const;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Helper function that is called for each child node to 'Run' that child.</summary>
	///
	/// <param name="node">  [in,out] If non-null, the node to run.</param>
	/// <param name="params">[in,out] If non-null, options for controlling the operation.</param>
	///
	/// <returns>0 to continue or 1 to fail.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	static int __RunNodes(std::shared_ptr<tsXmlNode> node, tscrypto::tsCryptoStringBase *params);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Helper function used to set the Make DOM flag in all child nodes.</summary>
	///
	/// <param name="*">[in,out] If non-null, the node to process.</param>
	/// <param name="*">[in,out] If non-null, the bool pointer.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	static void __MakeDOMChildren(std::shared_ptr<tsXmlNode>, void*);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Helper function that is called for each child node to 'Verify' that child.</summary>
	///
	/// <param name="node">  [in,out] If non-null, the node to verify.</param>
	/// <param name="params">[in,out] If non-null, options for controlling the operation.</param>
	///
	/// <returns>.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	static int __VerifyNodes(std::shared_ptr<tsXmlNode> node, tscrypto::tsCryptoStringBase *params);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Performs a 'Run' operation on all child nodes.</summary>
	///
	/// <param name="parameter1">[in,out] The results string.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool RunChildren(tscrypto::tsCryptoStringBase &);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the Make DOM flag for all children.</summary>
	///
	/// <param name="parameter1">[in,out] If non-null, The bool pointer.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void MakeDOMChildren(void*);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Appends an XML error to the string called 'Results'.</summary>
	///
	/// <param name="Results">  [in,out] The results.</param>
	/// <param name="Component">The component.</param>
	/// <param name="Method">   The method.</param>
	/// <param name="Number">   The error number.</param>
	/// <param name="Desc">		The description.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void AppendXMLError(tscrypto::tsCryptoStringBase &Results, const tscrypto::tsCryptoStringBase &Component, const tscrypto::tsCryptoStringBase &Method, int32_t Number, const tscrypto::tsCryptoStringBase &Desc);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the needs reauth flag in the topmost node.</summary>
	///
	/// <param name="setTo">true if reauthorization is required.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void SetNeedsReauth(bool setTo);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Helper function to convert all child attribute nodes into attributes recursively.</summary>
	///
	/// <param name="pNode">[in,out] If non-null, the node to process.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void __convertNodesToAttrs(std::shared_ptr<tsXmlNode> pNode, attributeNodeType typeOfConversion);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Helper function to recursively convert error nodes into error objects.</summary>
	///
	/// <param name="pNode">[in,out] If non-null, the node to process.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void __convertErrorNodes(std::shared_ptr<tsXmlNode> pNode);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Convert one error node into the error object.</summary>
	///
	/// <param name="pNode">	[in,out] If non-null, the node that will hold the error object.</param>
	/// <param name="errorNode">[in,out] If non-null, the error node.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void __convertErrorNode(std::shared_ptr<tsXmlNode> pNode, std::shared_ptr<tsXmlNode> errorNode);
	/**
	 * \brief Gets the tag value as a COM object.  This allows you to store data temporarily in this node (not persisted).
	 *
	 * \return null if it fails, else the tag.
	 */
	std::shared_ptr<tsmod::IObject> getTag() const { return m_tag; }
	/**
	 * \brief Sets a tag value as a COM object.  This allows you to store data temporarily in this node (not persisted).
	 *
	 * \param [in,out] tag If non-null, the tag.
	 */
	void setTag(std::shared_ptr<tsmod::IObject> tag) { m_tag.reset(); m_tag = tag; }
protected:
	std::weak_ptr<tsXmlNode> m_Parent;							///< \brief The parent node
	std::weak_ptr<tsXmlNode> Me;
	tsAttributeMap m_Attributes;					///< \brief The attributes for this node
	tsXmlNodeList m_Children;	///< \brief The children of this node
	tsXmlErrorList m_Errors;		///< \brief The errors in this node
	tsXmlErrorList m_Warnings;	///< \brief The warnings in this node
	tscrypto::tsCryptoString m_Text;								///< \brief The text in this node
	tscrypto::tsCryptoString m_NodeName;							///< \brief The name of this node
	bool m_bProcessed;									///< \brief Has this node been processed
	bool m_bHasErrors;									///< \brief Does this node or one of its children have an error
	bool m_bHasWarnings;								///< \brief Does this node or one of its children have a warning
	uint32_t m_lNextID;										///< \brief The next TSID to assign
	bool m_bHash;										///< \brief Does this node require a hash attribute
	bool m_bProtect;									///< \brief Does this node require protection
	bool m_bMakeDom;									///< \brief The Make DOM flag
	bool m_wantsXmlContents;							///< \brief Does this node want the XML Contents
	tscrypto::tsCryptoString m_xmlContents;						///< \brief The XML Contents as a string
	bool m_wantsTextContents;							///< \brief Flag indicating if this node wants the text contents
	bool m_needsReauth;									///< \brief Flag indicating that this node requires reauthentication
//    tsByteString m_hashValue;
	std::shared_ptr<tsXmlNode> m_RunnableParseNode;				///< \brief Used by the parser to know which node is being processed
	std::shared_ptr<tsXmlNode> m_RootNode;						///< \brief Used by the parser to know which node is the top node
	bool     m_forceHashChecks;							///< \brief Flag used to force hash checks for this node
	bool     m_addTsIDs;								///< \brief Flag indicating that TSIDs are to be added to all nodes
	bool     m_useFormattedOutput;						///< \brief Flag indicating that indentation shall be used when generating XML output.
	std::shared_ptr<tsmod::IObject> m_tag;							///< \brief Generic holder for a COM object
	attributeNodeType m_attrNodeType;					///< \brief The type of attribute nodes to support
};

/// <summary>Defines an alias representing the node migrate parameter.</summary>
typedef struct _NodeMigrateParam
{
	tsXmlNode* pDestNode; ///< The destination node - where xxx is migrated to
	size_t lMigrateCount;			 ///< how many items have been migrated
} NodeMigrateParam;

#endif //!defined(AFX_XMLNODE_H__4A8A5CCE_A10B_4D5D_9D5A_7E47EB7D18F1__INCLUDED_)

