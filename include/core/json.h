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

/** \file json.h
 * \brief Defines the Java Script Object Notation (JSON) field and object classes
 */

#ifndef __JSON_H__
 /**
  * \brief A macro that defines JSON h.
  */
#define __JSON_H__

#pragma once

namespace tscrypto {

    class JSONObject;
    class JSONField;

    typedef enum
    {
        jet_Unknown,
        jet_Field,
        jet_Object,
    } JsonElementType;

    class VEILCORE_API JSONElement
    {
    public:
        static void* operator new(std::size_t count) {
            return tscrypto::cryptoNew(count);
        }
        static void* operator new[](std::size_t count) {
            return tscrypto::cryptoNew(count);
        }
        static void operator delete(void* ptr) {
            tscrypto::cryptoDelete(ptr);
        }
        static void operator delete[](void* ptr) {
            tscrypto::cryptoDelete(ptr);
        }

        JSONElement() : _parent(nullptr) {}
        virtual ~JSONElement() {}

        virtual JsonElementType ElementType() const = 0;

        virtual JSONElement* Parent() const { return _parent; }
        virtual void Parent(JSONElement* setTo) { _parent = setTo; }

        virtual void FixLineage() = 0;
        virtual bool DeleteMeFromParent() = 0;
        virtual JSONElement* findSingleItem(const tsCryptoStringBase& path, bool createNode) = 0;
        virtual const JSONElement* findSingleItem(const tsCryptoStringBase& path) const = 0;
        virtual void clear() = 0;
        virtual tsCryptoString ToString() const = 0;
        virtual bool FromString(const tsCryptoStringBase& setTo) = 0;
    private:
        JSONElement* _parent;
    };


#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
    VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API ICryptoContainerWrapper<JSONField>;
    VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<ICryptoContainerWrapper<JSONField>>;
    VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API ICryptoContainerWrapper<JSONElement*>;
    VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<ICryptoContainerWrapper<JSONElement*>>;
#pragma warning(pop)
#endif // _MSC_VER

    typedef std::shared_ptr<ICryptoContainerWrapper<JSONField>> JSONFieldList;
    typedef std::shared_ptr<ICryptoContainerWrapper<JSONElement*>> JsonSearchResultList;

    extern VEILCORE_API JSONFieldList CreateJSONFieldList();

    /**
     * \brief A single field in a JSON object
     */
    class VEILCORE_API JSONField : public JSONElement
    {
    public:
        /**
         * \brief Defines an alias representing the type of JSON fields.
         */
        typedef enum { jsonNull, jsonString, jsonBool, jsonNumber, jsonObject, jsonArray } jsonFieldType;
        /**
         * \brief Default constructor.
         */
        JSONField();
        /**
         * \brief Constructor.
         *
         * \param name The name.
         */
        JSONField(const tsCryptoStringBase& name);
        /**
         * \brief Constructor.
         *
         * \param name  The name.
         * \param value The value.
         */
        JSONField(const tsCryptoStringBase& name, const tsCryptoStringBase& value);
        JSONField(const tsCryptoStringBase& name, const char* value);
        /**
         * \brief Constructor.
         *
         * \param name  The name.
         * \param value true to value.
         */
        JSONField(const tsCryptoStringBase& name, bool value);
        /**
         * \brief Constructor.
         *
         * \param name  The name.
         * \param value The value.
         */
        JSONField(const tsCryptoStringBase& name, int64_t value);
        /**
         * \brief Constructor.
         *
         * \param name  The name.
         * \param value The value.
         */
        JSONField(const tsCryptoStringBase& name, const JSONObject& value);
        /**
         * \brief Constructor.
         *
         * \param name			 The name.
         * \param [in,out] value The value.
         */
        JSONField(const tsCryptoStringBase& name, JSONObject&& value);
        /**
         * \brief Constructor.
         *
         * \param name  The name.
         * \param value The value.
         */
        JSONField(const tsCryptoStringBase& name, const JSONFieldList& value);
        /**
         * \brief Destructor.
         */
        ~JSONField();
        /**
         * \brief Copy constructor.
         *
         * \param obj The object.
         */
        JSONField(const JSONField& obj);
        /**
         * \brief Move constructor.
         *
         * \param [in,out] obj The object.
         */
        JSONField(JSONField&& obj);
        /**
         * \brief Assignment operator.
         *
         * \param obj The object.
         *
         * \return A shallow copy of this object.
         */
        JSONField& operator=(const JSONField& obj);
        /**
         * \brief Move assignment operator.
         *
         * \param [in,out] obj The object.
         *
         * \return A shallow copy of this object.
         */
        JSONField& operator=(JSONField&& obj);
        /**
         * \brief Equality operator.
         *
         * \param obj The object.
         *
         * \return true if the parameters are considered equivalent.
         */
        bool operator==(const JSONField& obj) const;
        /**
         * \brief Gets the type.
         *
         * \return A jsonFieldType.
         */
        jsonFieldType Type() const;
        /**
         * \brief Gets the JSON field name.
         *
         * \return A tsCryptoString.
         */
        tsCryptoString Name() const;
        /**
         * \brief Sets the JSON field name.
         *
         * \param setTo The new field name.
         */
        void Name(const tsCryptoStringBase& setTo);
        /**
         * \brief Query if this object is XML attribute.
         *
         * \return true if XML attribute, false if not.
         */
        bool isXmlAttribute() const;
        /**
         * \brief Query if this object is XML text node.
         *
         * \return true if XML text node, false if not.
         */
        bool isXmlTextNode() const;
        /**
         * \brief Converts this object to a string.
         *
         * \return A tsCryptoString.
         */
        tsCryptoString AsString() const;
        /**
         * \brief Converts this object to a JSON.
         *
         * \return This object as a tsCryptoString.
         */
        tsCryptoString ToJSON() const;
        /**
         * \brief Returns the field contents as a boolean and uses defaultValue if the conversion is not possible
         *
         * \param defaultValue (Optional) the default value.
         *
         * \return the boolean value
         */
        bool AsBool(bool defaultValue = false) const;
        /**
        * \brief Returns the field contents as a number and uses defaultValue if the conversion is not possible
        *
        * \param defaultValue (Optional) the default value.
        *
        * \return the numeric value
        */
        int64_t AsNumber(int64_t defaultValue = 0) const;
        /**
         * \brief Converts this object to a null.
         *
         * \return A nullptr_t.
         */
        std::nullptr_t AsNull() const;
        /**
         * \brief Converts the contents of this object into a JSON object.
         *
         * \return A JSONObject reference
         * \throws std::runtime_error
         */
        JSONObject& AsObject();
        /**
        * \brief Converts the contents of this object into a JSON object.
        *
        * \return A JSONObject reference
        * \throws std::runtime_error
        */
        const JSONObject& AsObject() const;
        /**
         * \brief Converts this object to an array.
         *
         * \return the JSON field array
         * \throws std::runtime_error
         */
        const JSONFieldList& AsArray() const;
        /**
         * \brief Converts this object to an array.
         *
         * \return the JSON field array
         * \throws std::runtime_error
         */
        JSONFieldList& AsArray();
        /**
         * \brief Sets the JSON field to a null value
         *
         * \param setTo a nullptr.
         */
        void ValueAsNull();
        void Value(std::nullptr_t setTo);
        /**
         * \brief Sets the JSON field to a boolean value
         *
         * \param setTo The new value.
         */
        void Value(bool setTo);
        /**
        * \brief Sets the JSON field to a string value
        *
        * \param setTo The new value.
        */
        void Value(const tsCryptoStringBase& setTo);
        void Value(const char* setTo);
        /**
        * \brief Sets the JSON field to a numeric value
        *
        * \param setTo The new value.
        */
        void Value(int64_t setTo);
        /**
        * \brief Sets the JSON field to a JSON object value
        *
        * \param setTo The new value.
        */
        void Value(const JSONObject& setTo);
        /**
        * \brief Sets the JSON field to a JSON object value using the move symantics
        *
        * \param setTo The new value.
        */
        void Value(JSONObject&& setTo);
        /**
        * \brief Sets the JSON field to a JSON field array value
        *
        * \param setTo The new value.
        */
        void Value(const JSONFieldList& setTo);
        /**
        * \brief Sets the JSON field to a JSON field array value using the move symantics
        *
        * \param setTo The new value.
        */
        void Value(JSONFieldList&& setTo);
        /**
         * \brief Clears this object to its blank/initial state.
         */
        virtual void clear();
        void for_each(std::function<void(JSONField& fld)> func);
        void for_each(std::function<void(const JSONField& fld)> func) const;
        void erase_if(std::function<bool(JSONField& fld)> func);
        /**
         * \brief Converts an arrayNode to an XML.
         *
         * \param arrayNode (Optional) the array node.
         *
         * \return arrayNode as a tsCryptoString.
         */
        tsCryptoString ToXML(const tsCryptoStringBase& arrayNode = "") const;
        virtual JsonElementType ElementType() const
        {
            return jet_Field;
        }
        virtual void FixLineage();
        JsonSearchResultList JSONPathQuery(const tsCryptoStringBase& path);
        virtual bool DeleteMeFromParent();
        virtual JSONElement* findSingleItem(const tsCryptoStringBase& path, bool createNode);
        virtual const JSONElement* findSingleItem(const tsCryptoStringBase& path) const;
        virtual tsCryptoString ToString() const { return AsString(); }
        virtual bool FromString(const tsCryptoStringBase& setTo) { Value(setTo); return true; }

    protected:
        jsonFieldType _type;	///< The type
        tsCryptoString _name;		///< The field name
        tsCryptoString _stringVal; ///< The string value
        int64_t _numberVal; ///< Number of values
        bool    _boolVal;   ///< true to value
        bool    _isNull;	///< true if this object is null
        JSONFieldList _arrayVal;  ///< The array value
        JSONObject *_objectVal; ///< The object value
    };
    /**
     * \brief Represents a JSON object
     */
    class VEILCORE_API JSONObject : public JSONElement
    {
    public:
        /**
         * \brief Default constructor.
         */
        JSONObject();
        /**
         * \brief Destructor.
         */
        ~JSONObject();
        /**
         * \brief Copy constructor.
         *
         * \param obj The object.
         */
        JSONObject(const JSONObject& obj);
        /**
         * \brief Move constructor.
         *
         * \param [in,out] obj The object.
         */
        JSONObject(JSONObject&& obj);
        /**
         * \brief Assignment operator.
         *
         * \param obj The object.
         *
         * \return A shallow copy of this object.
         */
        JSONObject& operator=(const JSONObject& obj);
        /**
         * \brief Move assignment operator.
         *
         * \param [in,out] obj The object.
         *
         * \return A shallow copy of this object.
         */
        JSONObject& operator=(JSONObject&& obj);
        /**
         * \brief Equality operator.
         *
         * \param obj The object.
         *
         * \return true if the parameters are considered equivalent.
         */
        bool operator==(const JSONObject& obj) const;
        /**
         * \brief Gets the list of fields in this object
         *
         * \return The field list
         */
        JSONFieldList& Fields();
        /**
         * \brief Gets the list of fields in this object
         *
         * \return The field list
         */
        const JSONFieldList& Fields() const;
        /**
         * \brief Gets the field count.
         *
         * \return A size_t.
         */
        size_t fieldCount() const;
        /**
         * \brief Gets the specifed field from the object
         *
         * \param index Zero-based index of the field.
         *
         * \return A JSONField reference
         */
        const JSONField& field(size_t index) const;
        /**
         * \brief Gets the specifed field from the object
         *
         * \param index Zero-based index of the field.
         *
         * \return A JSONField reference
         */
        JSONField& field(size_t index);
        /**
        * \brief Gets the specifed field from the object
        *
        * \param index Name of the field.
        *
        * \return A JSONField reference
        */
        const JSONField& field(const tsCryptoStringBase& index) const;
        /**
        * \brief Gets the specifed field from the object
        *
        * \param index Name of the field.
        *
        * \return A JSONField reference
        */
        JSONField& field(const tsCryptoStringBase& index);
        /**
         * \brief Query if the specified field exists
         *
         * \param index The field index
         *
         * \return true if the field exists, false if not.
         */
        bool hasField(size_t index) const;
        /**
        * \brief Query if the specified field exists
        *
        * \param index The field name
        *
        * \return true if the field exists, false if not.
        */
        bool hasField(const tsCryptoStringBase& index) const;
        /**
         * \brief Adds a JSON field to the object.
         *
         * \param fld The field to add.
         *
         * \return A JSONObject reference;
         */
        JSONObject& add(const JSONField& fld);
        /**
        * \brief Adds a JSON field to the object using move symantics.
        *
        * \param fld The field to add.
        *
        * \return A JSONObject reference;
        */
        JSONObject& add(JSONField&& fld);

        /**
        * \brief Adds a JSON field to the object.
        *
        * \param name The field name to add.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& add(const tsCryptoStringBase& name, const tsCryptoStringBase& val);
        JSONObject& add(const tsCryptoStringBase& name, const char* val);
        /**
        * \brief Adds a JSON field to the object.
        *
        * \param name The field name to add.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& add(const tsCryptoStringBase& name, int64_t val);
        /**
        * \brief Adds a JSON field to the object.
        *
        * \param name The field name to add.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& add(const tsCryptoStringBase& name);
        /**
        * \brief Adds a JSON field to the object.
        *
        * \param name The field name to add.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& add(const tsCryptoStringBase& name, bool val);
        /**
        * \brief Adds a JSON field to the object.
        *
        * \param name The field name to add.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& add(const tsCryptoStringBase& name, const JSONObject& val);
        /**
        * \brief Adds a JSON field to the object using move symantics.
        *
        * \param name The field name to add.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& add(const tsCryptoStringBase& name, JSONObject&& val);
        /**
        * \brief Adds a JSON field to the object.
        *
        * \param name The field name to add.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& add(const tsCryptoStringBase& name, const JSONFieldList& val);
        /**
        * \brief Adds a JSON field to the object using move symantics.
        *
        * \param name The field name to add.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& add(const tsCryptoStringBase& name, JSONFieldList&& val);

        /**
        * \brief Replaces a JSON field in the object.
        *
        * \param fld The field to replace.
        *
        * \return A JSONObject reference;
        */
        JSONObject& replace(const JSONField& fld);
        /**
        * \brief Replaces a JSON field in the object using move symantics.
        *
        * \param fld The field to replace.
        *
        * \return A JSONObject reference;
        */
        JSONObject& replace(JSONField&& fld);
        /**
        * \brief Replaces a JSON field in the object.
        *
        * \param name The field name to replace.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& replace(const tsCryptoStringBase& name, const tsCryptoStringBase& val);
        JSONObject& replace(const tsCryptoStringBase& name, const char* val);
        /**
        * \brief Replaces a JSON field in the object.
        *
        * \param name The field name to replace.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& replace(const tsCryptoStringBase& name, int64_t val);
        /**
        * \brief Replaces a JSON field in the object.
        *
        * \param name The field name to replace.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& replaceWithNull(const tsCryptoStringBase& name);
        /**
        * \brief Replaces a JSON field in the object.
        *
        * \param name The field name to replace.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& replace(const tsCryptoStringBase& name, bool val);
        /**
        * \brief Replaces a JSON field in the object.
        *
        * \param name The field name to replace.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& replace(const tsCryptoStringBase& name, const JSONObject& val);
        /**
        * \brief Replaces a JSON field in the object using move symantics.
        *
        * \param name The field name to replace.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& replace(const tsCryptoStringBase& name, JSONObject&& val);
        /**
        * \brief Replaces a JSON field in the object.
        *
        * \param name The field name to replace.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& replace(const tsCryptoStringBase& name, const JSONFieldList& val);
        /**
        * \brief Replaces a JSON field in the object using move symantics.
        *
        * \param name The field name to replace.
        * \param val  The value.
        *
        * \return A JSONObject reference;
        */
        JSONObject& replace(const tsCryptoStringBase& name, JSONFieldList&& val);
        /**
         * \brief Deletes the field described by name.
         *
         * \param name The name.
         *
         * \return A JSONObject reference
         */
        JSONObject& deleteField(const tsCryptoStringBase& name);
        /**
         * \brief Renames a field.
         *
         * \param oldname The oldname.
         * \param newname The newname.
         *
         * \return A JSONObject reference;
         */
        JSONObject& renameField(const tsCryptoStringBase& oldname, const tsCryptoStringBase& newname);
        /**
         * \brief Converts this object to a JSON string.
         *
         * \return This object as a string.
         */
        tsCryptoString ToJSON() const;
        /**
         * \brief Initializes this object from the JSON string.
         *
         * \param json The JSON string.
         *
         * \return The number of characters used in the conversion.
         */
        ptrdiff_t FromJSON(const tsCryptoStringBase& json);
        ptrdiff_t FromJSON(const char* json);
        /**
         * \brief Converts this object into an XML string
         *
         * \param rootName Name of the root.
         *
         * \return rootName as a tsCryptoString.
         */
        tsCryptoString ToXML(const tsCryptoStringBase& rootName) const;
        /**
         * \brief Clears this object to its blank/initial state.
         */
        virtual void clear();
        /**
         * \brief Add fields from the object that do not already exist in this object.
         *
         * \param obj The object.
         *
         * \return A JSONObject reference
         */
        JSONObject& expand(const JSONObject& obj);
        /**
        * \brief Add fields from the object that do not already exist in this object.
        *
        * \param obj The object.
        *
        * \return A JSONObject reference
        */
        JSONObject& expand(const tsCryptoStringBase& obj);
        /**
         * \brief Replace fields from obj into this (replaces arrays...)
         *
         * \param obj The object being merged into this object.
         *
         * \return A JSONObject reference
         */
        JSONObject& merge(const JSONObject& obj);
        /**
        * \brief Replace fields from obj into this (replaces arrays...)
        *
        * \param obj The object being merged into this object.
        *
        * \return A JSONObject reference
        */
        JSONObject& merge(const tsCryptoStringBase& obj);
        /**
         * \brief Add fields from the object into this object (may create arrays)
         *
         * \param obj The object being added to this object.
         *
         * \return A JSONObject reference
         */
        JSONObject& unionOf(const JSONObject& obj);
        /**
        * \brief Add fields from the object into this object (may create arrays)
        *
        * \param obj The object being added to this object.
        *
        * \return A JSONObject reference
        */
        JSONObject& unionOf(const tsCryptoStringBase& obj);
        /**
         * \brief Looks for the specified field and returns its value as a string
         *
         * \param fieldName Name of the field.
         *
         * \return The value of the field
         */
        tsCryptoString AsString(const tsCryptoStringBase& fieldName) const;
        /**
         * \brief Looks for the specified field and returns its value as a boolean.
         *
         * \param fieldName    Name of the field.
         * \param defaultValue (Optional) the default value if the field does not exist or cannot be converted.
         *
         * \return The value of the field.
         */
        bool AsBool(const tsCryptoStringBase& fieldName, bool defaultValue = false) const;
        /**
        * \brief Looks for the specified field and returns its value as a number.
        *
        * \param fieldName    Name of the field.
        * \param defaultValue (Optional) the default value if the field does not exist or cannot be converted.
        *
        * \return The value of the field.
        */
        int64_t AsNumber(const tsCryptoStringBase& fieldName, int64_t defaultValue = 0) const;
        /**
         * \brief Looks for the specified field and returns its value.
         *
         * \param fieldName Name of the field.
         *
         * \return The value of the field.
         *
         * \throws std::runtime_error
         */
        std::nullptr_t AsNull(const tsCryptoStringBase& fieldName) const;
        /**
        * \brief Looks for the specified field and returns its value as a JSON object.
        *
        * \param fieldName Name of the field.
        *
        * \return The value of the field.
        *
        * \throws std::runtime_error
        */
        JSONObject& AsObject(const tsCryptoStringBase& fieldName);
        /**
        * \brief Looks for the specified field and returns its value as a JSON object.
        *
        * \param fieldName Name of the field.
        *
        * \return The value of the field.
        *
        * \throws std::runtime_error
        */
        const JSONObject& AsObject(const tsCryptoStringBase& fieldName) const;
        /**
        * \brief Looks for the specified field and returns its value as a JSON field array.
        *
        * \param fieldName Name of the field.
        *
        * \return The value of the field.
        *
        * \throws std::runtime_error
        */
        const JSONFieldList& AsArray(const tsCryptoStringBase& fieldName) const;
        /**
        * \brief Looks for the specified field and returns its value as a JSON field array.
        *
        * \param fieldName Name of the field.
        *
        * \return The value of the field.
        *
        * \throws std::runtime_error
        */
        JSONFieldList& AsArray(const tsCryptoStringBase& fieldName);
        /**
         * \brief Iterates through all of the fields in this object and calls func
         *
         * \param [in,out] func The function.
         */
        void foreach(std::function<void(JSONField&)> func);
        /**
        * \brief Iterates through all of the fields in this object and calls func
        *
        * \param [in,out] func The function.
        */
        void foreach(std::function<void(const JSONField&)> func) const;
        /**
         * \brief Iterates through all of the fields in this object and deletes the field if the function
         * returns true.
         *
         * \param [in,out] func The function.
         */
        void remove_if(std::function<bool(JSONField&)> func);
        /**
        * \brief Iterates through all of the elements in the JSON field array specified by arrayFieldName
        * in this object and deletes the element if the function returns true.
        *
        * \param arrayFieldName Name of the array field.
        * \param [in,out] func  The function.
        */
        void remove_if(const tsCryptoStringBase& arrayFieldName, std::function<bool(JSONField&)> func);

        /**
        * \brief Iterates over the given field name and calls func.  If the field is a vector then iterate over the elements of the vector
        *
        * \param fieldName	    Name of the field.
        * \param func The test function.
        */
        void foreach(const tsCryptoStringBase& fieldName, std::function<void(JSONField&)> func);
        /**
        * \brief Iterates over the given field name and calls func.  If the field is a vector then iterate over the elements of the vector
        *
        * \param fieldName	    Name of the field.
        * \param func The test function.
        */
        void foreach(const tsCryptoStringBase& fieldName, std::function<void(const JSONField&)> func) const;

        virtual JsonElementType ElementType() const
        {
            return jet_Object;
        }
        virtual void FixLineage();

        JsonSearchResultList JSONPathQuery(const tsCryptoStringBase& path);
        virtual JSONElement* findSingleItem(const tsCryptoStringBase& path, bool createNode);
        virtual const JSONElement* findSingleItem(const tsCryptoStringBase& path) const;
        virtual bool DeleteMeFromParent();
        virtual tsCryptoString ToString() const { return ToJSON(); }
        virtual bool FromString(const tsCryptoStringBase& setTo) { return FromJSON(setTo) > 0; }

        JSONFieldList createArrayField(const tsCryptoStringBase& fieldName);

    protected:
        JSONFieldList _fields;	///< The fields
    };

}

#endif // __JSON_H__

