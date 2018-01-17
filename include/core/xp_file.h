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

/*! @file xp_file.h
 * @brief This file defines the class that holds the cross platform file primitives
*/

#ifndef __XP_FILE_H__
#define __XP_FILE_H__

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

namespace tscrypto {

//#define XP_INVALID_FILE_ATTRIBUTES	((uint32_t)-1)			/*!< \brief The value that indicates the file attributes are invalid **/
//#define XP_FILE_ATTRIBUTE_READONLY				0x00000001	/*!< \brief Read only file **/
//#define XP_FILE_ATTRIBUTE_HIDDEN				0x00000002	/*!< \brief Hidden file **/
//#define XP_FILE_ATTRIBUTE_SYSTEM				0x00000004	/*!< \brief System file **/
//#define XP_FILE_ATTRIBUTE_DIRECTORY				0x00000010	/*!< \brief Directory **/
//#define XP_FILE_ATTRIBUTE_ARCHIVE				0x00000020	/*!< \brief Archive flag **/
//#define XP_FILE_ATTRIBUTE_DEVICE				0x00000040	/*!< \brief Is a device **/
//#define XP_FILE_ATTRIBUTE_NORMAL				0x00000080	/*!< \brief Normal file **/
//#define XP_FILE_ATTRIBUTE_TEMPORARY				0x00000100	/*!< \brief Temporary file **/
//#define XP_FILE_ATTRIBUTE_SPARSE_FILE			0x00000200	/*!< \brief Sparse file **/
//#define XP_FILE_ATTRIBUTE_REPARSE_POINT			0x00000400	/*!< \brief Reparse point **/
//#define XP_FILE_ATTRIBUTE_COMPRESSED			0x00000800	/*!< \brief Compressed file **/
//#define XP_FILE_ATTRIBUTE_OFFLINE				0x00001000	/*!< \brief Offline file **/
//#define XP_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED	0x00002000	/*!< \brief Not content indexed **/
//#define XP_FILE_ATTRIBUTE_ENCRYPTED				0x00004000	/*!< \brief Encrypted file **/
//#define XP_FILE_ATTRIBUTE_VALID_FLAGS			0x00007fb7	/*!< \brief Mask for valid files **/
//#define XP_FILE_ATTRIBUTE_VALID_SET_FLAGS		0x000031a7	/*!< \brief Full set of flags tat can be set on a file **/
//
//#define XP_DELETE					0x00010000L	/*!< \brief File Security: Can delete */
//#define XP_READ_CONTROL				0x00020000L	/*!< \brief File Security: Read control */
//#define XP_WRITE_DAC				0x00040000L	/*!< \brief File Security: Write DAC */
//#define XP_WRITE_OWNER				0x00080000L	/*!< \brief File Security: Write Owner */
//#define XP_SYNCHRONIZE				0x00100000L	/*!< \brief File Security: Synchronize */
//#define XP_STANDARD_RIGHTS_REQUIRED	0x000F0000L	/*!< \brief File Security: Standard rights required */
//#define XP_STANDARD_RIGHTS_READ		0x00020000L	/*!< \brief File Security: Read */
//#define XP_STANDARD_RIGHTS_WRITE	0x00020000L	/*!< \brief File Security: Write */
//#define XP_STANDARD_RIGHTS_EXECUTE	0x00020000L	/*!< \brief File Security: Execute */
//#define XP_STANDARD_RIGHTS_ALL		0x001F0000L	/*!< \brief File Security: All standard rights */
//#define XP_SPECIFIC_RIGHTS_ALL		0x0000FFFFL	/*!< \brief File Security: Specific standard rights */
//#define XP_ACCESS_SYSTEM_SECURITY	0x10000000L	/*!< \brief File Security: Access system security */
//
//#define XP_MAXIMUM_ALLOWED			0x02000000	/*!< \brief File Security: maximum Allowed */
//#define XP_GENERIC_READ				0x80000000	/*!< \brief File Security: Generic read */
//#define XP_GENERIC_WRITE			0x40000000	/*!< \brief File Security: Generic write */
//#define XP_GENERIC_EXECUTE			0x20000000	/*!< \brief File Security: Generic execute */
//#define XP_GENERIC_ALL				0x10000000	/*!< \brief File Security: All generic */
//
//#define XP_INVALID_SET_FILE_POINTER ((uint32_t)-1)	/*!< \brief Return code for SetFilePointer */
//
///* Also in ddk/winddk.h */
//#define XP_FILE_LIST_DIRECTORY					0x00000001	 /*!< \brief Access Right: List Directories */
//#define XP_FILE_READ_DATA						0x00000001	 /*!< \brief Access Right: Read Data */
//#define XP_FILE_ADD_FILE						0x00000002	 /*!< \brief Access Right: Add File */
//#define XP_FILE_WRITE_DATA						0x00000002	 /*!< \brief Access Right: Write Data */
//#define XP_FILE_ADD_SUBDIRECTORY				0x00000004	 /*!< \brief Access Right: Add Subdirectory */
//#define XP_FILE_APPEND_DATA						0x00000004	 /*!< \brief Access Right: Append data */
//#define XP_FILE_CREATE_PIPE_INSTANCE			0x00000004	 /*!< \brief Access Right: Create pipe instance */
//#define XP_FILE_READ_EA							0x00000008	 /*!< \brief Access Right: Read extended attributes */
//#define XP_FILE_READ_PROPERTIES					0x00000008	 /*!< \brief Access Right: Read properties */
//#define XP_FILE_WRITE_EA						0x00000010	 /*!< \brief Access Right: Write extended attributes */
//#define XP_FILE_WRITE_PROPERTIES				0x00000010	 /*!< \brief Access Right: Write properties */
//#define XP_FILE_EXECUTE							0x00000020	 /*!< \brief Access Right: Execute */
//#define XP_FILE_TRAVERSE						0x00000020	 /*!< \brief Access Right: Traverse */
//#define XP_FILE_DELETE_CHILD					0x00000040	 /*!< \brief Access Right: Delete Child */
//#define XP_FILE_READ_ATTRIBUTES					0x00000080	 /*!< \brief Access Right: Read attributes */
//#define XP_FILE_WRITE_ATTRIBUTES				0x00000100	 /*!< \brief Access Right: Write attributes */
//
//#define XP_FILE_SHARE_READ						0x00000001	 /*!< \brief File Share: Read sharing */
//#define XP_FILE_SHARE_WRITE						0x00000002	 /*!< \brief File Share: Write sharing */
//#define XP_FILE_SHARE_DELETE					0x00000004	 /*!< \brief File Share: Delete sharing */
//#define XP_FILE_SHARE_VALID_FLAGS				0x00000007	 /*!< \brief File Share: A mask for the valid sharing flags */
//
//#define XP_FILE_ATTRIBUTE_READONLY				0x00000001	 /*!< \brief File Attribute: Read only */
//#define XP_FILE_ATTRIBUTE_HIDDEN				0x00000002	 /*!< \brief File Attribute: Hidden */
//#define XP_FILE_ATTRIBUTE_SYSTEM				0x00000004	 /*!< \brief File Attribute: System */
//#define XP_FILE_ATTRIBUTE_DIRECTORY				0x00000010	 /*!< \brief File Attribute: Directory */
//#define XP_FILE_ATTRIBUTE_ARCHIVE				0x00000020	 /*!< \brief File Attribute: Archivable */
//#define XP_FILE_ATTRIBUTE_DEVICE				0x00000040	 /*!< \brief File Attribute: Device */
//#define XP_FILE_ATTRIBUTE_NORMAL				0x00000080	 /*!< \brief File Attribute: Normal */
//#define XP_FILE_ATTRIBUTE_TEMPORARY				0x00000100	 /*!< \brief File Attribute: Temporary file */
//#define XP_FILE_ATTRIBUTE_SPARSE_FILE			0x00000200	 /*!< \brief File Attribute: Sparse file */
//#define XP_FILE_ATTRIBUTE_REPARSE_POINT			0x00000400	 /*!< \brief File Attribute: Reparse Point */
//#define XP_FILE_ATTRIBUTE_COMPRESSED			0x00000800	 /*!< \brief File Attribute: Compressed file */
//#define XP_FILE_ATTRIBUTE_OFFLINE				0x00001000	 /*!< \brief File Attribute: Offline */
//#define XP_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED	0x00002000	 /*!< \brief File Attribute: Not content indexed */
//#define XP_FILE_ATTRIBUTE_ENCRYPTED				0x00004000	 /*!< \brief File Attribute: Encrypted */
//#define XP_FILE_ATTRIBUTE_VALID_FLAGS			0x00007fb7	 /*!< \brief File Attribute: Valid flags mask */
//#define XP_FILE_ATTRIBUTE_VALID_SET_FLAGS		0x000031a7	 /*!< \brief File Attribute: Valid settable flags mask */
//
////#define XP_FILE_COPY_STRUCTURED_STORAGE			0x00000041	 /*!<  */
////#define XP_FILE_STRUCTURED_STORAGE				0x00000441	 /*!<  */
//
////#define XP_FILE_VALID_OPTION_FLAGS				0x00ffffff	 /*!<  */
////#define XP_FILE_VALID_PIPE_OPTION_FLAGS			0x00000032	 /*!<  */
////#define XP_FILE_VALID_MAILSLOT_OPTION_FLAGS		0x00000032	 /*!<  */
////#define XP_FILE_VALID_SET_FLAGS					0x00000036	 /*!<  */
//
//#define XP_FILE_SUPERSEDE					0x00000000		 /*!< \brief Create Disposition flag: Supercede */
//#define XP_FILE_OPEN						0x00000001		 /*!< \brief Create Disposition flag: Open existing */
//#define XP_FILE_CREATE						0x00000002		 /*!< \brief Create Disposition flag: Create new */
//#define XP_FILE_OPEN_IF						0x00000003		 /*!< \brief Create Disposition flag: Open if existing */
//#define XP_FILE_OVERWRITE					0x00000004		 /*!< \brief Create Disposition flag: Overwrite */
//#define XP_FILE_OVERWRITE_IF				0x00000005		 /*!< \brief Create Disposition flag: Overwrite if existing */
//#define XP_FILE_MAXIMUM_DISPOSITION			0x00000005		 /*!< \brief Create Disposition flag: Maximum value for the flags */
//
//#define XP_FILE_DIRECTORY_FILE				0x00000001		 /*!< \brief File Create Options: Directory */
//#define XP_FILE_WRITE_THROUGH				0x00000002		 /*!< \brief File Create Options: Write through */
//#define XP_FILE_SEQUENTIAL_ONLY				0x00000004		 /*!< \brief File Create Options: Sequential only */
//#define XP_FILE_NO_INTERMEDIATE_BUFFERING	0x00000008		 /*!< \brief File Create Options: No intermediate buffering */
//#define XP_FILE_SYNCHRONOUS_IO_ALERT		0x00000010		 /*!< \brief File Create Options: Synchronous I/O with alert */
//#define XP_FILE_SYNCHRONOUS_IO_NONALERT		0x00000020		 /*!< \brief File Create Options: Synchronous I/O without alert */
//#define XP_FILE_NON_DIRECTORY_FILE			0x00000040		 /*!< \brief File Create Options: not a directory */
//#define XP_FILE_CREATE_TREE_CONNECTION		0x00000080		 /*!< \brief File Create Options: Create tree */
//#define XP_FILE_COMPLETE_IF_OPLOCKED		0x00000100		 /*!< \brief File Create Options: Complete if OPLocked */
//#define XP_FILE_NO_EA_KNOWLEDGE				0x00000200		 /*!< \brief File Create Options: No Extended Attributes */
//#define XP_FILE_OPEN_FOR_RECOVERY			0x00000400		 /*!< \brief File Create Options: Open for recovery */
//#define XP_FILE_RANDOM_ACCESS				0x00000800		 /*!< \brief File Create Options: Random Access */
//#define XP_FILE_DELETE_ON_CLOSE				0x00001000		 /*!< \brief File Create Options: Delete on close */
//#define XP_FILE_OPEN_BY_FILE_ID				0x00002000		 /*!< \brief File Create Options: Open by File ID */
//#define XP_FILE_OPEN_FOR_BACKUP_INTENT		0x00004000		 /*!< \brief File Create Options: Open for backup */
//#define XP_FILE_NO_COMPRESSION				0x00008000		 /*!< \brief File Create Options: No compression */
//#define XP_FILE_RESERVE_OPFILTER			0x00100000		 /*!< \brief File Create Options: Reserve OPLock */
//#define XP_FILE_OPEN_REPARSE_POINT			0x00200000		 /*!< \brief File Create Options: Open reparse point */
//#define XP_FILE_OPEN_NO_RECALL				0x00400000		 /*!< \brief File Create Options: Open with no recall */
//#define XP_FILE_OPEN_FOR_FREE_SPACE_QUERY	0x00800000		 /*!< \brief File Create Options: Open to check free space */
//
//#define XP_FILE_ALL_ACCESS (XP_STANDARD_RIGHTS_REQUIRED | XP_SYNCHRONIZE | 0x1FF) /*!< \brief Standard Rights: All access */
//#define XP_FILE_GENERIC_EXECUTE (XP_STANDARD_RIGHTS_EXECUTE | XP_FILE_READ_ATTRIBUTES | XP_FILE_EXECUTE | XP_SYNCHRONIZE)/*!< \brief Standard Rights: Open for execute */
//#define XP_FILE_GENERIC_READ (XP_STANDARD_RIGHTS_READ | XP_FILE_READ_DATA | XP_FILE_READ_ATTRIBUTES | XP_FILE_READ_EA | XP_SYNCHRONIZE)/*!< \brief Standard Rights: Open for read */
//#define XP_FILE_GENERIC_WRITE (XP_STANDARD_RIGHTS_WRITE | XP_FILE_WRITE_DATA | XP_FILE_WRITE_ATTRIBUTES | XP_FILE_WRITE_EA | XP_FILE_APPEND_DATA | XP_SYNCHRONIZE)/*!< \brief Standard Rights: Open for write */
//
//#define XP_CREATE_NEW          1	  /*!< \brief File Open Options: Create new file - fail if exists */
//#define XP_CREATE_ALWAYS       2	  /*!< \brief File Open Options: Always create new file */
//#define XP_OPEN_EXISTING       3	  /*!< \brief File Open Options: Only open existing files */
//#define XP_OPEN_ALWAYS         4	  /*!< \brief File Open Options: Open existing or create new */
//#define XP_TRUNCATE_EXISTING   5	  /*!< \brief File Open Options: Open existing but truncate it first */
//
//#define XP_FILE_BEGIN          0	  /*!< \brief Set File Position Mode: From beginning of the file */
//#define XP_FILE_CURRENT        1	  /*!< \brief Set File Position Mode: From the current position */
//#define XP_FILE_END            2	  /*!< \brief Set File Position Mode: From the end of the file */
//
//#ifdef _WIN32
///// <summary>A macro that defines cross platform path separator character.</summary>
//#define XP_PATH_SEP_CHAR '\\'
///// <summary>A macro that defines cross platform path separator string.</summary>
//#define XP_PATH_SEP_STR "\\"
///// <summary>A macro that defines cross platform pathlist separator.</summary>
//#define XP_PATHLIST_SEPARATOR ';'
//#else
//#define XP_PATH_SEP_CHAR '/'
//#define XP_PATH_SEP_STR "/"
//#define XP_PATHLIST_SEPARATOR ':'
//#endif
//
//#define XP_INVALID_FILE_SIZE (0xffffffff)	/*!< \brief Error code indicating that the file size is invalid */



	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Cross platform function to split a path into its component parts.</summary>
	///
	/// <param name="inPath">Full pathname of the in file.</param>
	/// <param name="path">  [in,out] The drive and path portion.</param>
	/// <param name="name">  [in,out] The file name.</param>
	/// <param name="ext">   [in,out] The extension.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void VEILCORE_API xp_SplitPath(const tsCryptoStringBase &inPath, tsCryptoStringBase &path, tsCryptoStringBase &name, tsCryptoStringBase &ext);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Cross platform function to get the last OS error number.</summary>
	///
	/// <returns>The last OS error number.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	uint32_t VEILCORE_API xp_GetLastError();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Cross platform function to set the last OS error number.</summary>
	///
	/// <param name="setTo">The value.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void VEILCORE_API xp_SetLastError(uint32_t setTo);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Cross platform function to get the path to the root of the boot drive.</summary>
	///
	/// <param name="path">[in,out] Full pathname of the file.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool VEILCORE_API xp_GetBootDriveRoot(tsCryptoStringBase &path);

	/**
	* \brief Reads a file and splits it up into a vector of the text lines in the file.
	*
	* \param filename		    Filename of the file.
	* \param [in,out] contents The contents.
	*
	* \return true if it succeeds, false if it fails.
	*/
	extern bool VEILCORE_API xp_ReadAllTextLines(const tsCryptoStringBase& filename, tsCryptoStringList& contents);
	/**
	* \brief Converts a string into a vector of all of the text lines.
	*
	* \param input			    The input.
	* \param [in,out] contents The contents.
	*
	* \return true if it succeeds, false if it fails.
	*/
	extern bool VEILCORE_API xp_StringToTextLines(const tsCryptoStringBase& input, tsCryptoStringList& contents);

	bool VEILCORE_API xp_ReadAllText(const tsCryptoStringBase& filename, tsCryptoStringBase& contents);
	bool VEILCORE_API xp_ReadAllBytes(const tsCryptoStringBase& filename, tsCryptoData& contents);
}
#endif // __XP_FILE_H__

