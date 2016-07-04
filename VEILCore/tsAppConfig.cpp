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
#include <errno.h>

static bool buildAndTestPath(tsAppConfig::ConfigLocation location, const tscrypto::tsCryptoString &appName, tscrypto::tsCryptoString &pathStr)
{
	tscrypto::tsCryptoString path;

	pathStr.clear();
	switch (location)
	{
	case tsAppConfig::Policy:
		if (!xp_GetSpecialFolder(sft_PolicyData, path))
		{
			path.clear();
			return false;
		}
		break;

	case tsAppConfig::System:
		if (!xp_GetSpecialFolder(sft_CommonApplicationData, path))
		{
			path.clear();
			LOG(FrameworkError, "Unable to access the common application directory.");
			//                CkmError("Unable to access the common application directory.");
			return false;
		}
		break;
	case tsAppConfig::User:
		if (!xp_GetSpecialFolder(sft_UserConfigFolder, path))
		{
			path.clear();
			LOG(FrameworkError, "Unable to access the user config directory.");
			//                CkmError("Unable to access the user data directory.");
			return false;
		}
		break;
	case tsAppConfig::Public:
		if (!xp_GetSpecialFolder(sft_PublicDataFolder, path))
		{
			path.clear();
			LOG(FrameworkError, "Unable to access the public data directory.");
			//                CkmError("Unable to access the public data directory.");
			return false;
		}
		break;
	case tsAppConfig::ModuleFolder:
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
	path += ".conf";
//#endif

	pathStr = path;

	return (xp_FileExists(path) != FALSE);
}

tsAppConfig::ConfigLocation tsAppConfig::configExistsHere(const tscrypto::tsCryptoString &appName, tsAppConfig::ConfigLocation location)
{
	tscrypto::tsCryptoString path;

	switch (location)
	{
	case tsAppConfig::Policy:
		if (buildAndTestPath(Policy, appName, path))
			return Policy;
		break;
	case System:
		if (buildAndTestPath(System, appName, path))
			return System;
		break;
	case User:
		if (buildAndTestPath(User, appName, path))
			return User;
		break;
	case Public:
		if (buildAndTestPath(Public, appName, path))
			return Public;
		break;
	case SystemPublicUser:
		if (buildAndTestPath(System, appName, path))
			return System;
		if (buildAndTestPath(Public, appName, path))
			return Public;
		if (buildAndTestPath(User, appName, path))
			return User;
		break;
	case UserPublicSystem:
		if (buildAndTestPath(User, appName, path))
			return User;
		if (buildAndTestPath(Public, appName, path))
			return Public;
		if (buildAndTestPath(System, appName, path))
			return System;
		break;
	case UserPublic:
		if (buildAndTestPath(User, appName, path))
			return User;
		if (buildAndTestPath(Public, appName, path))
			return Public;
		break;
	case PublicUser:
		if (buildAndTestPath(Public, appName, path))
			return Public;
		if (buildAndTestPath(User, appName, path))
			return User;
		break;
	case ModuleFolder:
		if (buildAndTestPath(ModuleFolder, appName, path))
			return ModuleFolder;
		break;
	default:
		break;
	}
	return NotFound;
}

//void *tsAppConfig::operator new(size_t bytes) 
//{ 
//    return FrameworkAllocator(bytes); 
//}
//
//void tsAppConfig::operator delete(void *ptr) 
//{ 
//    return FrameworkDeallocator(ptr); 
//}

tscrypto::tsCryptoString tsAppConfig::filePath(const tscrypto::tsCryptoString &appName, ConfigLocation location)
{
	tscrypto::tsCryptoString path;

	switch (location)
	{
	case Policy:
		buildAndTestPath(Policy, appName, path);
		return path;
	case System:
		buildAndTestPath(System, appName, path);
		return path;
	case User:
		buildAndTestPath(User, appName, path);
		return path;
	case Public:
		buildAndTestPath(Public, appName, path);
		return path;
	case ModuleFolder:
		buildAndTestPath(ModuleFolder, appName, path);
		return path;
	case SystemPublicUser:
		if (buildAndTestPath(System, appName, path))
			return path;
		if (buildAndTestPath(Public, appName, path))
			return path;
		if (buildAndTestPath(User, appName, path))
			return path;
		break;
	case UserPublicSystem:
		if (buildAndTestPath(User, appName, path))
			return path;
		if (buildAndTestPath(Public, appName, path))
			return path;
		if (buildAndTestPath(System, appName, path))
			return path;
		break;
	case UserPublic:
		if (buildAndTestPath(User, appName, path))
			return path;
		if (buildAndTestPath(Public, appName, path))
			return path;
		break;
	case PublicUser:
		if (buildAndTestPath(Public, appName, path))
			return path;
		if (buildAndTestPath(User, appName, path))
			return path;
		break;
	default:
		break;
	}
	path.clear();
	return path;
}

tsAppConfig::tsAppConfig(const tscrypto::tsCryptoString &appName, ConfigLocation location)
{
	tscrypto::tsCryptoData contents;
	tscrypto::tsCryptoString results;
	int64_t len;

	m_root = tsXmlNode::Create();

	m_root->AddTsIDs(false);
	m_root->NodeName(appName);

	ConfigLocation foundHere = configExistsHere(appName, location);
	if (foundHere != NotFound)
	{
		switch (foundHere)
		{
		case Policy:
			buildAndTestPath(Policy, appName, m_path);
			break;
		case System:
			buildAndTestPath(System, appName, m_path);
			break;
		case User:
			buildAndTestPath(User, appName, m_path);
			break;
		case Public:
			buildAndTestPath(Public, appName, m_path);
			break;
		case ModuleFolder:
			buildAndTestPath(ModuleFolder, appName, m_path);
			break;
		}
	}
	else
	{
		switch (location)
		{
		case Policy:
			buildAndTestPath(Policy, appName, m_path);
			break;
		case System:
			buildAndTestPath(System, appName, m_path);
			break;
		case User:
			buildAndTestPath(User, appName, m_path);
			break;
		case Public:
			buildAndTestPath(Public, appName, m_path);
			break;
		case ModuleFolder:
			buildAndTestPath(ModuleFolder, appName, m_path);
			break;
		case SystemPublicUser:
			if (!buildAndTestPath(System, appName, m_path) && m_path.size() == 0 &&
				!buildAndTestPath(Public, appName, m_path) && m_path.size() == 0 &&
				!buildAndTestPath(User, appName, m_path))
			{
			}
			break;
		case UserPublicSystem:
			if (!buildAndTestPath(User, appName, m_path) && m_path.size() == 0 &&
				!buildAndTestPath(Public, appName, m_path) && m_path.size() == 0 &&
				!buildAndTestPath(System, appName, m_path))
			{
			}
			break;
		case UserPublic:
			if (!buildAndTestPath(User, appName, m_path) && m_path.size() == 0 &&
				!buildAndTestPath(Public, appName, m_path))
			{
			}
			break;
		case PublicUser:
			if (!buildAndTestPath(Public, appName, m_path) && m_path.size() == 0 &&
				!buildAndTestPath(User, appName, m_path))
			{
			}
			break;
		default:
			break;
		}
	}

	XP_FILE file = XP_FILE_INVALID;

	int retryCount;

	if (!xp_FileExists(m_path.c_str()))
	{
		//CkmDebug(DBG_INFO1, "Unable to open the application configuration file for read '%s'.  The file does not exist.", m_path.c_str());
		return;
	}
	for (retryCount = 0; retryCount < 10; retryCount++)
	{
		file = xp_CreateFile(m_path.c_str(), XP_GENERIC_READ, XP_FILE_SHARE_READ, NULL, XP_OPEN_EXISTING, XP_FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == XP_FILE_INVALID)
		{
			if (xp_GetLastError() != ERROR_SHARING_VIOLATION)
			{
				LOG(FrameworkError, "Unable to open the application configuration file for read " << m_path.c_str());
				//				CkmDebug(DBG_INFO1, "Unable to open the application configuration file for read '%s'.", m_path.c_str());
				return;
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
		LOG(FrameworkError, "Unable to open the application configuration file " << m_path.c_str() << " for read due to share violation.");
		//        CkmDebug(DBG_INFO1, "Unable to open the application configuration file '%s' for read due to share violation.", m_path.c_str());
		return;
	}

	len = xp_GetFileSize64FromHandle(file);
	if (len == 0 || len > 1000000)
	{
		xp_CloseFile(file);
		return;
	}
	contents.resize((unsigned int)len);
	uint32_t bytesRead;

	if (!xp_ReadFile(file, contents.rawData(), (uint32_t)len, &bytesRead, NULL) || bytesRead != (uint32_t)len)
	{
		LOG(FrameworkError, "Unable to read application configuration data " << m_path.c_str());
		//        CkmError("Unable to read application configuration data '%s'.", m_path.c_str());
		xp_CloseFile(file);
		return;
	}
	xp_CloseFile(file);
	if (!m_root->Parse(contents.ToUtf8String(), results, false, false))
	{
		LOG(FrameworkError, "Unable to parse application configuration data.");
		//        CkmError("Unable to parse application configuration data.");
		m_root->ClearChildren();
		m_root->Attributes().ClearAll();
	}
}

tsAppConfig::tsAppConfig(const tscrypto::tsCryptoString &appName, tsAppConfig::ConfigLocation location, tsAppConfig::ConfigLocation buildHere)
{
	tscrypto::tsCryptoData contents;
	tscrypto::tsCryptoString results;
	int64_t len;

	m_root = tsXmlNode::Create();
	m_root->AddTsIDs(false);
	m_root->NodeName(appName);

	ConfigLocation foundHere = configExistsHere(appName, location);
	if (foundHere != NotFound)
	{
		switch (foundHere)
		{
		case Policy:
			buildAndTestPath(Policy, appName, m_path);
			break;
		case System:
			buildAndTestPath(System, appName, m_path);
			break;
		case User:
			buildAndTestPath(User, appName, m_path);
			break;
		case Public:
			buildAndTestPath(Public, appName, m_path);
			break;
		case ModuleFolder:
			buildAndTestPath(ModuleFolder, appName, m_path);
			break;
		}
	}
	else
	{
		switch (buildHere)
		{
		case Policy:
			buildAndTestPath(Policy, appName, m_path);
			break;
		case System:
			buildAndTestPath(System, appName, m_path);
			break;
		case User:
			buildAndTestPath(User, appName, m_path);
			break;
		case Public:
			buildAndTestPath(Public, appName, m_path);
			break;
		case ModuleFolder:
			buildAndTestPath(ModuleFolder, appName, m_path);
			break;
		case SystemPublicUser:
			if (!buildAndTestPath(System, appName, m_path) && m_path.size() == 0 &&
				!buildAndTestPath(Public, appName, m_path) && m_path.size() == 0 &&
				!buildAndTestPath(User, appName, m_path))
			{
			}
			break;
		case UserPublicSystem:
			if (!buildAndTestPath(User, appName, m_path) && m_path.size() == 0 &&
				!buildAndTestPath(Public, appName, m_path) && m_path.size() == 0 &&
				!buildAndTestPath(System, appName, m_path))
			{
			}
			break;
		case UserPublic:
			if (!buildAndTestPath(User, appName, m_path) && m_path.size() == 0 &&
				!buildAndTestPath(Public, appName, m_path))
			{
			}
			break;
		case PublicUser:
			if (!buildAndTestPath(Public, appName, m_path) && m_path.size() == 0 &&
				!buildAndTestPath(User, appName, m_path))
			{
			}
			break;
		default:
			break;
		}
	}

	XP_FILE file = XP_FILE_INVALID;

	int retryCount;

	if (!xp_FileExists(m_path.c_str()))
	{
		//CkmDebug(DBG_INFO1, "Unable to open the application configuration file for read '%s'.  The file does not exist.", m_path.c_str());
		return;
	}
	for (retryCount = 0; retryCount < 10; retryCount++)
	{
		file = xp_CreateFile(m_path.c_str(), XP_GENERIC_READ, XP_FILE_SHARE_READ, NULL, XP_OPEN_EXISTING, XP_FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == XP_FILE_INVALID)
		{
			if (xp_GetLastError() != ERROR_SHARING_VIOLATION)
			{
				LOG(FrameworkError, "Unable to open the application configuration file for read " << m_path.c_str());
				//				CkmDebug(DBG_INFO1, "Unable to open the application configuration file for read '%s'.", m_path.c_str());
				return;
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
		LOG(FrameworkError, "Unable to open the application configuration file " << m_path.c_str() << " for read due to share violation.");
		//        CkmDebug(DBG_INFO1, "Unable to open the application configuration file '%s' for read due to share violation.", m_path.c_str());
		return;
	}

	len = xp_GetFileSize64FromHandle(file);
	if (len == 0 || len > 1000000)
	{
		xp_CloseFile(file);
		return;
	}
	contents.resize((unsigned int)len);
	uint32_t bytesRead;

	if (!xp_ReadFile(file, contents.rawData(), (uint32_t)len, &bytesRead, NULL) || bytesRead != (uint32_t)len)
	{
		LOG(FrameworkError, "Unable to read application configuration data " << m_path.c_str());
		//        CkmError("Unable to read application configuration data '%s'.", m_path.c_str());
		xp_CloseFile(file);
		return;
	}
	xp_CloseFile(file);
	if (!m_root->Parse(contents.ToUtf8String(), results, false, false))
	{
		LOG(FrameworkError, "Unable to parse application configuration data.");
		//        CkmError("Unable to parse application configuration data.");
		m_root->ClearChildren();
		m_root->Attributes().ClearAll();
	}
}

tsAppConfig::~tsAppConfig()
{
}

std::shared_ptr<tsXmlNode> tsAppConfig::Root()
{
	return m_root;
}

std::shared_ptr<tsXmlNode> tsAppConfig::Root() const
{
	return m_root;
}

std::shared_ptr<tsXmlNode> tsAppConfig::findNode(const tscrypto::tsCryptoString &nodeName, bool buildIt)
{
	tscrypto::tsCryptoString path = nodeName;
	char *context = NULL;
	std::shared_ptr<tsXmlNode> node = m_root;

	while (path.size() > 0 && path[0] == '/')
	{
		path.DeleteAt(0, 1);
	}
	while (path.size() > 0 && path[path.size() - 1] == '/')
	{
		path.resize(path.size() - 1);
	}

	char *p = TsStrTok(path.rawData(), ("/"), &context);

	if (p == NULL)
		return NULL;

	do
	{
		std::shared_ptr<tsXmlNode> node1 = node->ChildByName(p);

		if (node1 == NULL && buildIt)
		{
			node1 = node->StartSubnode(p);
		}
		node = node1;
		if (node1 == NULL)
			return node1;

		p = TsStrTok(NULL, ("/"), &context);
	} while (p != NULL);

	return node;
}

std::shared_ptr<tsXmlNode> tsAppConfig::findNode(const tscrypto::tsCryptoString &nodeName) const
{
	tscrypto::tsCryptoString path = nodeName;
	char *context = NULL;
	std::shared_ptr<tsXmlNode> node = m_root;

	while (path.size() > 0 && path[0] == '/')
	{
		path.DeleteAt(0, 1);
	}
	while (path.size() > 0 && path[path.size() - 1] == '/')
	{
		path.resize(path.size() - 1);
	}

	char *p = TsStrTok(path.rawData(), ("/"), &context);

	if (p == NULL)
		return NULL;

	do
	{
		std::shared_ptr<tsXmlNode> node1 = node->ChildByName(p);

		if (!node1)
		{
			return nullptr;
		}
		node = node1;
		p = TsStrTok(NULL, ("/"), &context);
	} while (p != NULL);

	return node;
}

tsXmlNodeList tsAppConfig::findNodes(const tscrypto::tsCryptoString &xpath)
{
	return m_root->findNodes(xpath);
}

tsXmlNodeList tsAppConfig::findNodes(const tscrypto::tsCryptoString &xpath) const
{
	return m_root->findNodes(xpath);
}

void tsAppConfig::deleteNode(const tscrypto::tsCryptoString &nodeName)
{
	std::shared_ptr<tsXmlNode> node = m_root->ChildByName(nodeName);

	if (!!node)
	{
		m_root->RemoveChild(node);
	}
}

std::shared_ptr<tsXmlNode> tsAppConfig::addNode(const tscrypto::tsCryptoString &nodeName)
{
	if (m_root->ChildByName(nodeName) != NULL)
		return m_root->ChildByName(nodeName);

	return m_root->StartSubnode(nodeName);
}
// krr added 12/02/09 Same as addNode(nodeName) except you can add duplicates
std::shared_ptr<tsXmlNode> tsAppConfig::addNode(const tscrypto::tsCryptoString &nodeName, bool bUnique)
{
	if (bUnique)
	{
		if (m_root->ChildByName(nodeName) != NULL)
			return m_root->ChildByName(nodeName);
	}

	return m_root->StartSubnode(nodeName);
}

bool tsAppConfig::Save()
{
	tscrypto::tsCryptoString xml;

	m_root->UseFormattedOutput(true);
	if (!m_root->BuildXML(xml, true))
	{
		FrameworkError << "Unable to build application configuration xml" << tscrypto::endl;
		//        CkmError("Unable to build application configuration xml");
		return false;
	}


	XP_FILE file = XP_FILE_INVALID;

	int retryCount;

	for (retryCount = 0; retryCount < 10; retryCount++)
	{
		file = xp_CreateFile(m_path.c_str(), XP_GENERIC_WRITE, 0, NULL, XP_CREATE_ALWAYS, XP_FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == XP_FILE_INVALID)
		{
			if (xp_GetLastError() != ERROR_SHARING_VIOLATION)
			{
				FrameworkError << "Unable to open the application configuration file " << m_path.c_str() << " for write." << tscrypto::endl;
				//				CkmDebug(DBG_INFO1, "Unable to open the application configuration file '%s' for write.", m_path.c_str());
				return false;
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
		FrameworkError << "Unable to open the application configuration file " << m_path.c_str() << " for write due to share violation." << tscrypto::endl;
		//        CkmDebug(DBG_INFO1, "Unable to open the application configuration file '%s' for write due to share violation.", m_path.c_str());
		return false;
	}
	uint32_t bytesWritten;

	tscrypto::tsCryptoData tmp;
	tmp.UTF8FromString(xml);

	if (!xp_WriteFile(file, tmp.c_str(), (uint32_t)tmp.size(), &bytesWritten, NULL) || bytesWritten != (uint32_t)tmp.size())
	{
		FrameworkError << "Unable to read application configuration data " << m_path.c_str() << tscrypto::endl;
		//        CkmError("Unable to read application configuration data '%s'.", m_path.c_str());
		xp_CloseFile(file);
		return false;
	}
	xp_CloseFile(file);
	return true;
}

tscrypto::tsCryptoString tsAppConfig::getNodeItem(const tscrypto::tsCryptoString &nodeName, const tscrypto::tsCryptoString &itemName) const
{
	std::shared_ptr<tsXmlNode> node;

	if ((node = findNode(nodeName)) == NULL)
		return "";

	if (node->Attributes().hasItem(itemName))
		return node->Attributes().item(itemName);
	return "";
}

int tsAppConfig::getNodeItemAsNumber(const tscrypto::tsCryptoString &nodeName, const tscrypto::tsCryptoString &itemName, int defaultValue) const
{
	std::shared_ptr<tsXmlNode> node;

	if ((node = findNode(nodeName)) == NULL)
		return defaultValue;

	return node->Attributes().itemAsNumber(itemName, defaultValue);
}

bool tsAppConfig::getNodeItemAsBool(const tscrypto::tsCryptoString &nodeName, const tscrypto::tsCryptoString &itemName, bool defaultValue) const
{
	std::shared_ptr<tsXmlNode> node;

	if ((node = findNode(nodeName)) == NULL)
		return defaultValue;

	return node->Attributes().itemAsNumber(itemName, defaultValue) != 0;
}

bool tsAppConfig::setNodeItem(const tscrypto::tsCryptoString &nodeName, const tscrypto::tsCryptoString &itemName, const tscrypto::tsCryptoString &value)
{
	std::shared_ptr<tsXmlNode> node;

	if ((node = findNode(nodeName, true)) == NULL)
	{
		node = addNode(nodeName);
	}
	if (node == NULL)
		return false;

	return node->Attributes().AddItem(itemName, value);
}

bool tsAppConfig::setNodeItemAsNumber(const tscrypto::tsCryptoString &nodeName, const tscrypto::tsCryptoString &itemName, int value)
{
	std::shared_ptr<tsXmlNode> node;

	if ((node = findNode(nodeName, true)) == NULL)
	{
		node = addNode(nodeName);
	}
	if (node == NULL)
		return false;

	return node->Attributes().AddItem(itemName, value);
}

bool tsAppConfig::setNodeItemAsBool(const tscrypto::tsCryptoString &nodeName, const tscrypto::tsCryptoString &itemName, bool value)
{
	std::shared_ptr<tsXmlNode> node;

	if ((node = findNode(nodeName, true)) == NULL)
	{
		node = addNode(nodeName);
	}
	if (node == NULL)
		return false;

	return node->Attributes().AddItem(itemName, value ? "1" : "0");
}

// 08/08/2010 added new member functions to support Nodes without attributes
bool tsAppConfig::setNodeText(const tscrypto::tsCryptoString &itemName, const tscrypto::tsCryptoString &itemValue)
{
	std::shared_ptr<tsXmlNode> node;

	if ((node = findNode(itemName, true)) == NULL)
	{
		node = addNode(itemName);
	}

	if (node == NULL)
		return false;

	return node->NodeText(itemValue);
}

// 08/08/2010 added new member functions to support Nodes without attributes
bool tsAppConfig::setNodeTextAsNumber(const tscrypto::tsCryptoString &itemName, int value)
{
	std::shared_ptr<tsXmlNode> node;

	if ((node = findNode(itemName, true)) == NULL)
	{
		node = addNode(itemName);
	}

	if (node == NULL)
		return false;

	tscrypto::tsCryptoString tmp;
	tmp << value;
	return node->NodeText(tmp);
}

bool tsAppConfig::setNodeTextAsBool(const tscrypto::tsCryptoString &itemName, bool value)
{
	std::shared_ptr<tsXmlNode> node;

	if ((node = findNode(itemName, true)) == NULL)
	{
		node = addNode(itemName);
	}

	if (node == NULL)
		return false;

	return node->NodeText(value ? "1" : "0");
}

// 08/09/2010 added new member functions to support Nodes without attributes
// 08/11/2010 KRR opps did not need itemValue and forgot const
tscrypto::tsCryptoString tsAppConfig::getNodeText(const tscrypto::tsCryptoString &itemName) const
{
	std::shared_ptr<tsXmlNode> node;
	const char *p;
	tscrypto::tsCryptoString tsNode;

	if ((node = findNode(itemName)) == NULL)
		return "";

	tsNode = node->NodeText();

	if (tsNode.length() > 0)
		p = tsNode.c_str();
	else
		p = ("");

	return p;
}

// 08/09/2010 added new member functions to support Nodes without attributes
int tsAppConfig::getNodeTextAsNumber(const tscrypto::tsCryptoString &itemName, int defaultValue) const
{
	std::shared_ptr<tsXmlNode> node;

	if ((node = findNode(itemName)) == NULL)
		return defaultValue;

	return TsStrToInt(node->NodeText().c_str());
}

bool tsAppConfig::getNodeTextAsBool(const tscrypto::tsCryptoString &itemName, bool defaultValue) const
{
	std::shared_ptr<tsXmlNode> node;

	if ((node = findNode(itemName)) == NULL)
		return defaultValue;

	return TsStrToInt(node->NodeText().c_str()) != 0;
}

tscrypto::tsCryptoString tsAppConfig::configFilePath() const
{
	return m_path;
}
