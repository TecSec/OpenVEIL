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

#include "stdafx.h"
#include <CommCtrl.h>
#include "resource.h"
#include "TSGrid.h"

class AttributeSelectorGrid : public IAttributeSelector, public tsmod::IObject
{
public:
	AttributeSelectorGrid() : _parent(nullptr), _himl(NULL), _selectedAttributeCount(0), _cryptoGroup(nullptr)
	{}
	virtual ~AttributeSelectorGrid(){}

	// IVEILUIBase
	virtual void Destroy()
	{
		_parent = XP_WINDOW_INVALID;
		_session.reset();
		_cryptoGroupId.clear();
		_ckm7group.reset();
		_attrsList.reset();
		_GuidMap.clear();
		_cryptoGroup = nullptr;
		_himl = NULL;
		_cryptoGroup = nullptr;
		_selectedAttributeCount = 0;
	}
	virtual int  DisplayModal() override
	{
		if (_parent == XP_WINDOW_INVALID)
			_parent = (XP_WINDOW)GetActiveWindow();
		return (int)DialogBoxParamA((HINSTANCE)hDllInstance, MAKEINTRESOURCEA(IDD_ATTRIBUTE_SELECTOR_GRID), (HWND)_parent, SelectAttributesGridProc, (LPARAM)this);
	}
	virtual int  DisplayModal(XP_WINDOW wnd) override
	{
		_parent = wnd;
		return DisplayModal();
	}

	// IAudienceSelector
	virtual bool Start(std::shared_ptr<IKeyVEILSession> session, XP_WINDOW parent, const tscrypto::tsCryptoData& CryptoGroupId, std::shared_ptr<ICmsHeaderAttributeGroup> group, std::shared_ptr<ICmsHeaderAttributeListExtension> attrList) override
	{
		INITCOMMONCONTROLSEX icc;

		icc.dwSize = sizeof(icc);
		icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES | ICC_TAB_CLASSES | ICC_WIN95_CLASSES;
		InitCommonControlsEx(&icc);
		if (!session || !group)
			return false;

		if (!session->IsLoggedIn())
			return false;

		_cryptoGroupId = CryptoGroupId;
		_ckm7group = group;
		_attrsList = attrList;
		_session = session;
		_selectedAttributeCount = 0;

		_himl = ImageList_LoadBitmap((HINSTANCE)hDllInstance, MAKEINTRESOURCE(IDB_ATTR_ACCESS), 26, 0, CLR_NONE);
		return true;
	}
protected:
	XP_WINDOW											_parent;
	std::shared_ptr<IKeyVEILSession>					_session;
    tscrypto::tsCryptoData								_cryptoGroupId;
	std::shared_ptr<ICmsHeaderAttributeGroup>			_ckm7group;
	std::shared_ptr<ICmsHeaderAttributeListExtension>	_attrsList;
	std::vector<tscrypto::tsCryptoData>					_GuidMap;
	HIMAGELIST											_himl;
	Asn1::CTS::_POD_CryptoGroup*						_cryptoGroup;
	int													_selectedAttributeCount;
	std::shared_ptr<Asn1::CTS::_POD_Profile>			_profile;


	void MarkIncomingAttributes(HWND hWnd)
	{
		HWND hGrd = GetDlgItem(hWnd, IDC_SELECT_ATTRIBUTE_GRID);
		int count;
		char name[512];
		tscrypto::tsCryptoString wName;
		int rowCount;
		int colCount;
		int id;

		if (!_ckm7group || !_attrsList)
			return;

		// CKM 7
		count = (int)_ckm7group->GetAttributeCount();

		rowCount = (int)SendMessage(hGrd, GM_GETROWCOUNT, 0, 0);
		colCount = (int)SendMessage(hGrd, GM_GETCOLCOUNT, 0, 0);

		for (int row = 0; row < rowCount; row++)
		{
			for (int col = 0; col < colCount; col++)
			{
				name[0] = 0;
				SendMessage(hGrd, GM_GETCELLDATA, (row << 16) | col, (LPARAM)name);
				id = (int)SendMessage(hGrd, GM_GETCELLITEMDATA, (row << 16) | col, 0);
				if (name[0] == '-')
				{
					tscrypto::tsCryptoData attributeGuid = _GuidMap[id];
					std::shared_ptr<ICmsHeaderAttribute> attr;

					for (int i = 0; i < count; i++)
					{
						attr.reset();

						if (_attrsList->GetAttribute(_ckm7group->GetAttributeIndex(i), attr) && attr->GetAttributeId() == attributeGuid)
						{
							_selectedAttributeCount++;
							name[0] = '+';
							SendMessage(hGrd, GM_SETCELLDATA, (row << 16) | col, (LPARAM)name);
							break;
						}
					}
				}
			}
		}
	}

	std::vector<Asn1::CTS::_POD_Category*> BuildCategoryList(Asn1::CTS::_POD_CryptoGroup* cryptoGroup)
	{
		std::vector<Asn1::CTS::_POD_Category*> tmp;

		if (cryptoGroup->exists_FiefdomList())
		{
			for (uint32_t i = 0; i < cryptoGroup->get_FiefdomList()->size(); i++)
			{
				Asn1::CTS::_POD_Fiefdom& fief = cryptoGroup->get_FiefdomList()->get_at(i);
				if (fief.exists_CategoryList())
				{
					for (uint32_t j = 0; j < fief.get_CategoryList()->size(); j++)
					{
						tmp.push_back(&fief.get_CategoryList()->get_at(j));
					}
				}
			}
		}
		return tmp;
	}

	void FillGrid(HWND hWnd, Asn1::CTS::_POD_CryptoGroup* cryptoGroup)
	{
		int count;
		int i;
		std::vector<Asn1::CTS::_POD_Category*> catList;
		Asn1::CTS::_POD_Category* cat;
		tscrypto::tsCryptoString name;
		HWND hGrd = GetDlgItem(hWnd, IDC_SELECT_ATTRIBUTE_GRID);
		COLUMN col;
		int maxAttrCount = 0;
		int attributeCount = 0;
		int column;
		//ROWCOLOR rowcolor = {0xFF0000, 0x00FFFF};

		if (!IsWindow(hGrd))
			return;

		SendMessage(hGrd, GM_RESETCOLUMNS, 0, 0);
		SendMessage(hGrd, GM_SETBACKCOLOR, 0xf0f0f0, 0);
		SendMessage(hGrd, GM_SETGRIDCOLOR, 0, 0);
		//    SendMessage(hGrd,GM_SETTEXTCOLOR,0x000000,0);

		col.colwt = 87;
		col.halign = GA_ALIGN_CENTER;
		col.calign = GA_ALIGN_LEFT;
		col.ctype = TYPE_SELTEXT;
		col.ctextmax = 50;
		col.lpszformat = 0;
		col.himl = 0;
		col.hdrflag = 0;
		col.colxp = 0;
		col.edthwnd = 0;
		col.lParam = 0;

		_GuidMap.clear();

		if (cryptoGroup != NULL)
		{
			catList = BuildCategoryList(cryptoGroup);
			count = (int)catList.size();
			for (i = 0; i < count; i++)
			{
				cat = catList[i];
				name = cat->get_Name();

				col.lParam = i;
				col.lpszhdrtext = (intptr_t)name.c_str();

				column = (int)SendMessage(hGrd, GM_ADDCOL, 0, (LPARAM)&col);
				if (cat->exists_AttributeList())
				{
					attributeCount = (int)cat->get_AttributeList()->size();

					int removeCount = 0;
					for (int j = 0; j < attributeCount; j++)
					{
						Asn1::CTS::_POD_Attribute& attr = cat->get_AttributeList()->get_at(j);
						if (!attr.get_hasWrite())
						{
							removeCount++;
						}
					}
					attributeCount -= removeCount;
				}
				else
					attributeCount = 0;

				if (attributeCount > maxAttrCount)
				{
					maxAttrCount = attributeCount;
				}
			}
			for (attributeCount = 0; attributeCount < maxAttrCount; attributeCount++)
			{
				SendMessage(hGrd, GM_ADDROW, 0, 0);
			}
			for (i = 0; i < count; i++)
			{
				memset(&col, 0, sizeof(col));

				if (SendMessage(hGrd, GM_GETCOLDATA, i, (LPARAM)&col) == 0)
				{
					cat = catList[col.lParam];
					if (cat != nullptr)
					{
						//
						// Now populate the rows for this column
						//
						int row = 0;
						if (cat->exists_AttributeList())
						{
							attributeCount = (int)cat->get_AttributeList()->size();
							for (int j = 0; j < attributeCount; j++)
							{
								Asn1::CTS::_POD_Attribute& attr = cat->get_AttributeList()->get_at(j);
								name = attr.get_Name();
								name.prepend("-");

								if (attr.get_hasWrite())
								{
									SendMessage(hGrd, GM_SETCELLDATA, (row << 16) | i, (LPARAM)name.c_str());

									_GuidMap.push_back(attr.get_Id());
									SendMessage(hGrd, GM_SETCELLITEMDATA, (row << 16) | i, (LPARAM)_GuidMap.size() - 1);
									row++;
								}
							}
						}
						SendMessage(hGrd, GM_COLUMNSORT, i, 0);
					}
				}
			}
		}
		else
			count = 0;
	}

	Asn1::CTS::_POD_CryptoGroup* GetCryptoGroupById(std::shared_ptr<IKeyVEILSession> session, const tscrypto::tsCryptoData& id)
	{
		if (!_profile->exists_cryptoGroupList())
			return nullptr;

		for (uint32_t i = 0; i < _profile->get_cryptoGroupList()->size(); i++)
		{
			Asn1::CTS::_POD_CryptoGroup* group = &_profile->get_cryptoGroupList()->get_at(i);

			if (!!group && group->get_Id() == id)
				return group;
		}
		return nullptr;
	}

	Asn1::CTS::_POD_CryptoGroup* GetCryptoGroup(std::shared_ptr<IKeyVEILSession> session, uint32_t index)
	{
		if (!_profile->exists_cryptoGroupList())
			return nullptr;

		if (index >= _profile->get_cryptoGroupList()->size())
			return nullptr;
		return &_profile->get_cryptoGroupList()->get_at(index);
	}

	Asn1::CTS::_POD_CryptoGroup* GetCryptoGroup(HWND hWnd, std::shared_ptr<IKeyVEILSession> session, const tscrypto::tsCryptoData& cgId)
	{
		//if (cgId == GUID_NULL)
		//	CryptoGroup = GetCryptoGroup(_session, (int)SendDlgItemMessage(hWnd, IDC_CRYPTOGROUPS, CB_GETITEMDATA, (int)SendDlgItemMessage(hWnd, IDC_CRYPTOGROUPS, CB_GETCURSEL, 0, 0), 0));
		//else
			return GetCryptoGroupById(session, cgId);
	}

	int FindAttrIndex(std::shared_ptr<ICmsHeaderAttributeListExtension> attrList, const tscrypto::tsCryptoData &id)
	{
		int count = (int)attrList->GetAttributeCount();
		std::shared_ptr<ICmsHeaderAttribute> attr;

		for (int i = 0; i < count; i++)
		{
			attr.reset();
			if (attrList->GetAttribute(i, attr) && attr->GetAttributeId() == id)
				return i;
		}
		count = attrList->AddAttribute();
		attr.reset();
		if (attrList->GetAttribute(count, attr) && attr->SetAttributeId(id) && attr->SetCryptoGroupNumber(0))
			return count;
		return -1;
	}

	static intptr_t CALLBACK	SelectAttributesGridProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		AttributeSelectorGrid *params = (AttributeSelectorGrid*)GetWindowLongPtr(hWnd, DWLP_USER);

		switch (msg)
		{
		case WM_INITDIALOG:
			params = (AttributeSelectorGrid*)lParam;

			params->_profile = params->_session->GetProfile();
			SetWindowLongPtr(hWnd, DWLP_USER, lParam);
			EnableWindow(GetDlgItem(hWnd, IDOK), FALSE);

			{
				HWINSTA station = GetProcessWindowStation();
				DWORD count;
				char buff[MAX_PATH + 1] = { 0, };

				memset(buff, 0, sizeof(buff));
				GetUserObjectInformationA(station, UOI_NAME, buff, sizeof(buff), &count);
				if (strstr(buff, "WinSta0") == NULL)
				{
					EndDialog(hWnd, IDCANCEL);
				}
			}

			if (params->_cryptoGroupId.size() == 0)
			{
				::MessageBox(hWnd, "You must specify the Crypto Group that is to be used.", "PROGRAMMING ERROR", MB_OK);
				//std::shared_ptr<Asn1::CTS::CryptoGroup> CryptoGroup;
				//int count;
				//int i;
				//tscrypto::tsCryptoString name;

				//EnableWindow(GetDlgItem(hWnd, IDC_CRYPTOGROUP_STATIC), FALSE);
				//ShowWindow(GetDlgItem(hWnd, IDC_CRYPTOGROUP_STATIC), SW_HIDE);
				//EnableWindow(GetDlgItem(hWnd, IDC_CRYPTOGROUPS), TRUE);
				//ShowWindow(GetDlgItem(hWnd, IDC_CRYPTOGROUPS), SW_SHOW);

				//std::shared_ptr<Asn1::CTS::Profile> profile = params->_session->GetProfile();

				//if (!!profile && profile->exists_cryptoGroupList())
				//{
				//	count = (int)profile->get_cryptoGroupList()->size();
				//	for (i = 0; i < count; i++)
				//	{
				//		CryptoGroup.reset();
				//		CryptoGroup = profile->get_cryptoGroupList()->get_ptr_at(i);
				//		name = CryptoGroup->get_Name();
				//		int index = (int)SendDlgItemMessageA(hWnd, IDC_CRYPTOGROUPS, CB_ADDSTRING, 0, LPARAM(name.c_str()));
				//		SendDlgItemMessage(hWnd, IDC_CRYPTOGROUPS, CB_SETITEMDATA, index, i);
				//	}
				//	if (SendDlgItemMessage(hWnd, IDC_CRYPTOGROUPS, CB_GETCOUNT, 0, 0) > 0)
				//	{
				//		SendDlgItemMessage(hWnd, IDC_CRYPTOGROUPS, CB_SETCURSEL, 0, 0);

				//		CryptoGroup.reset();
				//		params->GetCryptoGroup(hWnd, params->_session, params->_cryptoGroupId, CryptoGroup);
				//		params->FillGrid(hWnd, CryptoGroup);
				//	}
				//}
			}
			else
			{
				Asn1::CTS::_POD_CryptoGroup* CryptoGroup;
				tscrypto::tsCryptoString name;

				//EnableWindow(GetDlgItem(hWnd, IDC_CRYPTOGROUP_STATIC), TRUE);
				//ShowWindow(GetDlgItem(hWnd, IDC_CRYPTOGROUP_STATIC), SW_SHOW);
				//EnableWindow(GetDlgItem(hWnd, IDC_CRYPTOGROUPS), FALSE);
				//ShowWindow(GetDlgItem(hWnd, IDC_CRYPTOGROUPS), SW_HIDE);

				CryptoGroup = params->GetCryptoGroupById(params->_session, params->_cryptoGroupId);
				if (!CryptoGroup)
				{
					EndDialog(hWnd, IDCANCEL);
					return TRUE;
				}
				
				name = CryptoGroup->get_Name();
				//SetDlgItemTextA(hWnd, IDC_CRYPTOGROUP_STATIC, name.c_str());

				params->FillGrid(hWnd, CryptoGroup);
				params->MarkIncomingAttributes(hWnd);
			}
			EnableWindow(GetDlgItem(hWnd, IDOK), (params->_selectedAttributeCount > 0) ? TRUE : FALSE);
			return (intptr_t)TRUE;

		case WM_COMMAND:
			if (LOWORD(wParam) == IDOK && HIWORD(wParam) == BN_CLICKED)
			{
				Asn1::CTS::_POD_CryptoGroup* CryptoGroup;
				int rowCount;
				int colCount;
				HWND hGrd = GetDlgItem(hWnd, IDC_SELECT_ATTRIBUTE_GRID);
				char name[512];

				if (!!params->_ckm7group && !!params->_attrsList)
				{
					CryptoGroup = params->GetCryptoGroup(hWnd, params->_session, params->_cryptoGroupId);
					if (!CryptoGroup)
					{
						MessageBoxA(hWnd, "You must first select a cryptogroup.", "Error", MB_OK);
						return TRUE;
					}

					while (params->_ckm7group->GetAttributeCount() > 0)
						params->_ckm7group->RemoveAttributeIndex(0);

					rowCount = (int)SendMessage(hGrd, GM_GETROWCOUNT, 0, 0);
					colCount = (int)SendMessage(hGrd, GM_GETCOLCOUNT, 0, 0);

					for (int col = 0; col < colCount; col++)
					{
						for (int row = 0; row < rowCount; row++)
						{
							name[0] = 0;
							SendMessage(hGrd, GM_GETCELLDATA, (row << 16) | col, (LPARAM)name);
							if (name[0] == '+')
							{
                                tscrypto::tsCryptoData attributeGuid = params->_GuidMap[(int)SendMessage(hGrd, GM_GETCELLITEMDATA, (row << 16) | col, 0)];

								int idx = params->FindAttrIndex(params->_attrsList, attributeGuid);

								if (idx >= 0)
									params->_ckm7group->AddAttributeIndex(idx);
							}
						}
					}
					params->_cryptoGroupId = CryptoGroup->get_Id();
				}
				else
				{
				}
				EndDialog(hWnd, IDOK);
				return TRUE;
			}
			else if (LOWORD(wParam) == IDCANCEL && HIWORD(wParam) == BN_CLICKED)
			{
				EndDialog(hWnd, IDCANCEL);
			}
			//else if (LOWORD(wParam) == IDC_CRYPTOGROUPS && HIWORD(wParam) == CBN_SELCHANGE)
			//{
			//	std::shared_ptr<Asn1::CTS::CryptoGroup> CryptoGroup;

			//	params->GetCryptoGroup(hWnd, params->_session, params->_cryptoGroupId, CryptoGroup);
			//	params->FillGrid(hWnd, CryptoGroup);
			//}
			break;

		case WM_NOTIFY:
		{
			NMHDR *p = (NMHDR*)lParam;

			if (wParam == IDC_SELECT_ATTRIBUTE_GRID && p->code == GN_AFTEREDIT)
			{
				if (((char *)((GRIDNOTIFY*)p)->lpdata)[0] == '+')
					params->_selectedAttributeCount++;
				else if (((char *)((GRIDNOTIFY*)p)->lpdata)[0] == '-')
					params->_selectedAttributeCount--;
				EnableWindow(GetDlgItem(hWnd, IDOK), (params->_selectedAttributeCount > 0) ? TRUE : FALSE);
			}
		}
		break;

		}
		return (intptr_t)FALSE;
	}


};

tsmod::IObject* CreateAttributeSelectorGrid()
{
	return dynamic_cast<tsmod::IObject*>(new AttributeSelectorGrid());
}