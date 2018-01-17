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

// For compilers that support precompilation, includes "wx/wx.h".
#include "stdafx.h"

////@begin includes
#include "wx/imaglist.h"
////@end includes

////@begin XPM images
////@end XPM images


/*
 * AboutCKM type definition
 */

IMPLEMENT_DYNAMIC_CLASS( AboutCKM, wxDialog )


/*
 * AboutCKM event table definition
 */

BEGIN_EVENT_TABLE( AboutCKM, wxDialog )

////@begin AboutCKM event table entries
    EVT_BUTTON( wxID_OK, AboutCKM::OnOkClick )
////@end AboutCKM event table entries

END_EVENT_TABLE()


/*
 * AboutCKM constructors
 */

AboutCKM::AboutCKM()
{
    Init();
}

AboutCKM::AboutCKM( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * AboutCKM creator
 */

bool AboutCKM::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin AboutCKM creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end AboutCKM creation
    return true;
}


/*
 * AboutCKM destructor
 */

AboutCKM::~AboutCKM()
{
////@begin AboutCKM destruction
////@end AboutCKM destruction
}


/*
 * Member initialisation
 */

void AboutCKM::Init()
{
////@begin AboutCKM member initialisation
    lblAppName = NULL;
    lblVersion = NULL;
    lblCopyright = NULL;
////@end AboutCKM member initialisation

	_appName = "VEIL";
}


/*
 * Control creation for AboutCKM
 */

void AboutCKM::CreateControls()
{    
////@begin AboutCKM content construction
    AboutCKM* itemDialog1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(6, 1, 0, 0);
    itemDialog1->SetSizer(itemFlexGridSizer2);

    wxPanel* itemPanel3 = new wxPanel( itemDialog1, ID_PANEL3, wxDefaultPosition, wxDefaultSize, wxNO_BORDER|wxTAB_TRAVERSAL );
    itemPanel3->SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY);
    itemPanel3->SetBackgroundColour(wxColour(255, 255, 255));
    itemFlexGridSizer2->Add(itemPanel3, 0, wxGROW|wxALIGN_TOP|wxBOTTOM, 5);

    wxFlexGridSizer* itemFlexGridSizer4 = new wxFlexGridSizer(1, 1, 0, 0);
    itemPanel3->SetSizer(itemFlexGridSizer4);

    wxStaticBitmap* itemStaticBitmap5 = new wxStaticBitmap( itemPanel3, wxID_STATIC, itemDialog1->GetBitmapResource(wxT("tecseclogo.xpm")), wxDefaultPosition, wxSize(372, 73), 0 );
    itemFlexGridSizer4->Add(itemStaticBitmap5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 0);

    itemFlexGridSizer4->AddGrowableRow(0);
    itemFlexGridSizer4->AddGrowableCol(0);

    wxBoxSizer* itemBoxSizer6 = new wxBoxSizer(wxHORIZONTAL);
    itemFlexGridSizer2->Add(itemBoxSizer6, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    lblAppName = new wxStaticText( itemDialog1, wxID_STATIC, _("VEIL"), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer6->Add(lblAppName, 0, wxALIGN_CENTER_VERTICAL|wxLEFT|wxTOP|wxBOTTOM, 5);

    wxStaticText* itemStaticText8 = new wxStaticText( itemDialog1, wxID_STATIC, wxGetTranslation(wxString(wxT("-  a CKM ")) + (wxChar) 0x00AE + wxT(" enabled application")), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer6->Add(itemStaticText8, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5);

    lblVersion = new wxStaticText( itemDialog1, wxID_VERSIONSTRING, _("Fill me in"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(lblVersion, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    lblCopyright = new wxStaticText( itemDialog1, wxID_COPYRIGHTSTRING, _("Fill me in"), wxDefaultPosition, wxDefaultSize, 0 );
    lblCopyright->Wrap(360);
    itemFlexGridSizer2->Add(lblCopyright, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxNotebook* itemNotebook11 = new wxNotebook( itemDialog1, ID_NOTEBOOK, wxDefaultPosition, wxSize(480, 200), wxBK_DEFAULT );

    wxPanel* itemPanel12 = new wxPanel( itemNotebook11, ID_PANEL2, wxDefaultPosition, wxDefaultSize, wxSUNKEN_BORDER|wxTAB_TRAVERSAL );
    itemPanel12->SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY);
    wxFlexGridSizer* itemFlexGridSizer13 = new wxFlexGridSizer(1, 1, 0, 0);
    itemPanel12->SetSizer(itemFlexGridSizer13);

    wxHtmlWindow* itemHtmlWindow14 = new wxHtmlWindow( itemPanel12, ID_HTMLWINDOW1, wxDefaultPosition, wxSize(200, 150), wxHW_SCROLLBAR_AUTO|wxSUNKEN_BORDER|wxHSCROLL|wxVSCROLL );
    itemHtmlWindow14->SetPage(_("<medium>The VEIL suite includes KeyVEIL, OpenVEIL, OpaqueVEIL and more.<br><br>\nVEIL, CKM and Constructive Key Management are registered trademarks of TecSec, Inc.<br><br>\nWarning: All VEIL and CKM programs are protected by copyright law and international treaties. Unauthorized reproduction or distribution of these programs or any portion of them may result in civil and criminal penalties, and will be prosecuted to the fullest extent possible under law.<br></medium>"));
    itemFlexGridSizer13->Add(itemHtmlWindow14, 0, wxGROW, 5);

    itemFlexGridSizer13->AddGrowableRow(0);
    itemFlexGridSizer13->AddGrowableCol(0);

    itemNotebook11->AddPage(itemPanel12, _("Copyright"));

    wxPanel* itemPanel15 = new wxPanel( itemNotebook11, ID_PANEL, wxDefaultPosition, wxDefaultSize, wxSUNKEN_BORDER|wxTAB_TRAVERSAL );
    itemPanel15->SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY);
    wxFlexGridSizer* itemFlexGridSizer16 = new wxFlexGridSizer(1, 1, 0, 0);
    itemPanel15->SetSizer(itemFlexGridSizer16);

    wxHtmlWindow* itemHtmlWindow17 = new wxHtmlWindow( itemPanel15, ID_HTMLWINDOW2, wxDefaultPosition, wxSize(200, 150), wxHW_SCROLLBAR_AUTO|wxSUNKEN_BORDER|wxHSCROLL|wxVSCROLL );
    itemHtmlWindow17->SetPage(_("This product is protected by one or more of the following U.S. patents, as well as pending U.S. patent applications and foreign patents:<br><br>5,369,702; 5,369,707; 5,375,169; 5,410,599; 5,432,851; 5,440,290; 5,680,452; 5,787,173; 5,898,781; 6,075,865; 6,229,445; 6,266,417; 6,490,680; 6,542,608; 6,549,623; 6,606,386; 6,608,901; 6,684,330; 6,694,433; 6,754,820; 6,845,453; 6,868,598; 7,016,495; 7,069,448; 7,079,653; 7,089,417; 7,095,851; 7,095,852; 7,111,173; 7,131,009; 7,178,030; 7,212,632; 7,490,240; 7,539,855; 7,738,660 ;7,817,800; 7,974,410; 8,077,870; 8,083,808; 8,285,991; 8,308,820; 8,712,046"));
    itemFlexGridSizer16->Add(itemHtmlWindow17, 0, wxGROW, 5);

    itemFlexGridSizer16->AddGrowableRow(0);
    itemFlexGridSizer16->AddGrowableCol(0);

    itemNotebook11->AddPage(itemPanel15, _("Patents"));

    wxPanel* itemPanel18 = new wxPanel( itemNotebook11, ID_PANEL1, wxDefaultPosition, wxDefaultSize, wxSUNKEN_BORDER|wxTAB_TRAVERSAL );
    itemPanel18->SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY);
    wxFlexGridSizer* itemFlexGridSizer19 = new wxFlexGridSizer(0, 1, 0, 0);
    itemPanel18->SetSizer(itemFlexGridSizer19);

    wxHtmlWindow* itemHtmlWindow20 = new wxHtmlWindow( itemPanel18, ID_HTMLWINDOW, wxDefaultPosition, wxSize(200, 150), wxHW_SCROLLBAR_AUTO|wxSUNKEN_BORDER|wxHSCROLL|wxVSCROLL );
    itemHtmlWindow20->SetPage(_("Portions of the may include software from the following owners:<br>\n<hr>\n<strong>ConvertUTF.h, ConvertUTF.cpp</strong><br>\n<br>\nCopyright 2001-2004 Unicode, Inc.<br>\n<br>\nDisclaimer<br>\n<br>\nThis source code is provided as is by Unicode, Inc. No claims are made as to fitness for any particular purpose. No warranties of any kind are expressed or implied. The recipient agrees to determine applicability of information provided. If this file has been purchased on magnetic or optical media from Unicode, Inc., the sole remedy for any claim will be exchange of defective media within 90 days of receipt.<br>\n<br>\nLimitations on Rights to Redistribute This Code<br>\n<br>\nUnicode, Inc. hereby grants the right to freely use the information supplied in this file in the creation of products supporting the Unicode Standard, and to make copies of this file in any form for internal or external distribution as long as this notice remains attached.<br>\n<hr>\n<strong>SimpleOpt.h</strong><br>\n <br>\nCopyright (c) 2006-2013, Brodie Thiesfield<br>\n<br>\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \"Software\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:<br>\n<br>\nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.<br>\n<br>\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.<br>\n<hr>\n<strong>bzip2 (Modified for the build environment)</strong><br>\n<br>\nThis program, \"bzip2\", the associated library \"libbzip2\", and all documentation, are copyright (C) 1996-2010 Julian R Seward.  All rights reserved.<br>\n<br>\nRedistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:<br>\n<br>\n1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.<br>\n<br>\n2. The origin of this software must not be misrepresented; you must not claim that you wrote the original software.  If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.<br>\n<br>\n3. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.<br>\n<br>\n4. The name of the author may not be used to endorse or promote products derived from this software without specific prior written permission.<br>\n<br>\nTHIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.<br>\n<br>\nJulian Seward, jseward@bzip.org<br>\nbzip2/libbzip2 version 1.0.6 of 6 September 2010<br>\n<hr>\n<strong>zlib (Modified for the build environment)</strong><br>\n<br>\nCopyright (C) 1995-2013 Jean-loup Gailly and Mark Adler<br>\n<br>\nThis software is provided 'as-is', without any express or implied warranty.  In no event will the authors be held liable for any damages arising from the use of this software.<br>\n<br>\nPermission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:<br>\n<br>\n1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.<br>\n2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.<br>\n3. This notice may not be removed or altered from any source distribution.<br>\n<br>\nJean-loup Gailly        Mark Adler<br>\njloup@gzip.org          madler@alumni.caltech.edu<br>\n<hr>  \n<strong>aes.h aes_modes.cpp aes_via_ace.h aescpp.hasaescrypt.cpp aeskey.cpp aesopt.h aestab.cpp aestag.h gcm.cpp gcm.h gf_mul_lo.h gf128mul.cpp gf128mul.h mode_hdr.h brg_endian.h brg_types.h</strong><br/\n<br>\n(modufied for the build environment and added aesni support)<br>\n<br>\nCopyright (c) 1998-2008, Brian Gladman, Worcester, UK. All rights reserved.<br>\n<br>\nLICENSE TERMS<br>\n<br>\nThe redistribution and use of this software (with or without changes) is allowed without the payment of fees or royalties provided that:<br>\n<br>\n1. source code distributions include the above copyright notice, this list of conditions and the following disclaimer;<br>\n<br>\n2. binary distributions include the above copyright notice, this list of conditions and the following disclaimer in their documentation;<br>\n<br>\n3. the name of the copyright holder is not used to endorse products built using this software without specific written permission.<br>\n<br>\nDISCLAIMER<br>\n<br>\nThis software is provided 'as is' with no explicit or implied warranties in respect of its properties, including, but not limited to, correctness and/or fitness for purpose.<br>\n<hr>\n<strong>hmac.h sha2.cpp sha2.h</strong> (modufied for the build environment)<br>\n<br>\nCopyright (c) 2002, Dr Brian Gladman, Worcester, UK.   All rights reserved.<br>\n<br>\nLICENSE TERMS\n<br>\nThe free distribution and use of this software in both source and binary form is allowed (with or without changes) provided that:<br>\n<br>\n1. distributions of this source code include the above copyright notice, this list of conditions and the following disclaimer;<br>\n<br>\n2. distributions in binary form include the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other associated materials;<br>\n<br>\n3. the copyright holder's name is not used to endorse products built using this software without specific written permission.<br>\n<br>\nALTERNATIVELY, provided that this notice is retained in full, this product may be distributed under the terms of the GNU General Public License (GPL), in which case the provisions of the GPL apply INSTEAD OF those given above.<br>\n<br>\nDISCLAIMER<br>\n<br>\nThis software is provided 'as is' with no explicit or implied warranties in respect of its properties, including, but not limited to, correctness and/or fitness for purpose.<br>\n<hr>\n<strong>pevents.h pevents.cpp</strong>\n<br>\n* Author: Mahmoud Al-Qudsi <mqudsi@neosmart.net><br>\n* Copyright (C) 2011 - 2013 by NeoSmart Technologies<br>\n* This code is released under the terms of the MIT License<br>\n<hr>\n<strong>nargv.h  nargv.cpp</strong><br>\n<br>\n    //============================================================================<br>\n    // Name         : nargv.c<br>\n    // Author       : Triston J. Taylor (pc.wiz.tt@gmail.com)<br>\n    // Version      : 2.0<br>\n    // Copyright    : (C) Triston J. Taylor 2012. All Rights Reserved<br>\n    //============================================================================<br>"));
    itemFlexGridSizer19->Add(itemHtmlWindow20, 0, wxGROW, 5);

    itemFlexGridSizer19->AddGrowableRow(0);
    itemFlexGridSizer19->AddGrowableCol(0);

    itemNotebook11->AddPage(itemPanel18, _("Open Source"));

    itemFlexGridSizer2->Add(itemNotebook11, 0, wxGROW|wxALL, 5);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer21 = new wxStdDialogButtonSizer;

    itemFlexGridSizer2->Add(itemStdDialogButtonSizer21, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);
    wxButton* itemButton22 = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer21->AddButton(itemButton22);

    itemStdDialogButtonSizer21->Realize();

    itemFlexGridSizer2->AddGrowableRow(4);
    itemFlexGridSizer2->AddGrowableCol(0);

////@end AboutCKM content construction
	lblVersion->SetLabel(VEILWXWINDOWS_FULL_VERSION);
	lblCopyright->SetLabel(VEIL_COPYRIGHT);
	lblAppName->SetLabel(_appName.c_str());
}

void AboutCKM::SetAppName(const tscrypto::tsCryptoString& setTo)
{
	_appName = setTo;
	if (lblAppName != nullptr)
	{
		lblAppName->SetLabel(_appName.c_str());
	}
}

/*
 * Should we show tooltips?
 */

bool AboutCKM::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap AboutCKM::GetBitmapResource( const wxString& name )
{
    return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon AboutCKM::GetIconResource( const wxString& name )
{
	return ::GetIconResource(name);
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
 */

void AboutCKM::OnOkClick( wxCommandEvent& event )
{
	EndDialog(wxID_OK);
}

