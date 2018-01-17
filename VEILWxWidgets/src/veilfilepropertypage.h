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

#ifndef _VEILFILEPROPERTYPAGE_H_
#define _VEILFILEPROPERTYPAGE_H_


/*!
 * Includes
 */

////@begin includes
#include "wx/valtext.h"
////@end includes

/*!
 * Forward declarations
 */

////@begin forward declarations
////@end forward declarations

/*!
 * Control identifiers
 */

////@begin control identifiers
#define ID_VEILFILEPROPERTYPAGE 10000
#define ID_OVERWRITE_EXISTING 10003
#define ID_CLOSE_WHEN_DONE 10004
#define ID_PASSES 10011
#define ID_DELETE_ENCRYPTION 10005
#define ID_DELETE_ON_DECRYPTION 10006
#define ID_COMPRESSION 10009
#define SYMBOL_VEILFILEPROPERTYPAGE_STYLE wxTAB_TRAVERSAL
#define SYMBOL_VEILFILEPROPERTYPAGE_TITLE _("File Encryption")
#define SYMBOL_VEILFILEPROPERTYPAGE_IDNAME ID_VEILFILEPROPERTYPAGE
#define SYMBOL_VEILFILEPROPERTYPAGE_SIZE wxSize(460, 290)
#define SYMBOL_VEILFILEPROPERTYPAGE_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * VEILFilePropertyPage class declaration
 */

class VEILFilePropertyPage: public wxPanel
{    
    DECLARE_DYNAMIC_CLASS( VEILFilePropertyPage )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    VEILFilePropertyPage();
    VEILFilePropertyPage( wxWindow* parent, wxWindowID id = SYMBOL_VEILFILEPROPERTYPAGE_IDNAME, const wxString& caption = SYMBOL_VEILFILEPROPERTYPAGE_TITLE, const wxPoint& pos = SYMBOL_VEILFILEPROPERTYPAGE_POSITION, const wxSize& size = SYMBOL_VEILFILEPROPERTYPAGE_SIZE, long style = SYMBOL_VEILFILEPROPERTYPAGE_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_VEILFILEPROPERTYPAGE_IDNAME, const wxString& caption = SYMBOL_VEILFILEPROPERTYPAGE_TITLE, const wxPoint& pos = SYMBOL_VEILFILEPROPERTYPAGE_POSITION, const wxSize& size = SYMBOL_VEILFILEPROPERTYPAGE_SIZE, long style = SYMBOL_VEILFILEPROPERTYPAGE_STYLE );

    /// Destructor
    ~VEILFilePropertyPage();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin VEILFilePropertyPage event handler declarations

    /// wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_OVERWRITE_EXISTING
    void OnOverwriteExistingClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_CLOSE_WHEN_DONE
    void OnCloseWhenDoneClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_PASSES
    void OnPassesTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_DELETE_ENCRYPTION
    void OnDeleteEncryptionClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_DELETE_ON_DECRYPTION
    void OnDeleteOnDecryptionClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_COMPRESSION
    void OnCompressionSelected( wxCommandEvent& event );

////@end VEILFilePropertyPage event handler declarations

////@begin VEILFilePropertyPage member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end VEILFilePropertyPage member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin VEILFilePropertyPage member variables
    wxCheckBox* chkOverwriteExisting;
    wxCheckBox* chkCloseWhenDone;
    wxTextCtrl* edtPasses;
    wxCheckBox* chkDeleteAfterEncryption;
    wxCheckBox* chkDeleteAfterDecryption;
    wxChoice* cmbCompression;
////@end VEILFilePropertyPage member variables
	int m_nSecureDelete;
	bool m_startOnLogin;
	bool m_bWindowsStart;
	//	CkmCompressionType m_Compress;
	int m_CompType;
	bool	m_bDelAftEnc;
	bool	m_bDelAftDec;
	bool	m_bCertEnc;
	bool	m_bCloseAft;
	bool	m_bOverWrite;
	wxString _passesStr;
	std::shared_ptr<BasicVEILPreferences> _prefs;
	bool _bInitialized;
	bool _bDirty;
	std::weak_ptr<IVEILPropertySheet> _parentSheet;

    void UpdateData(bool fromControls);
	void DisablePolicyField(wxWindow* hWnd, JsonConfigLocation location);
	void OnInitialize();
	void Initialization();
	void OnPrefChange();
	void SetModified(bool bChanged = true);
};

#endif
    // _VEILFILEPROPERTYPAGE_H_
