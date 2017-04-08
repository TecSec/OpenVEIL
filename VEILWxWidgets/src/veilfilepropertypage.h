/////////////////////////////////////////////////////////////////////////////
// Name:        veilfilepropertypage.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     10/02/2016 15:13:35
// RCS-ID:      
// Copyright:   Copyright (c) 2017, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

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
