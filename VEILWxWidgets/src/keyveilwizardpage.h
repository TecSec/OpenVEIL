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

#ifndef _KEYVEILWIZARDPAGE_H_
#define _KEYVEILWIZARDPAGE_H_


/*!
 * Includes
 */

////@begin includes
#include "wx/wizard.h"
////@end includes

/*!
 * Forward declarations
 */

////@begin forward declarations
class KeyVEILWizardPage;
////@end forward declarations

/*!
 * Control identifiers
 */

////@begin control identifiers
#define ID_KEYVEIL_LOGIN 10001
#define ID_KEYVEIL_URL 10005
#define ID_KEYVEIL_USER 10006
#define ID_KEYVEIL_PASSWORD 10007
#define ID_CONNECT 10016
////@end control identifiers


/*!
 * KeyVEILWizardPage class declaration
 */

class KeyVEILWizardPage: public wxWizardPage, public ISkippablePage
{    
    DECLARE_DYNAMIC_CLASS( KeyVEILWizardPage )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    KeyVEILWizardPage();

    KeyVEILWizardPage( wxWizard* parent );

    /// Creation
    bool Create( wxWizard* parent );

    /// Destructor
    ~KeyVEILWizardPage();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin KeyVEILWizardPage event handler declarations

    /// wxEVT_WIZARD_PAGE_CHANGED event handler for ID_KEYVEIL_LOGIN
    void OnKeyveilLoginPageChanged( wxWizardEvent& event );

    /// wxEVT_WIZARD_PAGE_CHANGING event handler for ID_KEYVEIL_LOGIN
    void OnKeyveilLoginPageChanging( wxWizardEvent& event );

    /// wxEVT_WIZARD_FINISHED event handler for ID_KEYVEIL_LOGIN
    void OnKeyveilLoginFinished( wxWizardEvent& event );

    /// wxEVT_WIZARD_HELP event handler for ID_KEYVEIL_LOGIN
    void OnKeyveilLoginHelp( wxWizardEvent& event );

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_KEYVEIL_URL
    void OnKeyveilUrlTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_KEYVEIL_USER
    void OnKeyveilUserTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_KEYVEIL_PASSWORD
    void OnKeyveilPasswordTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_CONNECT
    void OnConnectClick( wxCommandEvent& event );

////@end KeyVEILWizardPage event handler declarations

////@begin KeyVEILWizardPage member function declarations

    /// Gets the previous page
    virtual wxWizardPage* GetPrev() const;

    /// Gets the next page
    virtual wxWizardPage* GetNext() const;

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end KeyVEILWizardPage member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin KeyVEILWizardPage member variables
    wxTextCtrl* _txtKeyVEILUrl;
    wxTextCtrl* _txtUsername;
    wxTextCtrl* _txtPassword;
    wxButton* _btnConnect;
////@end KeyVEILWizardPage member variables
	wxWizardPage* nextPage;
	wxWizardPage* prevPage;
	void SetNextPage(wxWizardPage* setTo) { nextPage = setTo; }
	void SetPrevPage(wxWizardPage* setTo) { prevPage = setTo; }
	
	tscrypto::tsCryptoString _url;
    tscrypto::tsCryptoString _username;
    tscrypto::tsCryptoString _pinBuffer;
    bool _initialized;

	void updateControls();

	// Inherited via ISkippablePage
	virtual bool skipMe() override;
};

#endif
    // _KEYVEILWIZARDPAGE_H_
