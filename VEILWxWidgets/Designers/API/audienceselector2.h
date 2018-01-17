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

#ifndef _AUDIENCESELECTOR2_H_
#define _AUDIENCESELECTOR2_H_


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
class TokenSelectionWizardPage;
class FavoriteSelectionPage;
class GroupEditorWizardPage;
class wxSimpleHtmlListBox;
class SaveSelectionWizardPage;
////@end forward declarations

/*!
 * Control identifiers
 */

////@begin control identifiers
#define ID_AUDIENCESELECTOR 10000
#define SYMBOL_AUDIENCESELECTOR2_IDNAME ID_AUDIENCESELECTOR
////@end control identifiers


/*!
 * AudienceSelector2 class declaration
 */

class AudienceSelector2 : public wxWizard
{    
    DECLARE_DYNAMIC_CLASS(AudienceSelector2)
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
	AudienceSelector2();
	AudienceSelector2( wxWindow* parent, wxWindowID id = SYMBOL_AUDIENCESELECTOR2_IDNAME, const wxPoint& pos = wxDefaultPosition );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_AUDIENCESELECTOR2_IDNAME, const wxPoint& pos = wxDefaultPosition );

    /// Destructor
    ~AudienceSelector2();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin AudienceSelector2 event handler declarations

    /// wxEVT_WIZARD_PAGE_CHANGED event handler for ID_AUDIENCESELECTOR
    void OnAudienceselectorPageChanged( wxWizardEvent& event );

    /// wxEVT_WIZARD_PAGE_CHANGING event handler for ID_AUDIENCESELECTOR
    void OnAudienceselectorPageChanging( wxWizardEvent& event );

    /// wxEVT_WIZARD_CANCEL event handler for ID_AUDIENCESELECTOR
    void OnAudienceselectorCancel( wxWizardEvent& event );

    /// wxEVT_WIZARD_FINISHED event handler for ID_AUDIENCESELECTOR
    void OnAudienceselectorFinished( wxWizardEvent& event );

    /// wxEVT_INIT_DIALOG event handler for ID_AUDIENCESELECTOR
    void OnInitDialog( wxInitDialogEvent& event );

////@end AudienceSelector2 event handler declarations

////@begin AudienceSelector2 member function declarations

    /// Runs the wizard
    bool Run();

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end AudienceSelector2 member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin AudienceSelector2 member variables
    KeyVEILWizardPage* _keyVeilPage;
    TokenSelectionWizardPage* _tokenPage;
    FavoriteSelectionPage* _favoriteSelectionPage;
    GroupEditorWizardPage* _accessGroupPage;
    SaveSelectionWizardPage* _savePage;
////@end AudienceSelector2 member variables
	audienceSelector2Variables* _vars;
	wxPanel* leftPanel;
	wxFlexGridSizer* leftPanelSizer;

	wxWizardPage *GetFirstPage() const;
	void setVariables(audienceSelector2Variables* inVars);
	void setupLeftPanel();
};

#endif // _AUDIENCESELECTOR2_H_
