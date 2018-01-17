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

#ifndef _ATTRIBUTESELECTORGRID_H_
#define _ATTRIBUTESELECTORGRID_H_


/*!
 * Includes
 */


/*!
 * Forward declarations
 */

/*!
 * Control identifiers
 */

////@begin control identifiers
#define ID_ATTRIBUTESELECTORGRID 10000
#define ID_ATTR_SCROLLER 10003
#define ID_GRID 10002
#define SYMBOL_ATTRIBUTESELECTORGRID_STYLE wxDEFAULT_DIALOG_STYLE|wxCAPTION|wxRESIZE_BORDER|wxTAB_TRAVERSAL
#define SYMBOL_ATTRIBUTESELECTORGRID_TITLE _("Attribute Selector")
#define SYMBOL_ATTRIBUTESELECTORGRID_IDNAME ID_ATTRIBUTESELECTORGRID
#define SYMBOL_ATTRIBUTESELECTORGRID_SIZE wxSize(500, 350)
#define SYMBOL_ATTRIBUTESELECTORGRID_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * AttributeSelectorGrid class declaration
 */

class AttributeSelectorGrid: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( AttributeSelectorGrid )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    AttributeSelectorGrid();
    AttributeSelectorGrid( wxWindow* parent, wxWindowID id = SYMBOL_ATTRIBUTESELECTORGRID_IDNAME, const wxString& caption = SYMBOL_ATTRIBUTESELECTORGRID_TITLE, const wxPoint& pos = SYMBOL_ATTRIBUTESELECTORGRID_POSITION, const wxSize& size = SYMBOL_ATTRIBUTESELECTORGRID_SIZE, long style = SYMBOL_ATTRIBUTESELECTORGRID_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_ATTRIBUTESELECTORGRID_IDNAME, const wxString& caption = SYMBOL_ATTRIBUTESELECTORGRID_TITLE, const wxPoint& pos = SYMBOL_ATTRIBUTESELECTORGRID_POSITION, const wxSize& size = SYMBOL_ATTRIBUTESELECTORGRID_SIZE, long style = SYMBOL_ATTRIBUTESELECTORGRID_STYLE );

    /// Destructor
    ~AttributeSelectorGrid();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin AttributeSelectorGrid event handler declarations

    /// wxEVT_GRID_CELL_LEFT_CLICK event handler for ID_GRID
    void OnCellLeftClick( wxGridEvent& event );

    /// wxEVT_GRID_CELL_CHANGED event handler for ID_GRID
    void OnCellChanged( wxGridEvent& event );

    /// wxEVT_GRID_SELECT_CELL event handler for ID_GRID
    void OnSelectCell( wxGridEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
    void OnOkClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
    void OnCancelClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
    void OnHelpClick( wxCommandEvent& event );

////@end AttributeSelectorGrid event handler declarations

	void OnGridChar(wxKeyEvent& event);

////@begin AttributeSelectorGrid member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end AttributeSelectorGrid member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin AttributeSelectorGrid member variables
    wxScrolledWindow* _scrollGridWindow;
    wxFlexGridSizer* _szGrids;
    wxButton* btnOK;
    ////@end AttributeSelectorGrid member variables

	//    std::vector<GUID>									_GuidMap;
	//    wxImageList											_imageList;
	//    Asn1::CTS::_POD_CryptoGroup*						_cryptoGroup;
	//    std::vector<Asn1::CTS::_POD_Category*>				_catList;
	//    std::shared_ptr<Asn1::CTS::_POD_Profile>			_profile;

	std::vector<tscrypto::tsCryptoData>					_idMap;
	Asn1::CTS::_POD_CryptoGroup*						_cryptoGroup;
	std::shared_ptr<Asn1::CTS::_POD_Profile>			_profile;
	attributeSelectorVariables*                         _vars;

	void setVariables(attributeSelectorVariables* inVars);
	std::vector<wxGrid*> _grids;

protected:
	void OnInitDialog();
	int FindAttrIndex(std::shared_ptr<ICmsHeaderAttributeListExtension> attrList, const tscrypto::tsCryptoData &id);
	Asn1::CTS::_POD_CryptoGroup* GetCryptoGroupById(std::shared_ptr<IKeyVEILSession> session, const tscrypto::tsCryptoData& id);
	Asn1::CTS::_POD_CryptoGroup* GetCryptoGroup(std::shared_ptr<IKeyVEILSession> session, size_t index);
	Asn1::CTS::_POD_CryptoGroup* GetCryptoGroup(std::shared_ptr<IKeyVEILSession> session, const tscrypto::tsCryptoData& cgId);
	void MarkIncomingAttributes();
	std::vector<const Asn1::CTS::_POD_Category*> BuildCategoryList(const Asn1::CTS::_POD_Fiefdom* fiefdom);
	void FillGrid(Asn1::CTS::_POD_CryptoGroup* cryptoGroup);
	wxGrid* AddFiefdomGrid(const tscrypto::tsCryptoString& name);
};

#endif
    // _ATTRIBUTESELECTORGRID_H_
