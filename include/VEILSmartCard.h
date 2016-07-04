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

#ifndef __VEILSMARTCARD_H__
#define __VEILSMARTCARD_H__

#pragma once

#include "VEIL.h"

#ifdef _WIN32
#ifdef _STATIC_RUNTIME_LOADER
#define VEILSMARTCARD_EXPORT
#define VEILSMARTCARD_TEMPLATE_EXTERN extern
#else
#if !defined(VEILSMARTCARDDEF) && !defined(DOXYGEN)
#define VEILSMARTCARD_EXPORT  __declspec(dllimport)
#define VEILSMARTCARD_TEMPLATE_EXTERN extern
#else
/// <summary>A macro that defines extern syntax for templates.</summary>
#define VEILSMARTCARD_TEMPLATE_EXTERN
/// <summary>A macro that defines the export modifiers for the AppPlatform components.</summary>
#define VEILSMARTCARD_EXPORT __declspec(dllexport)
#endif
#endif
#else
#if !defined(VEILSMARTCARDDEF) && !defined(DOXYGEN)
#define VEILSMARTCARD_EXPORT
#define VEILSMARTCARD_TEMPLATE_EXTERN extern
#else
#define VEILSMARTCARD_EXPORT EXPORT_SYMBOL
#define VEILSMARTCARD_TEMPLATE_EXTERN
#endif
#endif // _WIN32

//#include "CkmSmartCard/TokenPacket.h"
//#include "CkmSmartCard/CTSProfile.h"

extern bool VEILSMARTCARD_EXPORT InitializeSmartCard();
void VEILSMARTCARD_EXPORT DisableSmartCardAccess(bool disabled);
bool VEILSMARTCARD_EXPORT SmartCardAccessDisabled();

#include "VEILSmartCard/tsWinscardExports.h"

/// <summary>Defines the action to take when disconnecting from a smart card reader.</summary>
typedef enum {
	SCardLeaveCard = 0,  /*!< Don't do anything special on close */
	SCardResetCard = 1,  /*!< Reset the card on close */
	SCardUnpowerCard = 2,/*!< Power down the card on close */
	SCardEjectCard = 3,  /*!< Eject the card on close */
} SCardDisposition;

/// <summary>Defines the types of changes detected.</summary>
typedef enum {
	wcard_AddReader,	///< \brief A reader has been added to the system
	wcard_RemoveReader,	///< \brief A reader has been removed from the system
	wcard_InsertCard,	///< \brief A card has been inserted into a reader
	wcard_RemoveCard,	///< \brief A card has been removed from a reader
} WinscardChangeType;

/// <summary>Represents the functions available for a smart card reader.</summary>
class ICkmWinscardReader
{
public:
	/**
	* \brief Gets the reader name.
	*
	* \return the reader name.
	*/
	virtual tscrypto::tsCryptoString ReaderName() const = 0;
	/**
	* \brief Gets the atr string.
	*
	* \return the atr string.
	*/
	virtual tscrypto::tsCryptoData   ATR() const = 0;
	/**
	* \brief Gets the status bits for this reader.
	*
	* \return the status bits for this reader.
	*/
	virtual uint32_t       Status() const = 0;
	/**
	* \brief Gets the number of events that have been detected for this reader.
	*
	* \return the number of events that have been detected for this reader.
	*/
	virtual int  EventNumber() const = 0;
	/**
	* \brief Has this reader detected a change.
	*
	* \return true if a change has been detected, false if not.
	*/
	virtual bool Changed() const = 0;
	/**
	* \brief Determines if this reader is in the unknown state.
	*
	* \return true if unknown, false if not.
	*/
	virtual bool StateUnknown() const = 0;
	/**
	* \brief Determines if this reader is in the unavailable state.
	*
	* \return true if unavailable, false if not.
	*/
	virtual bool StateUnavailable() const = 0;
	/**
	* \brief Determines if this reader is empty.
	*
	* \return true if empty, false if not.
	*/
	virtual bool Empty() const = 0;
	/**
	* \brief Determines if there is a card in this reader.
	*
	* \return true if a card is present, false if not.
	*/
	virtual bool Present() const = 0;
	/**
	* \brief Determines if the ATR strings still match.
	*
	* \return true if the ATR strings match, false if not.
	*/
	virtual bool ATRMatch() const = 0;
	/**
	* \brief Determines if this reader is opened for exclusive use.
	*
	* \return true if exclusive use, false if not.
	*/
	virtual bool Exclusive() const = 0;
	/**
	* \brief Determines if this reader is in use.
	*
	* \return true if in use, false if not.
	*/
	virtual bool InUse() const = 0;
	/**
	* \brief Determines if the smart card has gone mute.
	*
	* \return true if mute, false if not.
	*/
	virtual bool Mute() const = 0;
	/**
	* \brief Determines if the card in this reader has been powered down.
	*
	* \return true if no power, false power is applied.
	*/
	virtual bool Unpowered() const = 0;
};

/// <summary>Defines the interface that implements the server (not card) side of a Global Platform secure channel.</summary>
class ServerSecureChannel
{
public:
	virtual bool finish() = 0;

	virtual tscrypto::tsCryptoData getCardChallenge() = 0;
	virtual tscrypto::tsCryptoData getHostChallenge() = 0;
	virtual tscrypto::tsCryptoData getSessionEncKey() = 0;
	virtual tscrypto::tsCryptoData getSessionMacKey() = 0;
	virtual tscrypto::tsCryptoData getSessionRMacKey() = 0;
	virtual tscrypto::tsCryptoData getSessionKEK() = 0;
	virtual uint8_t getSCPVersion() = 0;
	virtual bool setSCPVersion(uint8_t setTo) = 0;
	virtual uint8_t getSCPLevel() = 0;
	virtual bool setSCPLevel(uint8_t setTo) = 0;
	virtual uint8_t getSecurityLevel() = 0;

	virtual bool ComputeSessionKeys() = 0;
	virtual bool SetBaseKeys(const tscrypto::tsCryptoData &encKey, const tscrypto::tsCryptoData &macKey, const tscrypto::tsCryptoData &kekKey) = 0;
	virtual bool EstablishKeysFromSharedValue(const tscrypto::tsCryptoData &sharedValue) = 0;

	virtual bool ComputeHostChallengeCommand(byte keyRef, tscrypto::tsCryptoData &data) = 0;
	virtual bool ComputeAuthentication(const tscrypto::tsCryptoData &challengeResponse, byte securityLevelDesired, tscrypto::tsCryptoData &authenticationCommand) = 0;
	virtual tscrypto::tsCryptoData EncryptData(const tscrypto::tsCryptoData &data) = 0;
	virtual tscrypto::tsCryptoData DecryptData(const tscrypto::tsCryptoData &data) = 0;
	virtual tscrypto::tsCryptoData PadAndEncryptData(const tscrypto::tsCryptoData &data) = 0;
	virtual tscrypto::tsCryptoData PadData(const tscrypto::tsCryptoData &data) = 0;
	virtual tscrypto::tsCryptoData UnpadData(const tscrypto::tsCryptoData &data) = 0;

	virtual bool Wrap(const tscrypto::tsCryptoData &commandToWrap, tscrypto::tsCryptoData &wrappedCommand) = 0;
	virtual bool Unwrap(uint8_t CLA, uint8_t INS, uint8_t p1, uint8_t p2, uint8_t lc, const tscrypto::tsCryptoData &cmdData, uint8_t le, tscrypto::tsCryptoData &outData, size_t &sw) = 0;

	virtual bool ActivateChannel() = 0;
	virtual bool ActivateChannelWithLevel(uint8_t level) = 0;
};

/**
* \brief Defines the functionality for a connection to a smart card.
*/
class ICkmWinscardConnection
{
public:
	/**
	* \brief Disconnects from the smart card and applies the given disposition.
	*
	* \param disposition The disposition to apply to the smart card.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool Disconnect(SCardDisposition disposition) = 0;
	/**
	* \brief Reconnects to the smart card.
	*
	* \param disposition	   The disposition to apply to the smart card.
	* \param protocolsToAllow The protocols to allow.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool Reconnect(SCardDisposition disposition, uint32_t protocolsToAllow) = 0;
	/**
	* \brief Transmits a command and receives the response from the smart card.
	*
	* \param dataToSend		    The data to send.
	* \param Le				    The length of the returned data.
	* \param [in,out] dataReceived The data received.
	* \param [in,out] sw		    The status word.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool Transmit(const tscrypto::tsCryptoData &dataToSend, int Le, tscrypto::tsCryptoData &dataReceived, size_t &sw) = 0;
	/**
	* \brief Gets an attribute from the smart card reader.
	*
	* \param attributeId    Identifier for the attribute.
	* \param [in,out] value The value.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool GetAttribute(uint32_t attributeId, tscrypto::tsCryptoData &value) = 0;
	/**
	* \brief Creates an exclusive connection to the smart card so that other threads cannot change the card.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool BeginTransaction() = 0;
	/**
	* \brief Restores the smart card to shared access to allow other threads to access the card.
	*
	* \param disposition The disposition to apply.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool EndTransaction(SCardDisposition disposition) = 0;
	/**
	* \brief Query if this connection is in a transaction.
	*
	* \return true if in transaction, false if not.
	*/
	virtual bool IsInTransaction() = 0;
	/**
	* \brief Sets the secure channel object for this connection to allow for secure communications to the smart card.
	*
	* \param [in] pObj The secure channel object.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool SetSecureChannel(std::shared_ptr<ServerSecureChannel> pObj) = 0;
	/**
	* \brief Gets the secure channel object.
	*
	* \param [out] pObj The secure channel object.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool GetSecureChannel(std::shared_ptr<ServerSecureChannel>& pObj) = 0;
	/**
	* \brief Gets the reader name.
	*
	* \return The reader name.
	*/
	virtual const tscrypto::tsCryptoString GetReaderName() = 0;
	/**
	* \brief Gets the communication protocol.
	*
	* \return The communication protocol.
	*/
	virtual int  GetProtocol() = 0;
	/**
	* \brief Query if this object is in proxy mode.
	*
	* \return true if in proxy mode, false if not.
	*/
	virtual bool IsInProxyMode() = 0;
	/**
	* \brief Sets proxy mode.
	*
	* \param setTo true to proxy mode.
	*/
	virtual void SetProxyMode(bool setTo) = 0;
	// Added 7.0.4
	virtual int Status() = 0; // Added to help with MS 5 sec timeout issue.  Returns the status of the current reader and resets the 5 sec timer.
};

/**
* \brief Defines the functions available to a smart card context.
*/
class ICkmWinscardContext 
{
public:
	/**
	* \brief Connects to the card in the specified reader.
	*
	* \param readerName	   Name of the reader.
	* \param protocolsToAllow The protocols to allow.
	* \param [out] pObj       The connection object.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool Connect(const tscrypto::tsCryptoString &readerName, uint32_t protocolsToAllow, std::shared_ptr<ICkmWinscardConnection>& pObj) = 0;
	/**
	* \brief Cancels all blocking operations connected to this context.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool Cancel() = 0;
	/**
	* \brief Query if this object is a valid context.
	*
	* \return true if valid, false if not.
	*/
	virtual bool IsValid() = 0;
};

/**
* \brief The callback interface that receives smart card change events.
*
* This is a low level interface and is not normally used.  See the ICkmWinscardMonitor interface for the current change monitoring system.
*/
class ICkmWinscardChange
{
public:
	/**
	* \brief A reader has been added to the system.
	*
	* \param name The reader name.
	*/
	virtual void readerAdded(const tscrypto::tsCryptoString &name) = 0;
	/**
	* \brief A reader has been removed from the system.
	*
	* \param name The reader name.
	*/
	virtual void readerRemoved(const tscrypto::tsCryptoString &name) = 0;
	/**
	* \brief A smart card has been inserted into a reader.
	*
	* \param name The reader name.
	*/
	virtual void cardInserted(const tscrypto::tsCryptoString &name) = 0;
	/**
	* \brief A smart card has been removed from a reader.
	*
	* \param name The reader name.
	*/
	virtual void cardRemoved(const tscrypto::tsCryptoString &name) = 0;
};

/**
* \brief Defines the information sent to consumers of the change monitoring system.
*/
class ICkmWinscardEvent : public ICkmChangeEvent
{
public:
	/**
	* \brief Gets the type of change detected.
	*
	* \return the type of change detected.
	*/
	virtual WinscardChangeType cardChangeType() = 0;
	/**
	* \brief The Reader name.
	*
	* \param [in,out] name The reader name.
	*
	* \return true for success or false for failure.
	*/
	virtual tscrypto::tsCryptoString readerName() = 0;
};

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
VEILSMARTCARD_TEMPLATE_EXTERN template class VEILSMARTCARD_EXPORT tscrypto::ICryptoContainerWrapper<std::shared_ptr<ICkmWinscardReader>>;
VEILSMARTCARD_TEMPLATE_EXTERN template class VEILSMARTCARD_EXPORT std::shared_ptr<tscrypto::ICryptoContainerWrapper<std::shared_ptr<ICkmWinscardReader>>>;
#pragma warning(pop)
#endif // _MSC_VER

typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<std::shared_ptr<ICkmWinscardReader>>> ICkmWinscardReaderList;
extern VEILSMARTCARD_EXPORT ICkmWinscardReaderList CreateICkmWinscardReaderList();

/**
* \brief Defines the functionality of the internal change monitoring system for smart cards.
*/
class ICkmWinscardMonitor
{
public:
	/**
	* \brief Registers the change receiver described by pObj.
	*
	* \param [in] pObj The change receiver.
	*
	* \return a cookie that represents this registered change receiver.
	*/
	virtual int RegisterChangeReceiver(std::shared_ptr<ICkmWinscardChange> pObj) = 0;
	/**
	* \brief Unregisters the change receiver described by cookie.
	*
	* \param cookie The cookie.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool UnregisterChangeReceiver(int cookie) = 0;
	/**
	* \brief Scans for changes in the smart card system.
	*/
	virtual void ScanForChanges() = 0;
	/**
	* \brief Creates a smart card context.
	*
	* \param [in,out] pObj If non-null, the object.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual bool CreateContext(std::shared_ptr<ICkmWinscardContext>& pObj) = 0;
	/**
	* \brief Gets the list of readers.
	*
	* \return The reader list.
	*/
	virtual ICkmWinscardReaderList GetReaderList() = 0;
};
/**
* \brief Defines an alias representing the smart card command that the server needs to have performed.
*/
typedef enum SmartCardCommand
{
	scc_None,
	scc_CardCommand,            ///< \brief Send a command to the card Syntax: sends and receives
	scc_CardUpdated,            ///< \brief The card is updated Syntax: void
	scc_OperationFailed,        ///< \brief The operation failed with message Syntax: string message, void
	scc_Status,                 ///< \brief A status message Syntax: string message, void
	scc_Disconnect,             ///< \brief Disconnect from the card Syntax: bool reset (one byte array), void
	scc_FinishTransaction,      ///< \brief Close the smart card transaction (release exclusive lock) Syntax: bool reset (one byte array), void
	scc_Unpower,                ///< \brief Remove power from the card Syntax: void
	scc_Reconnect,              ///< \brief Reconnect to the card Syntax: bool reset (one byte array), void
	scc_StartTransaction,       ///< \brief Start the smart card transaction (gain exclusive access) Syntax: void
	scc_GetCardAtr,             ///< \brief Get the Answer To Reset Syntax: returns atr in response
	scc_CardInReader,           ///< \brief See if a card is in the reader Syntax: returns bool in sw
	scc_GetProtocol,            ///< \brief Gets the communication protocol for this card Syntax: returns int in sw
	scc_GetTransactionStatus,   ///< \brief Reports if we have a transaction for this card (exclusive access) Syntax: returns bool in sw
	scc_PingCard,               ///< \brief Keepalive for transactions - MS now will fail out (SCARD_W_RESETCARD) if a transaction is inactive for 5 seconds.  Call this to keep the transaction alive.
} SmartCardCommand;
/**
* \brief Smart card command and data that the server needs performed.
*/
class SmartCardCommandResponse
{
public:
	SmartCardCommand Command;   ///< \brief The command type to perform
	tscrypto::tsCryptoData Data;				///< \brief The data needed for that command
};
/**
* \brief Events triggered during the processing of a smart card
*/
class ISmartCardLinkEvents
{
public:
	/**
	* \brief A Reader was added into the computer
	*
	* \param readerName Name of the reader added.
	*/
	virtual void ReaderInserted(const tscrypto::tsCryptoString& readerName) = 0;
	/**
	* \brief A Reader was removed from the computer.
	*
	* \param readerName Name of the reader.
	*/
	virtual void ReaderRemoved(const tscrypto::tsCryptoString& readerName) = 0;
	/**
	* \brief A Card was inserted into a reader.
	*
	* \param readerName Name of the reader that received the card.
	*/
	virtual void CardInserted(const tscrypto::tsCryptoString& readerName) = 0;
	/**
	* \brief A Card was removed from a reader.
	*
	* \param readerName Name of the reader that lost the card.
	*/
	virtual void CardRemoved(const tscrypto::tsCryptoString& readerName) = 0;
	/**
	* \brief The Server cancelled the card operation.
	*
	* \param readerName Name of the reader.
	*/
	virtual void ServerCancelledOperation(const tscrypto::tsCryptoString& readerName) = 0;
	/**
	* \brief Called by this system to report the results of the last operation and request the next
	* operation (return value).
	*
	* \param readerName Name of the reader.
	* \param response   The response data.
	* \param sw		 The status word from the card.
	*
	* \return A SmartCardCommandResponse describing the next card operation needed.
	*/
	virtual SmartCardCommandResponse RespondToServer(const tscrypto::tsCryptoString& readerName, const tscrypto::tsCryptoData& response, int sw) = 0;
	/**
	* \brief Reports a status message to the client from the server.
	*
	* \param readerName Name of the reader.
	* \param message    The status message.
	*/
	virtual void OnStatus(const tscrypto::tsCryptoString& readerName, const tscrypto::tsCryptoString& message) = 0;
	/**
	* \brief Reports to the client that the operation finished successfully.
	*
	* \param readerName Name of the reader that finished.
	* \param message    The success message.
	*/
	virtual void OnSuccess(const tscrypto::tsCryptoString& readerName, const tscrypto::tsCryptoString& message) = 0;
	/**
	* \brief Reports to the client that the operation failed.
	*
	* \param readerName Name of the reader that failed.
	* \param message    The reason for the failure.
	*/
	virtual void OnFailure(const tscrypto::tsCryptoString& readerName, const tscrypto::tsCryptoString& message) = 0;
};
/**
* \brief Implements the client half of a smart card communication system between a server and a client based smart card.
*
*  This system uses a reverse callback approach to allow the server to communicate with a smart card on the client computer.
*  The client starts the process off by configuring the operation with the server.  The server then waits for the client to
*  send a false response (\see ISmartCardLinkEvents::RespondToServer).  This response is automatically sent when the client
*  calls the StartCardPump function.  During the operation this object will call the ISmartCardLinkEvents::RespondToServer function
*  to report the last results and get the next command to process.  When the operation is finished the client must call CloseCardPump.
*/
class ISmartCardLink
{
public:
	/**
	* \brief Used by the client to see if there is a card in the specified reader.
	*
	* \param readerName Name of the reader to query.
	*
	* \return true if it contains a smart card, false otherwise.
	*/
	virtual bool CardInReader(const tscrypto::tsCryptoString& readerName) = 0;
	/**
	* \brief Use by the client to see if the card is held exclusively.
	*
	* \return true if exclusively held by this object, false otherwise.
	*/
	virtual bool IsInTransaction() = 0;
	/**
	* \brief Gets the name of the reader to which this object associated.
	*
	* \return The reader name.
	*/
	virtual tscrypto::tsCryptoString GetReaderName() = 0;
	/**
	* \brief Sets the name of the reader to which this object is to be associated.
	*
	* \param setTo The reader name.
	*/
	virtual void SetReaderName(const tscrypto::tsCryptoString& setTo) = 0;
	/**
	* \brief Start the communication link between the server and the smart card.
	*/
	virtual bool StartCardPump() = 0;
	/**
	* \brief Shuts down the communication link between the server and the smart card.
	*/
	virtual void CloseCardPump() = 0;
	/**
	* \brief Get a reference to the required callback for this communication link.
	*
	* \param [out] pVal If non-null, the value.
	*/
	virtual void GetEventHandler(std::shared_ptr<ISmartCardLinkEvents>& pVal) = 0;
	/**
	* \brief Establishes the required callback for this communication link.
	*
	* \param [in] setTo The communication callback.
	*/
	virtual void SetEventHandler(std::shared_ptr<ISmartCardLinkEvents> setTo) = 0;
};

class VEILSMARTCARD_EXPORT SmartCardCommandData
{
public:
	SmartCardCommandData() :
		Command(scc_None)
	{
	}
	SmartCardCommandData(const SmartCardCommandData& obj) :
		Command(obj.Command),
		Data(obj.Data)
	{
	}
	SmartCardCommandData(SmartCardCommandData&& obj) :
		Command(obj.Command),
		Data(std::move(obj.Data))
	{
		obj.Command = scc_None;
	}
	~SmartCardCommandData() {}
	SmartCardCommandData& operator=(const SmartCardCommandData& obj)
	{
		if (this != &obj)
		{
			Command = obj.Command;
			Data = obj.Data;
		}
		return *this;
	}
	SmartCardCommandData& operator=(SmartCardCommandData&& obj)
	{
		if (this != &obj)
		{
			Command = obj.Command;
			Data = std::move(obj.Data);

			obj.Command = scc_None;
		}
		return *this;
	}

	void Clear()
	{
		Command = scc_None;
		Data.clear();
	}

	SmartCardCommand Command;
	tscrypto::tsCryptoData Data;
};

class ISmartCardConnectionEvents
{
public:
	virtual void CardUpdated(const tscrypto::tsCryptoString& msg) = 0;
	virtual void OperationFailed(const tscrypto::tsCryptoString& msg) = 0;
	virtual void Status(const tscrypto::tsCryptoString& msg) = 0;
};

class ISmartCardConnection
{
public:
	virtual bool IsInTransaction() = 0;
	virtual void Disconnect(bool reset) = 0;
	virtual void FinishTransaction(bool reset) = 0;
	virtual void Unpower() = 0;
	virtual void Reconnect(bool reset) = 0;
	virtual void StartTransaction() = 0;
	virtual void OperationFailed(const tscrypto::tsCryptoString& message) = 0;
	virtual void Status(const tscrypto::tsCryptoString& message) = 0;
	virtual void CardUpdated(const tscrypto::tsCryptoString& message) = 0;
	virtual bool Transmit(const tscrypto::tsCryptoData& dataToSend, int Le, tscrypto::tsCryptoData& dataReceived, int& sw) = 0;
	virtual int Transmit(const tscrypto::tsCryptoData& dataToSend, int Le, tscrypto::tsCryptoData& dataReceived) = 0;
	virtual int Transmit(const tscrypto::tsCryptoData& dataToSend, tscrypto::tsCryptoData& dataReceived) = 0;
	virtual tscrypto::tsCryptoData GetCardAtr() = 0;
	virtual bool CardInReader() = 0;
	virtual tscrypto::tsCryptoData BuildCmd(BYTE CLA, BYTE INS, BYTE P1, BYTE P2, const tscrypto::tsCryptoData& data, BYTE Le) = 0;
	virtual int SendCommand(BYTE CLA, BYTE INS, BYTE P1, BYTE P2, BYTE Lc, const tscrypto::tsCryptoData& inData, BYTE Le, tscrypto::tsCryptoData& outData) = 0;
	virtual int SendCommand(const tscrypto::tsCryptoData& inData, tscrypto::tsCryptoData& outData) = 0;
	virtual bool GetSecureChannel(std::shared_ptr<ServerSecureChannel>& pVal) = 0;
	virtual bool SetSecureChannel(std::shared_ptr<ServerSecureChannel> setTo) = 0;

	virtual tscrypto::tsCryptoString ReaderName() const = 0;
	virtual void ReaderName(const tscrypto::tsCryptoString& setTo) = 0;

	// These functions are called by the communication thread and make up the command processing pump
	//
	// When the communications thread has a response from the last command it calls CommunicateWithCard.  Then
	// the communications thread periodically polls the hasCommandReady for polling mode or waitForCommandReady if only
	// a single card connection is used for this overall job.
	// Then the communication thread calls GetCommand when either hasCommandReady or waitForCommand returns true and sends
	// the response to the client.
	//
	virtual void CommunicateWithCard(const tscrypto::tsCryptoData& response, int sw) = 0;
	virtual bool hasCommandReady() = 0;
	virtual bool waitForCommandReady() = 0;
	virtual SmartCardCommandData GetCommand() = 0;

	// Use these functions to manage the list of callbacks for the events published by this interface
	virtual void RegisterEventHandler(std::shared_ptr<ISmartCardConnectionEvents> handler) = 0;
	virtual void UnregisterEventHandler(std::shared_ptr<ISmartCardConnectionEvents> handler) = 0;

	// This function is used to register a task cancellation event (used in ServerSmartCardConnection).
	virtual void SetCancelEvent(tscrypto::CryptoEvent* cancelEvent) = 0;

	virtual bool StillProcessing() = 0;

	virtual ~ISmartCardConnection(){}

	virtual bool Start() = 0; // Used in local connection to start the change monitors...
	virtual int GetCardStatus() = 0; // Used in local connection to poll card for status change and can be used to keep a transaction alive.  MS Winscard will time out after 5 sec of inactivity.
	virtual void PingCard() = 0;
};

class ISmartCardKeyInformation
{
public:
	virtual uint8_t KeyVersion() const = 0;
	virtual uint8_t KeyNumber() const = 0;
	virtual uint8_t KeyType() const = 0;
	virtual int KeyLength() const = 0;
	virtual tscrypto::tsCryptoData OtherInfo() const = 0;
};

class ISmartCardInformation
{
public:
	virtual tscrypto::tsCryptoString OSVersion() const = 0;
	virtual int ChipID() const = 0;
	virtual tscrypto::tsCryptoData SerialNumber() const = 0;
	virtual bool isFlashChip() const = 0;
	virtual bool isRomChip() const = 0;
	virtual bool isContact() const = 0;
	virtual bool isContactless() const = 0;
	virtual tscrypto::tsCryptoData IsdAid() const = 0;
	virtual tscrypto::tsCryptoData SsdAid() const = 0;
	virtual tscrypto::tsCryptoData DapAid() const = 0;
	virtual uint8_t ISDSecureChannelProtocol() const = 0;
	virtual uint8_t SSDSecureChannelProtocol() const = 0;
	virtual uint8_t DAPSecureChannelProtocol() const = 0;
	virtual uint8_t ISDSecureChannelParameter() const = 0;
	virtual uint8_t SSDSecureChannelParameter() const = 0;
	virtual uint8_t DAPSecureChannelParameter() const = 0;
	virtual uint8_t ISDKeyVersion() const = 0;
	virtual uint8_t SSDKeyVersion() const = 0;
	virtual uint8_t DAPKeyVersion() const = 0;
	virtual void ISDKeyVersion(uint8_t setTo) = 0;
	virtual void SSDKeyVersion(uint8_t setTo) = 0;
	virtual void DAPKeyVersion(uint8_t setTo) = 0;
	virtual uint8_t ISDKeyLength() const = 0;
	virtual uint8_t SSDKeyLength() const = 0;
	virtual uint8_t DAPKeyLength() const = 0;
	virtual uint8_t ISDKeyType() const = 0;
	virtual uint8_t SSDKeyType() const = 0;
	virtual uint8_t DAPKeyType() const = 0;
	virtual uint8_t ISDMaximumSecurityLevel() const = 0;
	virtual uint8_t SSDMaximumSecurityLevel() const = 0;
	virtual uint8_t DAPMaximumSecurityLevel() const = 0;
	virtual size_t ISDKeyCount() const = 0;
	virtual bool ISDKeyItem(size_t index, std::shared_ptr<ISmartCardKeyInformation>& pVal) const = 0;
	virtual size_t SSDKeyCount() const = 0;
	virtual bool SSDKeyItem(size_t index, std::shared_ptr<ISmartCardKeyInformation>& pVal) const = 0;
	virtual size_t DAPKeyCount() const = 0;
	virtual bool DAPKeyItem(size_t index, std::shared_ptr<ISmartCardKeyInformation>& pVal) const = 0;
	virtual tscrypto::tsCryptoData IIN() const = 0;
	virtual tscrypto::tsCryptoData CIN() const = 0;

	virtual void PopulateCardInformation(std::shared_ptr<ISmartCardConnection> connection) = 0;

	// Added 7.0.33
	virtual bool isTransportLocked() const = 0;
};

#endif // __VEILSMARTCARD_H__
