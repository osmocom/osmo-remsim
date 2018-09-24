/* Automatically generated file - do not edit */
#ifndef _FFASN1_RSPRO_H
#define _FFASN1_RSPRO_H

#include "asn1defs.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef int OperationTag;

extern const ASN1CType asn1_type_OperationTag[];

typedef int BankId;

extern const ASN1CType asn1_type_BankId[];

typedef int ClientId;

extern const ASN1CType asn1_type_ClientId[];

typedef enum ComponentType {
  ComponentType_remsimClient,
  ComponentType_remsimServer,
  ComponentType_remsimBankd,
} ComponentType;

extern const ASN1CType asn1_type_ComponentType[];

typedef ASN1String ComponentName;

extern const ASN1CType asn1_type_ComponentName[];

typedef struct ComponentIdentity {
  ComponentType type;
  ComponentName name;
  ComponentName software;
  ComponentName swVersion;
  BOOL hwManufacturer_option;
  ComponentName hwManufacturer;
  BOOL hwModel_option;
  ComponentName hwModel;
  BOOL hwSerialNr_option;
  ComponentName hwSerialNr;
  BOOL hwVersion_option;
  ComponentName hwVersion;
  BOOL fwVersion_option;
  ComponentName fwVersion;
} ComponentIdentity;


extern const ASN1CType asn1_type_ComponentIdentity[];

typedef ASN1String Ipv4Address;

extern const ASN1CType asn1_type_Ipv4Address[];

typedef ASN1String Ipv6Address;

extern const ASN1CType asn1_type_Ipv6Address[];

typedef enum {
  IpAddress_ipv4,
  IpAddress_ipv6,
} IpAddress_choice;

typedef struct IpAddress {
  IpAddress_choice choice;
  union {
    Ipv4Address ipv4;
    Ipv6Address ipv6;
  } u;
} IpAddress;

extern const ASN1CType asn1_type_IpAddress[];

typedef int PortNumber;

extern const ASN1CType asn1_type_PortNumber[];

typedef struct IpPort {
  IpAddress ip;
  PortNumber port;
} IpPort;


extern const ASN1CType asn1_type_IpPort[];

typedef enum ResultCode {
  ResultCode_ok,
  ResultCode_illegalClientId,
  ResultCode_illegalBankId,
  ResultCode_illegalSlotId,
  ResultCode_cardNotPresent,
  ResultCode_cardUnresponsive,
  ResultCode_cardTransmissionError,
} ResultCode;

extern const ASN1CType asn1_type_ResultCode[];

typedef int SlotNumber;

extern const ASN1CType asn1_type_SlotNumber[];

typedef struct ClientSlot {
  ClientId clientId;
  SlotNumber slotNr;
} ClientSlot;


extern const ASN1CType asn1_type_ClientSlot[];

typedef struct BankSlot {
  BankId bankId;
  SlotNumber slotNr;
} BankSlot;


extern const ASN1CType asn1_type_BankSlot[];

typedef ASN1String ATR;

extern const ASN1CType asn1_type_ATR[];

typedef struct TpduFlags {
  BOOL tpduHeaderPresent;
  BOOL finalPart;
  BOOL procByteContinueTx;
  BOOL procByteContinueRx;
} TpduFlags;


extern const ASN1CType asn1_type_TpduFlags[];

typedef struct SlotPhysStatus {
  BOOL resetActive;
  BOOL vccPresent_option;
  BOOL vccPresent;
  BOOL clkActive_option;
  BOOL clkActive;
  BOOL cardPresent_option;
  BOOL cardPresent;
} SlotPhysStatus;


extern const ASN1CType asn1_type_SlotPhysStatus[];

typedef struct ConnectBankReq {
  ComponentIdentity identity;
  BankId bankId;
  SlotNumber numberOfSlots;
} ConnectBankReq;


extern const ASN1CType asn1_type_ConnectBankReq[];

typedef struct ConnectBankRes {
  ComponentIdentity identity;
  ResultCode result;
} ConnectBankRes;


extern const ASN1CType asn1_type_ConnectBankRes[];

typedef struct ConnectClientReq {
  ComponentIdentity identity;
  BOOL clientSlot_option;
  ClientSlot clientSlot;
} ConnectClientReq;


extern const ASN1CType asn1_type_ConnectClientReq[];

typedef struct ConnectClientRes {
  ComponentIdentity identity;
  ResultCode result;
} ConnectClientRes;


extern const ASN1CType asn1_type_ConnectClientRes[];

typedef struct CreateMappingReq {
  ClientSlot client;
  BankSlot bank;
} CreateMappingReq;


extern const ASN1CType asn1_type_CreateMappingReq[];

typedef struct CreateMappingRes {
  ResultCode result;
} CreateMappingRes;


extern const ASN1CType asn1_type_CreateMappingRes[];

typedef struct RemoveMappingReq {
  ClientSlot client;
  BankSlot bank;
} RemoveMappingReq;


extern const ASN1CType asn1_type_RemoveMappingReq[];

typedef struct RemoveMappingRes {
  ResultCode result;
} RemoveMappingRes;


extern const ASN1CType asn1_type_RemoveMappingRes[];

typedef struct ConfigClientReq {
  ClientSlot clientSlot;
  IpPort bankd;
} ConfigClientReq;


extern const ASN1CType asn1_type_ConfigClientReq[];

typedef struct ConfigClientRes {
  ResultCode result;
} ConfigClientRes;


extern const ASN1CType asn1_type_ConfigClientRes[];

typedef struct SetAtrReq {
  ClientSlot slot;
  ATR atr;
} SetAtrReq;


extern const ASN1CType asn1_type_SetAtrReq[];

typedef struct SetAtrRes {
  ResultCode result;
} SetAtrRes;


extern const ASN1CType asn1_type_SetAtrRes[];

typedef struct TpduModemToCard {
  ClientSlot fromClientSlot;
  BankSlot toBankSlot;
  TpduFlags flags;
  ASN1String data;
} TpduModemToCard;


extern const ASN1CType asn1_type_TpduModemToCard[];

typedef struct TpduCardToModem {
  BankSlot fromBankSlot;
  ClientSlot toClientSlot;
  TpduFlags flags;
  ASN1String data;
} TpduCardToModem;


extern const ASN1CType asn1_type_TpduCardToModem[];

typedef struct ClientSlotStatusInd {
  ClientSlot fromClientSlot;
  BankSlot toBankSlot;
  SlotPhysStatus slotPhysStatus;
} ClientSlotStatusInd;


extern const ASN1CType asn1_type_ClientSlotStatusInd[];

typedef struct BankSlotStatusInd {
  BankSlot fromBankSlot;
  ClientSlot toClientSlot;
  SlotPhysStatus slotPhysStatus;
} BankSlotStatusInd;


extern const ASN1CType asn1_type_BankSlotStatusInd[];

typedef enum {
  RsproPDUchoice_connectBankReq,
  RsproPDUchoice_connectBankRes,
  RsproPDUchoice_connectClientReq,
  RsproPDUchoice_connectClientRes,
  RsproPDUchoice_createMappingReq,
  RsproPDUchoice_createMappingRes,
  RsproPDUchoice_removeMappingReq,
  RsproPDUchoice_removeMappingRes,
  RsproPDUchoice_configClientReq,
  RsproPDUchoice_configClientRes,
  RsproPDUchoice_setAtrReq,
  RsproPDUchoice_setAtrRes,
  RsproPDUchoice_tpduModemToCard,
  RsproPDUchoice_tpduCardToModem,
  RsproPDUchoice_clientSlotStatusInd,
  RsproPDUchoice_bankSlotStatusInd,
} RsproPDUchoice_choice;

typedef struct RsproPDUchoice {
  RsproPDUchoice_choice choice;
  union {
    ConnectBankReq connectBankReq;
    ConnectBankRes connectBankRes;
    ConnectClientReq connectClientReq;
    ConnectClientRes connectClientRes;
    CreateMappingReq createMappingReq;
    CreateMappingRes createMappingRes;
    RemoveMappingReq removeMappingReq;
    RemoveMappingRes removeMappingRes;
    ConfigClientReq configClientReq;
    ConfigClientRes configClientRes;
    SetAtrReq setAtrReq;
    SetAtrRes setAtrRes;
    TpduModemToCard tpduModemToCard;
    TpduCardToModem tpduCardToModem;
    ClientSlotStatusInd clientSlotStatusInd;
    BankSlotStatusInd bankSlotStatusInd;
  } u;
} RsproPDUchoice;

extern const ASN1CType asn1_type_RsproPDUchoice[];

typedef struct RsproPDU {
  int version;
  OperationTag tag;
  RsproPDUchoice msg;
} RsproPDU;


extern const ASN1CType asn1_type_RsproPDU[];

#ifdef  __cplusplus
}
#endif

#endif /* _FFASN1_RSPRO_H */
