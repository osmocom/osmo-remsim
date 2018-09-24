/* Automatically generated file - do not edit */

#include "asn1defs.h"
#include "rspro.h"

const ASN1CType asn1_type_OperationTag[] = {
  (ASN1_CTYPE_INTEGER << ASN1_CTYPE_SHIFT) | 0x5800000 | 0x100001,
  0x0,
  0x7fffffff,
  (intptr_t)"OperationTag",
};

const ASN1CType asn1_type_BankId[] = {
  (ASN1_CTYPE_INTEGER << ASN1_CTYPE_SHIFT) | 0x5800000 | 0x2,
  0x0,
  0x3ff,
  (intptr_t)"BankId",
};

const ASN1CType asn1_type_ClientId[] = {
  (ASN1_CTYPE_INTEGER << ASN1_CTYPE_SHIFT) | 0x5800000 | 0x2,
  0x0,
  0x3ff,
  (intptr_t)"ClientId",
};

const ASN1CType asn1_type_ComponentType[] = {
  (ASN1_CTYPE_ENUMERATED << ASN1_CTYPE_SHIFT) | 0x4000000 | 0xa,
  3,
  (intptr_t)"remsimClient",
  (intptr_t)"remsimServer",
  (intptr_t)"remsimBankd",
  (intptr_t)"ComponentType",
};

const ASN1CType asn1_type_ComponentName[] = {
  (ASN1_CTYPE_CHAR_STRING << ASN1_CTYPE_SHIFT) | 0x5800000 | 0x16,
  ASN1_CSTR_IA5String,
  0x1,
  0x20,
  1,
  0x0,
  0x7f,
  (intptr_t)"ComponentName",
};

static const ASN1CType asn1_type__local_0[] = {
  (ASN1_CTYPE_TAGGED << ASN1_CTYPE_SHIFT) | 0x0 | 0x100000,
  (intptr_t)asn1_type_ComponentName,
};

static const ASN1CType asn1_type__local_1[] = {
  (ASN1_CTYPE_TAGGED << ASN1_CTYPE_SHIFT) | 0x0 | 0x100001,
  (intptr_t)asn1_type_ComponentName,
};

static const ASN1CType asn1_type__local_2[] = {
  (ASN1_CTYPE_TAGGED << ASN1_CTYPE_SHIFT) | 0x0 | 0x100002,
  (intptr_t)asn1_type_ComponentName,
};

static const ASN1CType asn1_type__local_3[] = {
  (ASN1_CTYPE_TAGGED << ASN1_CTYPE_SHIFT) | 0x0 | 0x100003,
  (intptr_t)asn1_type_ComponentName,
};

static const ASN1CType asn1_type__local_4[] = {
  (ASN1_CTYPE_TAGGED << ASN1_CTYPE_SHIFT) | 0x0 | 0x100004,
  (intptr_t)asn1_type_ComponentName,
};

static const ASN1CType asn1_type__local_5[] = {
  (ASN1_CTYPE_TAGGED << ASN1_CTYPE_SHIFT) | 0x0 | 0x100005,
  (intptr_t)asn1_type_ComponentName,
};

static const ASN1CType asn1_type__local_6[] = {
  (ASN1_CTYPE_TAGGED << ASN1_CTYPE_SHIFT) | 0x0 | 0x100006,
  (intptr_t)asn1_type_ComponentName,
};

const ASN1CType asn1_type_ComponentIdentity[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x10,
  9,
  sizeof(ComponentIdentity),

  offsetof(ComponentIdentity, type) | 0x0,
  (intptr_t)asn1_type_ComponentType,
  0,
  (intptr_t)"type",

  offsetof(ComponentIdentity, name) | 0x0,
  (intptr_t)asn1_type_ComponentName,
  0,
  (intptr_t)"name",

  offsetof(ComponentIdentity, software) | 0x0,
  (intptr_t)asn1_type__local_0,
  0,
  (intptr_t)"software",

  offsetof(ComponentIdentity, swVersion) | 0x0,
  (intptr_t)asn1_type__local_1,
  0,
  (intptr_t)"swVersion",

  offsetof(ComponentIdentity, hwManufacturer) | 0x8000000,
  (intptr_t)asn1_type__local_2,
  offsetof(ComponentIdentity, hwManufacturer_option),
  (intptr_t)"hwManufacturer",

  offsetof(ComponentIdentity, hwModel) | 0x8000000,
  (intptr_t)asn1_type__local_3,
  offsetof(ComponentIdentity, hwModel_option),
  (intptr_t)"hwModel",

  offsetof(ComponentIdentity, hwSerialNr) | 0x8000000,
  (intptr_t)asn1_type__local_4,
  offsetof(ComponentIdentity, hwSerialNr_option),
  (intptr_t)"hwSerialNr",

  offsetof(ComponentIdentity, hwVersion) | 0x8000000,
  (intptr_t)asn1_type__local_5,
  offsetof(ComponentIdentity, hwVersion_option),
  (intptr_t)"hwVersion",

  offsetof(ComponentIdentity, fwVersion) | 0x8000000,
  (intptr_t)asn1_type__local_6,
  offsetof(ComponentIdentity, fwVersion_option),
  (intptr_t)"fwVersion",

  (intptr_t)"ComponentIdentity",
};

const ASN1CType asn1_type_Ipv4Address[] = {
  (ASN1_CTYPE_OCTET_STRING << ASN1_CTYPE_SHIFT) | 0x5800000 | 0x100000,
  0x4,
  0x4,
  (intptr_t)"Ipv4Address",
};

const ASN1CType asn1_type_Ipv6Address[] = {
  (ASN1_CTYPE_OCTET_STRING << ASN1_CTYPE_SHIFT) | 0x5800000 | 0x100001,
  0x10,
  0x10,
  (intptr_t)"Ipv6Address",
};

const ASN1CType asn1_type_IpAddress[] = {
  (ASN1_CTYPE_CHOICE << ASN1_CTYPE_SHIFT) | 0x4000000 | 0x0,
  2,
  sizeof(IpAddress),
  offsetof(IpAddress, choice),
  offsetof(IpAddress, u),
  (intptr_t)asn1_type_Ipv4Address,
  (intptr_t)"ipv4",
  (intptr_t)asn1_type_Ipv6Address,
  (intptr_t)"ipv6",
  (intptr_t)"IpAddress",
};

const ASN1CType asn1_type_PortNumber[] = {
  (ASN1_CTYPE_INTEGER << ASN1_CTYPE_SHIFT) | 0x5800000 | 0x2,
  0x0,
  0xffff,
  (intptr_t)"PortNumber",
};

const ASN1CType asn1_type_IpPort[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x4000000 | 0x10,
  2,
  sizeof(IpPort),

  offsetof(IpPort, ip) | 0x0,
  (intptr_t)asn1_type_IpAddress,
  0,
  (intptr_t)"ip",

  offsetof(IpPort, port) | 0x0,
  (intptr_t)asn1_type_PortNumber,
  0,
  (intptr_t)"port",

  (intptr_t)"IpPort",
};

const ASN1CType asn1_type_ResultCode[] = {
  (ASN1_CTYPE_ENUMERATED << ASN1_CTYPE_SHIFT) | 0x6000000 | 0xa,
  7,
  0,
  (intptr_t)"ok",
  (intptr_t)"illegalClientId",
  (intptr_t)"illegalBankId",
  (intptr_t)"illegalSlotId",
  (intptr_t)"cardNotPresent",
  (intptr_t)"cardUnresponsive",
  (intptr_t)"cardTransmissionError",
  (intptr_t)"ResultCode",
};

const ASN1CType asn1_type_SlotNumber[] = {
  (ASN1_CTYPE_INTEGER << ASN1_CTYPE_SHIFT) | 0x5800000 | 0x2,
  0x0,
  0x3ff,
  (intptr_t)"SlotNumber",
};

const ASN1CType asn1_type_ClientSlot[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x10,
  2,
  sizeof(ClientSlot),

  offsetof(ClientSlot, clientId) | 0x0,
  (intptr_t)asn1_type_ClientId,
  0,
  (intptr_t)"clientId",

  offsetof(ClientSlot, slotNr) | 0x0,
  (intptr_t)asn1_type_SlotNumber,
  0,
  (intptr_t)"slotNr",

  (intptr_t)"ClientSlot",
};

const ASN1CType asn1_type_BankSlot[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x10,
  2,
  sizeof(BankSlot),

  offsetof(BankSlot, bankId) | 0x0,
  (intptr_t)asn1_type_BankId,
  0,
  (intptr_t)"bankId",

  offsetof(BankSlot, slotNr) | 0x0,
  (intptr_t)asn1_type_SlotNumber,
  0,
  (intptr_t)"slotNr",

  (intptr_t)"BankSlot",
};

const ASN1CType asn1_type_ATR[] = {
  (ASN1_CTYPE_OCTET_STRING << ASN1_CTYPE_SHIFT) | 0x5800000 | 0x4,
  0x1,
  0x37,
  (intptr_t)"ATR",
};

static const ASN1CType asn1_type__local_7[] = {
  (ASN1_CTYPE_BOOLEAN << ASN1_CTYPE_SHIFT) | 0x0 | 0x1,
};

static const ASN1CType asn1_type__local_8[] = {
  (ASN1_CTYPE_BOOLEAN << ASN1_CTYPE_SHIFT) | 0x0 | 0x1,
};

static const ASN1CType asn1_type__local_9[] = {
  (ASN1_CTYPE_BOOLEAN << ASN1_CTYPE_SHIFT) | 0x0 | 0x1,
};

static const ASN1CType asn1_type__local_10[] = {
  (ASN1_CTYPE_BOOLEAN << ASN1_CTYPE_SHIFT) | 0x0 | 0x1,
};

const ASN1CType asn1_type_TpduFlags[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x10,
  4,
  sizeof(TpduFlags),

  offsetof(TpduFlags, tpduHeaderPresent) | 0x0,
  (intptr_t)asn1_type__local_7,
  0,
  (intptr_t)"tpduHeaderPresent",

  offsetof(TpduFlags, finalPart) | 0x0,
  (intptr_t)asn1_type__local_8,
  0,
  (intptr_t)"finalPart",

  offsetof(TpduFlags, procByteContinueTx) | 0x0,
  (intptr_t)asn1_type__local_9,
  0,
  (intptr_t)"procByteContinueTx",

  offsetof(TpduFlags, procByteContinueRx) | 0x0,
  (intptr_t)asn1_type__local_10,
  0,
  (intptr_t)"procByteContinueRx",

  (intptr_t)"TpduFlags",
};

static const ASN1CType asn1_type__local_11[] = {
  (ASN1_CTYPE_BOOLEAN << ASN1_CTYPE_SHIFT) | 0x0 | 0x100000,
};

static const ASN1CType asn1_type__local_12[] = {
  (ASN1_CTYPE_BOOLEAN << ASN1_CTYPE_SHIFT) | 0x0 | 0x100001,
};

static const ASN1CType asn1_type__local_13[] = {
  (ASN1_CTYPE_BOOLEAN << ASN1_CTYPE_SHIFT) | 0x0 | 0x100002,
};

static const ASN1CType asn1_type__local_14[] = {
  (ASN1_CTYPE_BOOLEAN << ASN1_CTYPE_SHIFT) | 0x0 | 0x100003,
};

const ASN1CType asn1_type_SlotPhysStatus[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x10,
  4,
  sizeof(SlotPhysStatus),

  offsetof(SlotPhysStatus, resetActive) | 0x0,
  (intptr_t)asn1_type__local_11,
  0,
  (intptr_t)"resetActive",

  offsetof(SlotPhysStatus, vccPresent) | 0x8000000,
  (intptr_t)asn1_type__local_12,
  offsetof(SlotPhysStatus, vccPresent_option),
  (intptr_t)"vccPresent",

  offsetof(SlotPhysStatus, clkActive) | 0x8000000,
  (intptr_t)asn1_type__local_13,
  offsetof(SlotPhysStatus, clkActive_option),
  (intptr_t)"clkActive",

  offsetof(SlotPhysStatus, cardPresent) | 0x8000000,
  (intptr_t)asn1_type__local_14,
  offsetof(SlotPhysStatus, cardPresent_option),
  (intptr_t)"cardPresent",

  (intptr_t)"SlotPhysStatus",
};

const ASN1CType asn1_type_ConnectBankReq[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x100000,
  3,
  sizeof(ConnectBankReq),

  offsetof(ConnectBankReq, identity) | 0x0,
  (intptr_t)asn1_type_ComponentIdentity,
  0,
  (intptr_t)"identity",

  offsetof(ConnectBankReq, bankId) | 0x0,
  (intptr_t)asn1_type_BankId,
  0,
  (intptr_t)"bankId",

  offsetof(ConnectBankReq, numberOfSlots) | 0x0,
  (intptr_t)asn1_type_SlotNumber,
  0,
  (intptr_t)"numberOfSlots",

  (intptr_t)"ConnectBankReq",
};

const ASN1CType asn1_type_ConnectBankRes[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x100001,
  2,
  sizeof(ConnectBankRes),

  offsetof(ConnectBankRes, identity) | 0x0,
  (intptr_t)asn1_type_ComponentIdentity,
  0,
  (intptr_t)"identity",

  offsetof(ConnectBankRes, result) | 0x0,
  (intptr_t)asn1_type_ResultCode,
  0,
  (intptr_t)"result",

  (intptr_t)"ConnectBankRes",
};

const ASN1CType asn1_type_ConnectClientReq[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x100002,
  2,
  sizeof(ConnectClientReq),

  offsetof(ConnectClientReq, identity) | 0x0,
  (intptr_t)asn1_type_ComponentIdentity,
  0,
  (intptr_t)"identity",

  offsetof(ConnectClientReq, clientSlot) | 0x8000000,
  (intptr_t)asn1_type_ClientSlot,
  offsetof(ConnectClientReq, clientSlot_option),
  (intptr_t)"clientSlot",

  (intptr_t)"ConnectClientReq",
};

const ASN1CType asn1_type_ConnectClientRes[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x100003,
  2,
  sizeof(ConnectClientRes),

  offsetof(ConnectClientRes, identity) | 0x0,
  (intptr_t)asn1_type_ComponentIdentity,
  0,
  (intptr_t)"identity",

  offsetof(ConnectClientRes, result) | 0x0,
  (intptr_t)asn1_type_ResultCode,
  0,
  (intptr_t)"result",

  (intptr_t)"ConnectClientRes",
};

const ASN1CType asn1_type_CreateMappingReq[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x100004,
  2,
  sizeof(CreateMappingReq),

  offsetof(CreateMappingReq, client) | 0x0,
  (intptr_t)asn1_type_ClientSlot,
  0,
  (intptr_t)"client",

  offsetof(CreateMappingReq, bank) | 0x0,
  (intptr_t)asn1_type_BankSlot,
  0,
  (intptr_t)"bank",

  (intptr_t)"CreateMappingReq",
};

const ASN1CType asn1_type_CreateMappingRes[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x100005,
  1,
  sizeof(CreateMappingRes),

  offsetof(CreateMappingRes, result) | 0x0,
  (intptr_t)asn1_type_ResultCode,
  0,
  (intptr_t)"result",

  (intptr_t)"CreateMappingRes",
};

const ASN1CType asn1_type_RemoveMappingReq[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x100006,
  2,
  sizeof(RemoveMappingReq),

  offsetof(RemoveMappingReq, client) | 0x0,
  (intptr_t)asn1_type_ClientSlot,
  0,
  (intptr_t)"client",

  offsetof(RemoveMappingReq, bank) | 0x0,
  (intptr_t)asn1_type_BankSlot,
  0,
  (intptr_t)"bank",

  (intptr_t)"RemoveMappingReq",
};

const ASN1CType asn1_type_RemoveMappingRes[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x100007,
  1,
  sizeof(RemoveMappingRes),

  offsetof(RemoveMappingRes, result) | 0x0,
  (intptr_t)asn1_type_ResultCode,
  0,
  (intptr_t)"result",

  (intptr_t)"RemoveMappingRes",
};

const ASN1CType asn1_type_ConfigClientReq[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x100008,
  2,
  sizeof(ConfigClientReq),

  offsetof(ConfigClientReq, clientSlot) | 0x0,
  (intptr_t)asn1_type_ClientSlot,
  0,
  (intptr_t)"clientSlot",

  offsetof(ConfigClientReq, bankd) | 0x0,
  (intptr_t)asn1_type_IpPort,
  0,
  (intptr_t)"bankd",

  (intptr_t)"ConfigClientReq",
};

const ASN1CType asn1_type_ConfigClientRes[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x100009,
  1,
  sizeof(ConfigClientRes),

  offsetof(ConfigClientRes, result) | 0x0,
  (intptr_t)asn1_type_ResultCode,
  0,
  (intptr_t)"result",

  (intptr_t)"ConfigClientRes",
};

const ASN1CType asn1_type_SetAtrReq[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x10000a,
  2,
  sizeof(SetAtrReq),

  offsetof(SetAtrReq, slot) | 0x0,
  (intptr_t)asn1_type_ClientSlot,
  0,
  (intptr_t)"slot",

  offsetof(SetAtrReq, atr) | 0x0,
  (intptr_t)asn1_type_ATR,
  0,
  (intptr_t)"atr",

  (intptr_t)"SetAtrReq",
};

const ASN1CType asn1_type_SetAtrRes[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x10000b,
  1,
  sizeof(SetAtrRes),

  offsetof(SetAtrRes, result) | 0x0,
  (intptr_t)asn1_type_ResultCode,
  0,
  (intptr_t)"result",

  (intptr_t)"SetAtrRes",
};

static const ASN1CType asn1_type__local_15[] = {
  (ASN1_CTYPE_OCTET_STRING << ASN1_CTYPE_SHIFT) | 0x1000000 | 0x4,
  0x0,
};

const ASN1CType asn1_type_TpduModemToCard[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x10000c,
  4,
  sizeof(TpduModemToCard),

  offsetof(TpduModemToCard, fromClientSlot) | 0x0,
  (intptr_t)asn1_type_ClientSlot,
  0,
  (intptr_t)"fromClientSlot",

  offsetof(TpduModemToCard, toBankSlot) | 0x0,
  (intptr_t)asn1_type_BankSlot,
  0,
  (intptr_t)"toBankSlot",

  offsetof(TpduModemToCard, flags) | 0x0,
  (intptr_t)asn1_type_TpduFlags,
  0,
  (intptr_t)"flags",

  offsetof(TpduModemToCard, data) | 0x0,
  (intptr_t)asn1_type__local_15,
  0,
  (intptr_t)"data",

  (intptr_t)"TpduModemToCard",
};

static const ASN1CType asn1_type__local_16[] = {
  (ASN1_CTYPE_OCTET_STRING << ASN1_CTYPE_SHIFT) | 0x1000000 | 0x4,
  0x0,
};

const ASN1CType asn1_type_TpduCardToModem[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x10000d,
  4,
  sizeof(TpduCardToModem),

  offsetof(TpduCardToModem, fromBankSlot) | 0x0,
  (intptr_t)asn1_type_BankSlot,
  0,
  (intptr_t)"fromBankSlot",

  offsetof(TpduCardToModem, toClientSlot) | 0x0,
  (intptr_t)asn1_type_ClientSlot,
  0,
  (intptr_t)"toClientSlot",

  offsetof(TpduCardToModem, flags) | 0x0,
  (intptr_t)asn1_type_TpduFlags,
  0,
  (intptr_t)"flags",

  offsetof(TpduCardToModem, data) | 0x0,
  (intptr_t)asn1_type__local_16,
  0,
  (intptr_t)"data",

  (intptr_t)"TpduCardToModem",
};

const ASN1CType asn1_type_ClientSlotStatusInd[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x10000e,
  3,
  sizeof(ClientSlotStatusInd),

  offsetof(ClientSlotStatusInd, fromClientSlot) | 0x0,
  (intptr_t)asn1_type_ClientSlot,
  0,
  (intptr_t)"fromClientSlot",

  offsetof(ClientSlotStatusInd, toBankSlot) | 0x0,
  (intptr_t)asn1_type_BankSlot,
  0,
  (intptr_t)"toBankSlot",

  offsetof(ClientSlotStatusInd, slotPhysStatus) | 0x0,
  (intptr_t)asn1_type_SlotPhysStatus,
  0,
  (intptr_t)"slotPhysStatus",

  (intptr_t)"ClientSlotStatusInd",
};

const ASN1CType asn1_type_BankSlotStatusInd[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x10000f,
  3,
  sizeof(BankSlotStatusInd),

  offsetof(BankSlotStatusInd, fromBankSlot) | 0x0,
  (intptr_t)asn1_type_BankSlot,
  0,
  (intptr_t)"fromBankSlot",

  offsetof(BankSlotStatusInd, toClientSlot) | 0x0,
  (intptr_t)asn1_type_ClientSlot,
  0,
  (intptr_t)"toClientSlot",

  offsetof(BankSlotStatusInd, slotPhysStatus) | 0x0,
  (intptr_t)asn1_type_SlotPhysStatus,
  0,
  (intptr_t)"slotPhysStatus",

  (intptr_t)"BankSlotStatusInd",
};

const ASN1CType asn1_type_RsproPDUchoice[] = {
  (ASN1_CTYPE_CHOICE << ASN1_CTYPE_SHIFT) | 0x6000000 | 0x100002,
  16,
  0,
  sizeof(RsproPDUchoice),
  offsetof(RsproPDUchoice, choice),
  offsetof(RsproPDUchoice, u),
  (intptr_t)asn1_type_ConnectBankReq,
  (intptr_t)"connectBankReq",
  (intptr_t)asn1_type_ConnectBankRes,
  (intptr_t)"connectBankRes",
  (intptr_t)asn1_type_ConnectClientReq,
  (intptr_t)"connectClientReq",
  (intptr_t)asn1_type_ConnectClientRes,
  (intptr_t)"connectClientRes",
  (intptr_t)asn1_type_CreateMappingReq,
  (intptr_t)"createMappingReq",
  (intptr_t)asn1_type_CreateMappingRes,
  (intptr_t)"createMappingRes",
  (intptr_t)asn1_type_RemoveMappingReq,
  (intptr_t)"removeMappingReq",
  (intptr_t)asn1_type_RemoveMappingRes,
  (intptr_t)"removeMappingRes",
  (intptr_t)asn1_type_ConfigClientReq,
  (intptr_t)"configClientReq",
  (intptr_t)asn1_type_ConfigClientRes,
  (intptr_t)"configClientRes",
  (intptr_t)asn1_type_SetAtrReq,
  (intptr_t)"setAtrReq",
  (intptr_t)asn1_type_SetAtrRes,
  (intptr_t)"setAtrRes",
  (intptr_t)asn1_type_TpduModemToCard,
  (intptr_t)"tpduModemToCard",
  (intptr_t)asn1_type_TpduCardToModem,
  (intptr_t)"tpduCardToModem",
  (intptr_t)asn1_type_ClientSlotStatusInd,
  (intptr_t)"clientSlotStatusInd",
  (intptr_t)asn1_type_BankSlotStatusInd,
  (intptr_t)"bankSlotStatusInd",
  (intptr_t)"RsproPDUchoice",
};

static const ASN1CType asn1_type__local_17[] = {
  (ASN1_CTYPE_INTEGER << ASN1_CTYPE_SHIFT) | 0x1800000 | 0x100000,
  0x0,
  0x20,
};

const ASN1CType asn1_type_RsproPDU[] = {
  (ASN1_CTYPE_SEQUENCE << ASN1_CTYPE_SHIFT) | 0x4000000 | 0x10,
  3,
  sizeof(RsproPDU),

  offsetof(RsproPDU, version) | 0x0,
  (intptr_t)asn1_type__local_17,
  0,
  (intptr_t)"version",

  offsetof(RsproPDU, tag) | 0x0,
  (intptr_t)asn1_type_OperationTag,
  0,
  (intptr_t)"tag",

  offsetof(RsproPDU, msg) | 0x0,
  (intptr_t)asn1_type_RsproPDUchoice,
  0,
  (intptr_t)"msg",

  (intptr_t)"RsproPDU",
};

