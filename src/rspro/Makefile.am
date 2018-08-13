ASN_MODULE_SOURCES =	\
	ATR.c \
	BankId.c \
	BankSlot.c \
	BankSlotStatusInd.c \
	ClientId.c \
	ClientSlot.c \
	ClientSlotStatusInd.c \
	ComponentIdentity.c \
	ComponentName.c \
	ComponentType.c \
	ConfigClientReq.c \
	ConfigClientRes.c \
	ConnectBankReq.c \
	ConnectBankRes.c \
	ConnectClientReq.c \
	ConnectClientRes.c \
	CreateMappingReq.c \
	CreateMappingRes.c \
	IpAddress.c \
	IpPort.c \
	Ipv4Address.c \
	Ipv6Address.c \
	OperationTag.c \
	PortNumber.c \
	RemoveMappingReq.c \
	RemoveMappingRes.c \
	ResultCode.c \
	RsproPDU.c \
	RsproPDUchoice.c \
	SetAtrReq.c \
	SetAtrRes.c \
	SlotNumber.c \
	SlotPhysStatus.c \
	TpduCardToModem.c \
	TpduFlags.c \
	TpduModemToCard.c \
	$(NULL)

ASN_MODULE_INC = \
	ATR.h \
	BankId.h \
	BankSlot.h \
	BankSlotStatusInd.h \
	ClientId.h \
	ClientSlot.h \
	ClientSlotStatusInd.h \
	ComponentIdentity.h \
	ComponentName.h \
	ComponentType.h \
	ConfigClientReq.h \
	ConfigClientRes.h \
	ConnectBankReq.h \
	ConnectBankRes.h \
	ConnectClientReq.h \
	ConnectClientRes.h \
	CreateMappingReq.h \
	CreateMappingRes.h \
	IpAddress.h \
	IpPort.h \
	Ipv4Address.h \
	Ipv6Address.h \
	OperationTag.h \
	PortNumber.h \
	RemoveMappingReq.h \
	RemoveMappingRes.h \
	ResultCode.h \
	RsproPDU.h \
	RsproPDUchoice.h \
	SetAtrReq.h \
	SetAtrRes.h \
	SlotNumber.h \
	SlotPhysStatus.h \
	TpduCardToModem.h \
	TpduFlags.h \
	TpduModemToCard.h \
	$(NULL)

AM_CFLAGS = -I$(top_srcdir)/include $(ASN1C_CFLAGS) $(OSMOCORE_CFLAGS)

noinst_LTLIBRARIES=libosmo-asn1-rspro.la
libosmo_asn1_rspro_la_SOURCES=$(ASN_MODULE_SOURCES)
libosmo_asn1_rspro_la_LIBADD=$(ASN1C_LDADD)

regen: regenerate-from-asn1-source

regenerate-from-asn1-source:
	asn1c -R $(top_srcdir)/asn1/RSPRO.asn
	$(top_srcdir)/move-asn1-header-files.sh osmocom/rspro $(ASN_MODULE_INC)
