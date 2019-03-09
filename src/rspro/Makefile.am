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
	ErrorCode.c \
	ErrorInd.c \
	ErrorSeverity.c \
	ErrorString.c \
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
	ErrorCode.h \
	ErrorInd.h \
	ErrorSeverity.h \
	ErrorString.h \
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

ASN_MODULE_SOURCES+=BOOLEAN.c
ASN_MODULE_SOURCES+=IA5String.c
ASN_MODULE_SOURCES+=INTEGER.c
ASN_MODULE_SOURCES+=NativeEnumerated.c
ASN_MODULE_SOURCES+=NativeInteger.c
ASN_MODULE_SOURCES+=constr_CHOICE.c
ASN_MODULE_SOURCES+=constr_SEQUENCE.c
ASN_MODULE_SOURCES+=OCTET_STRING.c
ASN_MODULE_SOURCES+=BIT_STRING.c
ASN_MODULE_SOURCES+=asn_codecs_prim.c
ASN_MODULE_SOURCES+=ber_tlv_length.c
ASN_MODULE_SOURCES+=ber_tlv_tag.c
ASN_MODULE_SOURCES+=ber_decoder.c
ASN_MODULE_SOURCES+=der_encoder.c
ASN_MODULE_SOURCES+=constr_TYPE.c
ASN_MODULE_SOURCES+=constraints.c
ASN_MODULE_SOURCES+=xer_support.c
ASN_MODULE_SOURCES+=xer_decoder.c
ASN_MODULE_SOURCES+=xer_encoder.c
ASN_MODULE_SOURCES+=per_support.c
ASN_MODULE_SOURCES+=per_decoder.c
ASN_MODULE_SOURCES+=per_encoder.c
ASN_MODULE_SOURCES+=per_opentype.c

ASN_MODULE_INC+=BOOLEAN.h
ASN_MODULE_INC+=INTEGER.h
ASN_MODULE_INC+=NativeEnumerated.h
ASN_MODULE_INC+=IA5String.h
ASN_MODULE_INC+=NativeInteger.h
ASN_MODULE_INC+=constr_CHOICE.h
ASN_MODULE_INC+=constr_SEQUENCE.h
ASN_MODULE_INC+=asn_application.h
ASN_MODULE_INC+=asn_system.h
ASN_MODULE_INC+=asn_codecs.h
ASN_MODULE_INC+=asn_internal.h
ASN_MODULE_INC+=OCTET_STRING.h
ASN_MODULE_INC+=BIT_STRING.h
ASN_MODULE_INC+=asn_codecs_prim.h
ASN_MODULE_INC+=ber_tlv_length.h
ASN_MODULE_INC+=ber_tlv_tag.h
ASN_MODULE_INC+=ber_decoder.h
ASN_MODULE_INC+=der_encoder.h
ASN_MODULE_INC+=constr_TYPE.h
ASN_MODULE_INC+=constraints.h
ASN_MODULE_INC+=xer_support.h
ASN_MODULE_INC+=xer_decoder.h
ASN_MODULE_INC+=xer_encoder.h
ASN_MODULE_INC+=per_support.h
ASN_MODULE_INC+=per_decoder.h
ASN_MODULE_INC+=per_encoder.h
ASN_MODULE_INC+=per_opentype.h

AM_CFLAGS = -I$(top_srcdir)/include $(OSMOCORE_CFLAGS) \
		-I$(top_srcdir)/include/osmocom/rspro

noinst_LTLIBRARIES=libosmo-asn1-rspro.la
libosmo_asn1_rspro_la_SOURCES=$(ASN_MODULE_SOURCES)

regen: regenerate-from-asn1-source

regenerate-from-asn1-source:
	asn1c $(top_srcdir)/asn1/RSPRO.asn
	$(top_srcdir)/move-asn1-header-files.sh osmocom/rspro $(ASN_MODULE_INC)
