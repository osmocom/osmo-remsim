/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RSPRO"
 * 	found in "../../asn1/RSPRO.asn"
 */

#ifndef	_SetAtrReq_H_
#define	_SetAtrReq_H_


#include <asn_application.h>

/* Including external dependencies */
#include <osmocom/rspro/ClientSlot.h>
#include <osmocom/rspro/ATR.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SetAtrReq */
typedef struct SetAtrReq {
	ClientSlot_t	 slot;
	ATR_t	 atr;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SetAtrReq_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SetAtrReq;

#ifdef __cplusplus
}
#endif

#endif	/* _SetAtrReq_H_ */
#include <asn_internal.h>
