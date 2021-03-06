/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RSPRO"
 * 	found in "../../asn1/RSPRO.asn"
 */

#ifndef	_Ipv6Address_H_
#define	_Ipv6Address_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Ipv6Address */
typedef OCTET_STRING_t	 Ipv6Address_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Ipv6Address;
asn_struct_free_f Ipv6Address_free;
asn_struct_print_f Ipv6Address_print;
asn_constr_check_f Ipv6Address_constraint;
ber_type_decoder_f Ipv6Address_decode_ber;
der_type_encoder_f Ipv6Address_encode_der;
xer_type_decoder_f Ipv6Address_decode_xer;
xer_type_encoder_f Ipv6Address_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _Ipv6Address_H_ */
#include <asn_internal.h>
