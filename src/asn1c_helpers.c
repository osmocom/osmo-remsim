#include <assert.h>

#include <asn_application.h>
#include <constr_TYPE.h>
#include <constr_CHOICE.h>
#include <INTEGER.h>

#include "asn1c_helpers.h"

const char *asn_type_name(const asn_TYPE_descriptor_t *td)
{
	return td->name;
}

static int
_fetch_present_idx(const void *struct_ptr, int pres_offset, int pres_size) {
	const void *present_ptr;
	int present;

	present_ptr = ((const char *)struct_ptr) + pres_offset;

	switch(pres_size) {
	case sizeof(int):	present =   *(const int *)present_ptr; break;
	case sizeof(short):	present = *(const short *)present_ptr; break;
	case sizeof(char):	present =  *(const char *)present_ptr; break;
	default:
		/* ANSI C mandates enum to be equivalent to integer */
		assert(pres_size != sizeof(int));
		return 0;	/* If not aborted, pass back safe value */
	}

	return present;
}

const char *asn_choice_name(const asn_TYPE_descriptor_t *td, const void *sptr)
{
	const asn_CHOICE_specifics_t *cspec = td->specifics;
	int present = _fetch_present_idx(sptr, cspec->pres_offset, cspec->pres_size);
	const asn_TYPE_member_t *elm;

	if (present < 0 || present >= td->elements_count)
		return "<invalid>";

	elm = &td->elements[present-1];
	return elm->name;
}

const char *asn_enum_name(const asn_TYPE_descriptor_t *td, int data)
{
	const asn_INTEGER_specifics_t *ispec = td->specifics;

	if (data < 0 || data >= ispec->map_count)
		return "<invalid>";

	return ispec->value2enum[data].enum_name;

}
