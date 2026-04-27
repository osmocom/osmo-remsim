#pragma once

#include <asn_application.h>

extern int asn_debug;

struct asn_TYPE_descriptor_t;

const char *asn_type_name(const asn_TYPE_descriptor_t *td);
const char *asn_choice_name(const asn_TYPE_descriptor_t *td, const void *sptr);
const char *asn_enum_name(const asn_TYPE_descriptor_t *td, int data);
