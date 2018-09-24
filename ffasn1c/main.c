
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <asn1defs.h>

#include "rspro.h"


static void transcode(const uint8_t *buf, unsigned int len)
{
	ASN1Error err;
	struct RsproPDU *pdu;
	int rc;
	char *gserbuf;

	rc = asn1_ber_decode((void **)&pdu, asn1_type_RsproPDU, buf, len, &err);
	printf("rc=%d\n", rc);

	rc = asn1_gser_encode((uint8_t **) &gserbuf, asn1_type_RsproPDU, pdu);
	printf("rc=%d\n", rc);
	printf("%s\n", gserbuf);
}

int main(int argc, char **argv)
{
	uint8_t buf[2048];
	int fd, rc;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		exit(1);
	rc = read(fd, buf, sizeof(buf));
	close(fd);

	transcode(buf, rc);
}
