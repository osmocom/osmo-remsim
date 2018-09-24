FFASN1C_LIBS = -L/usr/local/lib -lffasn1 -lffasn1_runtime_stdc
FFASN1C_CFLAGS = -I/usr/local/include/ffasn1c

CFLAGS+=-Wall $(FFASN1C_CFLAGS)
LIBS+=$(FFASN1C_LIBS)

main: main.o rspro.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

rspro.c: ../asn1/RSPRO.asn
	ffasn1c -o $@ $^

clean:
	@rm -f *.o main
