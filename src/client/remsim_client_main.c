
#include <signal.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>

#include "client.h"

static void *g_tall_ctx;
void __thread *talloc_asn1_ctx;
int asn_debug;

static void handle_sig_usr1(int signal)
{
	OSMO_ASSERT(signal == SIGUSR1);
	talloc_report_full(g_tall_ctx, stderr);
}

static void printf_help()
{
	printf(
		"  -h --help                  Print this help message\n"
		"  -i --server-ip A.B.C.D     remsim-server IP address\n"
		"  -p --server-port 13245     remsim-server TCP port\n"
		"  -i --client-id <0-65535>   RSPRO ClientId of this client\n"
		"  -n --client-slot <0-65535> RSPRO SlotNr of this client\n"
	      );
}

static void handle_options(struct bankd_client *bc, int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static const struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "server-ip", 1, 0, 'i' },
			{ "server-port", 1, 0, 'p' },
			{ "client-id", 1, 0, 'c' },
			{ "client-slot", 1, 0, 'n' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hi:p:c:n:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			printf_help();
			exit(0);
			break;
		case 'i':
			bc->srv_conn.server_host = optarg;
			break;
		case 'p':
			bc->srv_conn.server_port = atoi(optarg);
			break;
		case 'c':
			remsim_client_set_clslot(bc, atoi(optarg), -1);
			break;
		case 'n':
			remsim_client_set_clslot(bc, -1, atoi(optarg));
			break;
		default:
			break;
		}
	}
}

int main(int argc, char **argv)
{
	struct bankd_client *g_client;
	char hostname[256];

	gethostname(hostname, sizeof(hostname));

	g_tall_ctx = talloc_named_const(NULL, 0, "global");
	talloc_asn1_ctx = talloc_named_const(g_tall_ctx, 0, "asn1");
	msgb_talloc_ctx_init(g_tall_ctx, 0);

	osmo_init_logging2(g_tall_ctx, &log_info);

	g_client = remsim_client_create(g_tall_ctx, hostname, "remsim-client");

	handle_options(g_client, argc, argv);

	osmo_fsm_inst_dispatch(g_client->srv_conn.fi, SRVC_E_ESTABLISH, NULL);

	signal(SIGUSR1, handle_sig_usr1);

	asn_debug = 0;

	client_user_main(g_client);
}
