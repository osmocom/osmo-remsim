
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>
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
		"  -v --version               Print program version\n"
		"  -d --debug option          Enable debug logging (e.g. DMAIN:DST2)\n"
		"  -i --server-ip A.B.C.D     remsim-server IP address\n"
		"  -p --server-port 13245     remsim-server TCP port\n"
		"  -c --client-id <0-1023>    RSPRO ClientId of this client\n"
		"  -n --client-slot <0-1023>  RSPRO SlotNr of this client\n"
		"  -a --atr HEXSTRING         default ATR to simulate (until bankd overrides it)\n"
		"  -r --atr-ignore-rspro      Ignore any ATR from bankd; use only ATR given by -a)\n"
		"  -e --event-script <path>   event script to be called by client\n"
		"  -L --disable-color         Disable colors for logging to stderr\n"
#ifdef USB_SUPPORT
		"  -V --usb-vendor VENDOR_ID\n"
		"  -P --usb-product PRODUCT_ID\n"
		"  -C --usb-config CONFIG_ID\n"
		"  -I --usb-interface INTERFACE_ID\n"
		"  -S --usb-altsetting ALTSETTING_ID\n"
		"  -A --usb-address ADDRESS\n"
		"  -H --usb-path PATH\n"
#endif
	      );
}

static void handle_options(struct client_config *cfg, int argc, char **argv)
{
	int rc;

	while (1) {
		int option_index = 0, c;
		static const struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "version", 0, 0, 'v' },
			{ "debug", 1, 0, 'd' },
			{ "server-ip", 1, 0, 'i' },
			{ "server-port", 1, 0, 'p' },
			{ "client-id", 1, 0, 'c' },
			{ "client-slot", 1, 0, 'n' },
			{ "atr", 1, 0, 'a' },
			{ "atr-ignore-rspro", 0, 0, 'r' },
			{ "event-script", 1, 0, 'e' },
			{" disable-color", 0, 0, 'L' },
#ifdef USB_SUPPORT
			{ "usb-vendor", 1, 0, 'V' },
			{ "usb-product", 1, 0, 'P' },
			{ "usb-config", 1, 0, 'C' },
			{ "usb-interface", 1, 0, 'I' },
			{ "usb-altsetting", 1, 0, 'S' },
			{ "usb-address", 1, 0, 'A' },
			{ "usb-path", 1, 0, 'H' },
#endif
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hvd:i:p:c:n:a:re:L"
#ifdef USB_SUPPORT
						"V:P:C:I:S:A:H:"
#endif
				,
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			printf_help();
			exit(0);
			break;
		case 'v':
			printf("osmo-remsim-client version %s\n", VERSION);
			exit(0);
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'i':
			osmo_talloc_replace_string(cfg, &cfg->server_host, optarg);
			break;
		case 'p':
			cfg->server_port = atoi(optarg);
			break;
		case 'c':
			cfg->client_id = atoi(optarg);
			break;
		case 'n':
			cfg->client_slot = atoi(optarg);
			break;
		case 'a':
			rc = osmo_hexparse(optarg, cfg->atr.data, ARRAY_SIZE(cfg->atr.data));
			if (rc < 2 || rc > ARRAY_SIZE(cfg->atr.data)) {
				fprintf(stderr, "ATR malformed\n");
				exit(2);
			}
			break;
		case 'r':
			cfg->atr_ignore_rspro = true;
			break;
		case 'e':
			osmo_talloc_replace_string(cfg, &cfg->event_script, optarg);
			break;
		case 'L':
			log_set_use_color(osmo_stderr_target, 0);
			break;
#ifdef USB_SUPPORT
		case 'V':
			cfg->usb.vendor_id = strtol(optarg, NULL, 16);
			break;
		case 'P':
			cfg->usb.product_id = strtol(optarg, NULL, 16);
			break;
		case 'C':
			cfg->usb.config_id = atoi(optarg);
			break;
		case 'I':
			cfg->usb.if_num = atoi(optarg);
			break;
		case 'S':
			cfg->usb.altsetting = atoi(optarg);
			break;
		case 'A':
			cfg->usb.addr = atoi(optarg);
			break;
		case 'H':
			cfg->usb.path = optarg;
			break;
#endif
		default:
			break;
		}
	}
}


static int avoid_zombies(void)
{
	static struct sigaction sa_chld;

	sa_chld.sa_handler = SIG_IGN;
	sigemptyset(&sa_chld.sa_mask);
	sa_chld.sa_flags = SA_NOCLDWAIT;
	sa_chld.sa_restorer = NULL;

	return sigaction(SIGCHLD, &sa_chld, NULL);
}

int main(int argc, char **argv)
{
	struct bankd_client *g_client;
	struct client_config *cfg;
	char hostname[256];

	gethostname(hostname, sizeof(hostname));

	g_tall_ctx = talloc_named_const(NULL, 0, "global");
	talloc_asn1_ctx = talloc_named_const(g_tall_ctx, 0, "asn1");
	msgb_talloc_ctx_init(g_tall_ctx, 0);

	osmo_init_logging2(g_tall_ctx, &log_info);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	osmo_fsm_log_addr(0);

	cfg = client_config_init(g_tall_ctx);
	OSMO_ASSERT(cfg);
	handle_options(cfg, argc, argv);

	g_client = remsim_client_create(g_tall_ctx, hostname, "remsim-client",cfg);

	osmo_fsm_inst_dispatch(g_client->srv_conn.fi, SRVC_E_ESTABLISH, NULL);

	signal(SIGUSR1, handle_sig_usr1);

	/* Silently (and portably) reap children. */
	if (avoid_zombies() < 0) {
		LOGP(DMAIN, LOGL_FATAL, "Unable to silently reap children: %s\n", strerror(errno));
		exit(1);
	}

	asn_debug = 0;

	client_user_main(g_client);
}
