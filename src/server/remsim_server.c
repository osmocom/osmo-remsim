#include <unistd.h>
#include <signal.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <sys/eventfd.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>

#include "debug.h"
#include "slotmap.h"
#include "rest_api.h"
#include "rspro_server.h"

struct rspro_server *g_rps;
void *g_tall_ctx;
__thread void *talloc_asn1_ctx;

struct osmo_fd g_event_ofd;

static void handle_sig_usr1(int signal)
{
	OSMO_ASSERT(signal == SIGUSR1);
	talloc_report_full(g_tall_ctx, stderr);
}

static void print_help()
{
	printf( "  Some useful help...\n"
		"  -h --help                This text\n"
		"  -V --version             Print version of the program\n"
		"  -d --debug option        Enable debug logging (e.g. DMAIN:DST2)\n"
		"  -L --disable-color       Disable colors for logging to stderr\n"
		);
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "version", 0, 0, 'V' },
			{ "debug", 1, 0, 'd' },
			{ "disable-color", 0, 0, 'L' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hVd:L", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'V':
			printf("osmo-resmim-server version %s\n", VERSION);
			exit(0);
			break;
		case 'L':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		default:
			/* ignore */
			break;
		}
	}

	if (argc > optind) {
		fprintf(stderr, "Unsupported extra positional arguments in command line\n");
		exit(2);
	}
}

int main(int argc, char **argv)
{
	char hostname[256];
	void *talloc_rest_ctx;
	int rc;

	if (gethostname(hostname, sizeof(hostname)) < 0)
		OSMO_STRLCPY_ARRAY(hostname, "unknown");

	g_tall_ctx = talloc_named_const(NULL, 0, "global");
	talloc_asn1_ctx = talloc_named_const(g_tall_ctx, 0, "asn1");
	talloc_rest_ctx = talloc_named_const(g_tall_ctx, 0, "rest");
	msgb_talloc_ctx_init(g_tall_ctx, 0);

	osmo_init_logging2(g_tall_ctx, &log_info);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	osmo_fsm_log_addr(0);
	log_set_print_tid(osmo_stderr_target, 1);
	log_enable_multithread();

	handle_options(argc, argv);

	g_rps = rspro_server_create(g_tall_ctx, "0.0.0.0", 9998);
	if (!g_rps)
		exit(1);
	g_rps->slotmaps = slotmap_init(g_rps);
	if (!g_rps->slotmaps)
		goto out_rspro;

	g_rps->comp_id.type = ComponentType_remsimServer;
	OSMO_STRLCPY_ARRAY(g_rps->comp_id.name, hostname);
	OSMO_STRLCPY_ARRAY(g_rps->comp_id.software, "remsim-server");
	OSMO_STRLCPY_ARRAY(g_rps->comp_id.sw_version, PACKAGE_VERSION);
	/* FIXME: other members of app_comp_id */

	rc = eventfd(0, 0);
	if (rc < 0)
		goto out_rps;
	osmo_fd_setup(&g_event_ofd, rc, OSMO_FD_READ, event_fd_cb, g_rps, 0);
	rc = osmo_fd_register(&g_event_ofd);
	if (rc < 0)
		goto out_eventfd;

	signal(SIGUSR1, handle_sig_usr1);

	rc = rest_api_init(talloc_rest_ctx, 9997);
	if (rc < 0)
		goto out_unregister;

	while (1) {
		osmo_select_main(0);
	}

	rest_api_fini();

	exit(0);

out_unregister:
	osmo_fd_unregister(&g_event_ofd);
out_eventfd:
	close(g_event_ofd.fd);
out_rps:
	talloc_free(g_rps->slotmaps);
out_rspro:
	rspro_server_destroy(g_rps);

	exit(1);
}
