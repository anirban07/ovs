/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2016, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include "column.h"
#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "file.h"
#include "hash.h"
#include "openvswitch/json.h"
#include "jsonrpc.h"
#include "jsonrpc-server.h"
#include "openvswitch/list.h"
#include "memory.h"
#include "monitor.h"
#include "ovsdb.h"
#include "ovsdb-data.h"
#include "ovsdb-intf.h"
#include "ovsdb-types.h"
#include "ovsdb-error.h"
#include "openvswitch/poll-loop.h"
#include "process.h"
#include "replication.h"
#include "row.h"
#include "simap.h"
#include "openvswitch/shash.h"
#include "stream-ssl.h"
#include "stream.h"
#include "sset.h"
#include "storage.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "trigger.h"
#include "util.h"
#include "unixctl.h"
#include "perf-counter.h"
#include "ovsdb-util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_server);

struct db {
    char *filename;
    struct ovsdb *db;
    struct uuid row_uuid;
};

/* SSL configuration. */
static char *private_key_file;
static char *certificate_file;
static char *ca_cert_file;
static char *ssl_protocols;
static char *ssl_ciphers;
static bool bootstrap_ca_cert;

static void parse_options(int argc, char *argvp[],
                          struct sset *db_filenames, struct sset *remotes,
                          char **unixctl_pathp, char **run_command,
                          char **sync_from, char **sync_exclude,
                          bool *is_backup);
OVS_NO_RETURN static void usage(void);

static void save_config__(FILE *config_file, const struct sset *remotes,
                          const struct sset *db_filenames,
                          const char *sync_from, const char *sync_exclude,
                          bool is_backup);
static void load_config(FILE *config_file, struct sset *remotes,
                        struct sset *db_filenames, char **sync_from,
                        char **sync_exclude, bool *is_backup);
static struct json *
sset_to_json(const struct sset *sset);

static void
main_loop(DB_FUNCTION_TABLE *pDbFnTable, PDB_INTERFACE_CONTEXT_T pContext,
          struct unixctl_server *unixctl, struct process *run_process,
          bool *exiting)
{
    long long int status_timer = LLONG_MIN;

    *exiting = false;
    while (!*exiting) {
        memory_run();
        if (memory_should_report()) {
            pDbFnTable->pfn_db_memory_usage_report(pContext);
        }

        /* Run unixctl_server_run() before reconfigure_remotes() because
         * ovsdb-server/add-remote and ovsdb-server/remove-remote can change
         * the set of remotes that reconfigure_remotes() uses. */
        unixctl_server_run(unixctl);

        pDbFnTable->pfn_db_process_rpc_requests(pContext, pDbFnTable);
        if (run_process) {
            process_run();
            if (process_exited(run_process)) {
                *exiting = true;
            }
        }

        pDbFnTable->pfn_db_update_servers_and_wait(pDbFnTable, pContext,
            unixctl, run_process);
        if (run_process) {
            process_wait(run_process);
        }
        if (*exiting) {
            poll_immediate_wake();
        }
        poll_timer_wait_until(status_timer);
        poll_block();
        if (should_service_stop()) {
            *exiting = true;
        }
    }
}

int
main(int argc, char *argv[])
{
    char *unixctl_path = NULL;
    char *run_command = NULL;
    struct unixctl_server *unixctl;
    struct ovsdb_jsonrpc_server *jsonrpc;
    struct sset remotes, db_filenames;
    char *sync_from, *sync_exclude;
    bool is_backup;
    struct process *run_process;
    bool exiting;
    int retval;
    FILE *config_tmpfile;
    struct server_config server_config;
    struct shash all_dbs;
    DB_FUNCTION_TABLE *pDbFnTable = NULL;
    PDB_INTERFACE_CONTEXT_T pDbIntfContext = NULL;
    uint32_t ret_error = 0;

    ret_error = db_provider_init(&pDbFnTable);
    if (ret_error) {
        ovs_fatal(ret_error, "Unable to initialize provider");
    }
    ret_error = pDbFnTable->pfn_db_open_context(&pDbIntfContext, 0);
    if (ret_error) {
        db_provider_shutdown(pDbFnTable);
        ovs_fatal(ret_error, "Failed to fetch context");
    }

    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    fatal_ignore_sigpipe();
    process_init();

    bool active = false;
    parse_options(argc, argv, &db_filenames, &remotes, &unixctl_path,
                  &run_command, &sync_from, &sync_exclude, &active);
    is_backup = sync_from && !active;

    daemon_become_new_user(false);

    /* Create and initialize 'config_tmpfile' as a temporary file to hold
     * ovsdb-server's most basic configuration, and then save our initial
     * configuration to it.  When --monitor is used, this preserves the effects
     * of ovs-appctl commands such as ovsdb-server/add-remote (which saves the
     * new configuration) across crashes. */
    config_tmpfile = tmpfile();
    if (!config_tmpfile) {
        ovs_fatal(errno, "failed to create temporary file");
    }

    save_config__(config_tmpfile, &remotes, &db_filenames, sync_from,
                  sync_exclude, is_backup);

    daemonize_start(false);

    /* Load the saved config. */
    load_config(config_tmpfile, &remotes, &db_filenames, &sync_from,
                &sync_exclude, &is_backup);

    pDbFnTable->pfn_db_setup_ssl_configuration(
        private_key_file,
        certificate_file,
        ca_cert_file,
        ssl_protocols,
        ssl_ciphers,
        bootstrap_ca_cert
    );

    /* Start ovsdb jsonrpc server. When running as a backup server,
     * jsonrpc connections are read only. Otherwise, both read
     * and write transactions are allowed.  */
    jsonrpc = ovsdb_jsonrpc_server_create(is_backup);

    shash_init(&all_dbs);
    pDbFnTable->pfn_db_initialize_state(
        pDbIntfContext,
        &remotes,
        config_tmpfile,
        &all_dbs,
        jsonrpc,
        &sync_from,
        &sync_exclude,
        &is_backup,
        &db_filenames,
        &exiting,
        &server_config
    );

    retval = unixctl_server_create(unixctl_path, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }

    if (run_command) {
        char *run_argv[4];

        run_argv[0] = "/bin/sh";
        run_argv[1] = "-c";
        run_argv[2] = run_command;
        run_argv[3] = NULL;

        retval = process_start(run_argv, &run_process);
        if (retval) {
            ovs_fatal(retval, "%s: process failed to start", run_command);
        }
    } else {
        run_process = NULL;
    }

    daemonize_complete();

    if (!run_command) {
        /* ovsdb-server is usually a long-running process, in which case it
         * makes plenty of sense to log the version, but --run makes
         * ovsdb-server more like a command-line tool, so skip it.  */
        VLOG_INFO("%s (Open vSwitch) %s", program_name, VERSION);
    }
    pDbFnTable->pfn_db_unixctl_cmd_register(pDbIntfContext);

    main_loop(pDbFnTable, pDbIntfContext, unixctl, run_process, &exiting);

    pDbFnTable->pfn_db_terminate_state(
        pDbIntfContext,
        &db_filenames
    );

    unixctl_server_destroy(unixctl);
    if (run_process && process_exited(run_process)) {
        int status = process_status(run_process);
        if (status) {
            ovs_fatal(0, "%s: child exited, %s",
                      run_command, process_status_msg(status));
        }
    }
    perf_counters_destroy();
    service_stop();
    return 0;
}

static void
parse_options(int argc, char *argv[],
              struct sset *db_filenames, struct sset *remotes,
              char **unixctl_pathp, char **run_command,
              char **sync_from, char **sync_exclude, bool *active)
{
    enum {
        OPT_REMOTE = UCHAR_MAX + 1,
        OPT_UNIXCTL,
        OPT_RUN,
        OPT_BOOTSTRAP_CA_CERT,
        OPT_PEER_CA_CERT,
        OPT_SYNC_FROM,
        OPT_SYNC_EXCLUDE,
        OPT_ACTIVE,
        OPT_NO_DBS,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };

    static const struct option long_options[] = {
        {"remote",      required_argument, NULL, OPT_REMOTE},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
#ifndef _WIN32
        {"run",         required_argument, NULL, OPT_RUN},
#endif
        {"help",        no_argument, NULL, 'h'},
        {"version",     no_argument, NULL, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        STREAM_SSL_LONG_OPTIONS,
        {"sync-from",   required_argument, NULL, OPT_SYNC_FROM},
        {"sync-exclude-tables", required_argument, NULL, OPT_SYNC_EXCLUDE},
        {"active", no_argument, NULL, OPT_ACTIVE},
        {"no-dbs", no_argument, NULL, OPT_NO_DBS},
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);
    bool add_default_db = true;

    *sync_from = NULL;
    *sync_exclude = NULL;
    sset_init(db_filenames);
    sset_init(remotes);
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_REMOTE:
            sset_add(remotes, optarg);
            break;

        case OPT_UNIXCTL:
            *unixctl_pathp = optarg;
            break;

        case OPT_RUN:
            *run_command = optarg;
            break;

        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS

        case 'p':
            private_key_file = optarg;
            break;

        case 'c':
            certificate_file = optarg;
            break;

        case 'C':
            ca_cert_file = optarg;
            bootstrap_ca_cert = false;
            break;

        case OPT_SSL_PROTOCOLS:
            ssl_protocols = optarg;
            break;

        case OPT_SSL_CIPHERS:
            ssl_ciphers = optarg;
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            ca_cert_file = optarg;
            bootstrap_ca_cert = true;
            break;

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case OPT_SYNC_FROM:
            *sync_from = xstrdup(optarg);
            break;

        case OPT_SYNC_EXCLUDE: {
            char *err = set_blacklist_tables(optarg, false);
            if (err) {
                ovs_fatal(0, "%s", err);
            }
            *sync_exclude = xstrdup(optarg);
            break;
        }
        case OPT_ACTIVE:
            *active = true;
            break;

        case OPT_NO_DBS:
            add_default_db = false;
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;
    if (argc > 0) {
        for (int i = 0; i < argc; i++) {
            sset_add(db_filenames, argv[i]);
        }
    } else if (add_default_db) {
        sset_add_and_free(db_filenames, xasprintf("%s/conf.db", ovs_dbdir()));
    }
}

static void
usage(void)
{
    printf("%s: Open vSwitch database server\n"
           "usage: %s [OPTIONS] [DATABASE...]\n"
           "where each DATABASE is a database file in ovsdb format.\n"
           "The default DATABASE, if none is given, is\n%s/conf.db.\n",
           program_name, program_name, ovs_dbdir());
    printf("\nJSON-RPC options (may be specified any number of times):\n"
           "  --remote=REMOTE         connect or listen to REMOTE\n");
    stream_usage("JSON-RPC", true, true, true);
    daemon_usage();
    vlog_usage();
    replication_usage();
    printf("\nOther options:\n"
           "  --run COMMAND           run COMMAND as subprocess then exit\n"
           "  --unixctl=SOCKET        override default control socket name\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}

static struct json *
sset_to_json(const struct sset *sset)
{
    struct json *array;
    const char *s;

    array = json_array_create_empty();
    SSET_FOR_EACH (s, sset) {
        json_array_add(array, json_string_create(s));
    }
    return array;
}


static void
sset_from_json(struct sset *sset, const struct json *array)
{
    size_t i;

    sset_clear(sset);

    ovs_assert(array->type == JSON_ARRAY);
    for (i = 0; i < array->array.n; i++) {
        const struct json *elem = array->array.elems[i];
        sset_add(sset, json_string(elem));
    }
}

/* Truncates and replaces the contents of 'config_file' by a representation of
 * 'remotes' and 'db_filenames'. */
static void
save_config__(FILE *config_file, const struct sset *remotes,
              const struct sset *db_filenames, const char *sync_from,
              const char *sync_exclude, bool is_backup)
{
    struct json *obj;
    char *s;

    if (ftruncate(fileno(config_file), 0) == -1) {
        VLOG_FATAL("failed to truncate temporary file (%s)",
                   ovs_strerror(errno));
    }

    obj = json_object_create();
    json_object_put(obj, "remotes", sset_to_json(remotes));
    json_object_put(obj, "db_filenames", sset_to_json(db_filenames));
    if (sync_from) {
        json_object_put(obj, "sync_from", json_string_create(sync_from));
    }
    if (sync_exclude) {
        json_object_put(obj, "sync_exclude",
                        json_string_create(sync_exclude));
    }
    json_object_put(obj, "is_backup", json_boolean_create(is_backup));

    s = json_to_string(obj, 0);
    json_destroy(obj);

    if (fseek(config_file, 0, SEEK_SET) != 0
        || fputs(s, config_file) == EOF
        || fflush(config_file) == EOF) {
        VLOG_FATAL("failed to write temporary file (%s)", ovs_strerror(errno));
    }
    free(s);
}

/* Clears and replaces 'remotes' and 'dbnames' by a configuration read from
 * 'config_file', which must have been previously written by save_config(). */
static void
load_config(FILE *config_file, struct sset *remotes, struct sset *db_filenames,
            char **sync_from, char **sync_exclude, bool *is_backup)
{
    struct json *json;

    if (fseek(config_file, 0, SEEK_SET) != 0) {
        VLOG_FATAL("seek failed in temporary file (%s)", ovs_strerror(errno));
    }
    json = json_from_stream(config_file);
    if (json->type == JSON_STRING) {
        VLOG_FATAL("reading json failed (%s)", json_string(json));
    }
    ovs_assert(json->type == JSON_OBJECT);

    sset_from_json(remotes, shash_find_data(json_object(json), "remotes"));
    sset_from_json(db_filenames,
                   shash_find_data(json_object(json), "db_filenames"));

    struct json *string;
    string = shash_find_data(json_object(json), "sync_from");
    free(*sync_from);
    *sync_from = string ? xstrdup(json_string(string)) : NULL;

    string = shash_find_data(json_object(json), "sync_exclude");
    free(*sync_exclude);
    *sync_exclude = string ? xstrdup(json_string(string)) : NULL;

    *is_backup = json_boolean(shash_find_data(json_object(json), "is_backup"));

    json_destroy(json);
}
