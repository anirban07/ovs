#include <config.h> // every C source file must include this
#include <sys/stat.h>

#include "ovsdb-provider.h"
VLOG_DEFINE_THIS_MODULE(ovsdb_provider);

/* SSL configuration. */
static char *private_key_file;
static char *certificate_file;
static char *ca_cert_file;
static char *ssl_protocols;
static char *ssl_ciphers;
static bool bootstrap_ca_cert;

/** unixctl callback */
unixctl_cb_func ovsdb_server_exit;
unixctl_cb_func ovsdb_server_compact;
unixctl_cb_func ovsdb_server_reconnect;
unixctl_cb_func ovsdb_server_perf_counters_clear;
unixctl_cb_func ovsdb_server_perf_counters_show;
unixctl_cb_func ovsdb_server_disable_monitor_cond;
unixctl_cb_func ovsdb_server_set_active_ovsdb_server;
unixctl_cb_func ovsdb_server_get_active_ovsdb_server;
unixctl_cb_func ovsdb_server_connect_active_ovsdb_server;
unixctl_cb_func ovsdb_server_disconnect_active_ovsdb_server;
unixctl_cb_func ovsdb_server_set_sync_exclude_tables;
unixctl_cb_func ovsdb_server_get_sync_exclude_tables;
unixctl_cb_func ovsdb_server_get_sync_status;

unixctl_cb_func ovsdb_server_add_remote;
unixctl_cb_func ovsdb_server_remove_remote;
unixctl_cb_func ovsdb_server_list_remotes;

unixctl_cb_func ovsdb_server_add_database;
unixctl_cb_func ovsdb_server_remove_database;
unixctl_cb_func ovsdb_server_list_databases;

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
open_db(struct server_config *config, const char *filename);
static void
read_db(struct server_config *config, struct db *db);
static void
close_db(struct server_config *config, struct db *db, char *comment);
static void
add_db(struct server_config *config, struct db *db);
static void
remove_db(struct server_config *config, struct shash_node *node, char *comment);
static void
add_server_db(struct server_config *config);
static bool
is_already_open(struct server_config *config OVS_UNUSED,
                const char *filename OVS_UNUSED);
static void
log_and_free_error(struct ovsdb_error *error);
static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
parse_txn(struct server_config *config, struct db *db,
          struct ovsdb_schema *schema, const struct json *txn_json,
          const struct uuid *txnid);
static char *reconfigure_remotes(struct ovsdb_jsonrpc_server *,
                                 const struct shash *all_dbs,
                                 struct sset *remotes);
static char *reconfigure_ssl(const struct shash *all_dbs);
static void
query_db_remotes(const char *name, const struct shash *all_dbs,
                 struct shash *remotes, struct ds *errors);
static char * OVS_WARN_UNUSED_RESULT
parse_db_column(const struct shash *all_dbs,
                const char *name_,
                const struct db **dbp,
                const struct ovsdb_table **tablep,
                const struct ovsdb_column **columnp);
static char * OVS_WARN_UNUSED_RESULT
parse_db_column__(const struct shash *all_dbs,
                  const char *name_, char *name,
                  const struct db **dbp,
                  const struct ovsdb_table **tablep,
                  const struct ovsdb_column **columnp);
static struct ovsdb_jsonrpc_options *
add_remote(struct shash *remotes, const char *target);
static void
free_remotes(struct shash *remotes);
static const char *
query_db_string(const struct shash *all_dbs, const char *name,
                struct ds *errors);
static void
add_manager_options(struct shash *remotes, const struct ovsdb_row *row);
static char * OVS_WARN_UNUSED_RESULT
parse_db_string_column(const struct shash *all_dbs,
                       const char *name,
                       const struct db **dbp,
                       const struct ovsdb_table **tablep,
                       const struct ovsdb_column **columnp);
static void save_config__(FILE *config_file, const struct sset *remotes,
                          const struct sset *db_filenames,
                          const char *sync_from, const char *sync_exclude,
                          bool is_backup);
static void save_config(struct server_config *);
static void
ovsdb_replication_init(const char *sync_from, const char *exclude,
                       struct shash *all_dbs, const struct uuid *server_uuid);
static struct json *
sset_to_json(const struct sset *sset);
static void
report_error_if_changed(char *error, char **last_errorp);
static void update_remote_status(DB_FUNCTION_TABLE *pDbFnTable,
                                 PDB_INTERFACE_CONTEXT_T pContext,
                                 const struct ovsdb_jsonrpc_server *jsonrpc,
                                 const struct sset *remotes,
                                 struct shash *all_dbs);
static void update_server_status(DB_FUNCTION_TABLE *pDbFnTable,
    PDB_INTERFACE_CONTEXT_T pContext, struct shash *all_dbs);
static void
update_remote_rows(const struct shash *all_dbs, const struct db *db_,
                   const char *remote_name,
                   const struct ovsdb_jsonrpc_server *jsonrpc,
                   struct ovsdb_txn *txn);
static void
update_remote_row(const struct ovsdb_row *row, struct ovsdb_txn *txn,
                  const struct ovsdb_jsonrpc_server *jsonrpc);
static void
commit_txn(DB_FUNCTION_TABLE *pDbFnTable, PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_txn *txn, const char *name);
static void
update_database_status(struct ovsdb_row *row, struct db *db);

uint32_t
ovsdb_open_context(DB_INTERFACE_CONTEXT_T **ppContext, int argc, ...)
{

    DB_INTERFACE_CONTEXT_T *pContext = NULL;
    struct server_config *config = NULL;

    pContext = xzalloc(sizeof *pContext);
    if (pContext == NULL) {
        return 1;
    }
    if (argc != 0) {
        va_list argList = { 0 };
        va_start(argList, argc);
        pContext->db = va_arg(argList, struct ovsdb *);
        pContext->session = va_arg(argList, struct ovsdb_session *);
        pContext->read_only = va_arg(argList, int);
        pContext->jsonrpc_session = va_arg(argList, struct ovsdb_jsonrpc_session *);
        va_end(argList);
    }
    config = xzalloc(sizeof *config);
    if (config == NULL) {
        free(pContext);
        return 1;
    }
    pContext->server_cfg = config;

    *ppContext = pContext;

    return 0;
}

uint32_t
ovsdb_close_context(DB_INTERFACE_CONTEXT_T *pContext)
{
    if (pContext) {
        free(pContext->server_cfg);
        free(pContext);
    }
    return 0;
}

uint32_t
db_provider_init(DB_FUNCTION_TABLE **ppOvsdbFnTable)
{
    DB_FUNCTION_TABLE *pOvsdbFnTable = NULL;

    pOvsdbFnTable = xzalloc(sizeof *pOvsdbFnTable);

    pOvsdbFnTable->pfn_db_open_context = &ovsdb_open_context;
    pOvsdbFnTable->pfn_db_close_context = &ovsdb_close_context;
    pOvsdbFnTable->pfn_db_execute_compose = &ovsdb_execute_compose_intf;
    pOvsdbFnTable->pfn_db_txn_propose_commit = &ovsdb_txn_propose_commit_intf;
    pOvsdbFnTable->pfn_db_txn_progress_is_complete =
        &ovsdb_txn_progress_is_complete_intf;
    pOvsdbFnTable->pfn_db_monitor_create = &ovsdb_monitor_create_intf;
    pOvsdbFnTable->pfn_db_monitor_cond_change = &ovsdb_monitor_cond_change_intf;
    pOvsdbFnTable->pfn_db_monitor_cancel = &ovsdb_monitor_cancel_intf;
    pOvsdbFnTable->pfn_db_initialize_state = &ovsdb_initialize_state_intf;
    pOvsdbFnTable->pfn_db_setup_ssl_configuration =
        &ovsdb_setup_ssl_configuration_intf;
    pOvsdbFnTable->pfn_db_unixctl_cmd_register =
        &ovsdb_unixctl_cmd_register_intf;
    pOvsdbFnTable->pfn_db_memory_usage_report = &ovsdb_memory_usage_report_intf;
    pOvsdbFnTable->pfn_db_process_rpc_requests =
        &ovsdb_process_rpc_requests_intf;
    pOvsdbFnTable->pfn_db_update_servers_and_wait =
        &ovsdb_update_servers_and_wait_intf;
    pOvsdbFnTable->pfn_db_terminate_state = &ovsdb_terminate_state_intf;
    pOvsdbFnTable->pfn_db_add_session_to_context =
        &ovsdb_add_session_to_context_intf;
    pOvsdbFnTable->pfn_db_add_db_to_context = &ovsdb_add_db_to_context_intf;
    pOvsdbFnTable->pfn_db_create_trigger = &ovsdb_create_trigger_intf;

    *ppOvsdbFnTable = pOvsdbFnTable;

    return 0;
}

void
db_provider_shutdown(DB_FUNCTION_TABLE *pOvsdbFnTable)
{
    if (pOvsdbFnTable) {
        free(pOvsdbFnTable);
    }
}

struct ovsdb_txn *
ovsdb_execute_compose_intf( PDB_INTERFACE_CONTEXT_T pContext, bool read_only,
    const struct json *params, const char *role, const char *id,
    long long int elapsed_msec, long long int *timeout_msec, bool *durable,
    struct json **resultsp)
{
    return ovsdb_execute_compose(
        pContext->db, pContext->session, params, read_only, role, id,
        elapsed_msec, timeout_msec, durable, resultsp
    );
}

struct ovsdb_txn_progress *
ovsdb_txn_propose_commit_intf(PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_txn *txn, bool durable)
{
    return ovsdb_txn_propose_commit(txn, durable);
}

bool
ovsdb_txn_progress_is_complete_intf(PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    const struct ovsdb_txn_progress *p)
{
    return ovsdb_txn_progress_is_complete(p);
}

struct jsonrpc_msg *
ovsdb_monitor_create_intf(PDB_INTERFACE_CONTEXT_T pContext,
    struct json *params, enum ovsdb_monitor_version version, struct json *id)
{
    struct ovsdb_jsonrpc_session *s = pContext->jsonrpc_session;
    struct ovsdb *db = pContext->db;

    return ovsdb_jsonrpc_monitor_create(s, db, params, version, id);
}

struct jsonrpc_msg *
ovsdb_monitor_cond_change_intf(PDB_INTERFACE_CONTEXT_T pContext,
    struct json *params, struct json *id)
{
    return ovsdb_jsonrpc_monitor_cond_change(pContext->jsonrpc_session, params,
                                             id);
}

struct jsonrpc_msg *
ovsdb_monitor_cancel_intf(PDB_INTERFACE_CONTEXT_T pContext,
    struct json_array *params, struct json *id)
{
    return ovsdb_jsonrpc_monitor_cancel(pContext->jsonrpc_session, params, id);
}

uint32_t
ovsdb_initialize_state_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct sset *remotes,
    FILE *config_tmpfile,
    struct shash *all_dbs,
    struct ovsdb_jsonrpc_server *jsonrpc,
    char **sync_from,
    char **sync_exclude OVS_UNUSED,
    bool *is_backup,
    struct sset *db_filenames,
    bool *exiting,
    struct server_config *server_cfg
) {
    const char *db_filename;
    struct server_config *config = pContext->server_cfg;
    int retval OVS_UNUSED;

    pContext->exiting = exiting;

    config->remotes = remotes;
    config->config_tmpfile = config_tmpfile;
    config->all_dbs = all_dbs;
    config->jsonrpc = jsonrpc;
    config->sync_from = sync_from;
    config->is_backup = is_backup;

    perf_counters_init();

    SSET_FOR_EACH(db_filename, db_filenames) {
        struct ovsdb_error *error = open_db(config, db_filename);
        if (error) {
            ovs_fatal(0, "%s", ovsdb_error_to_string_free(error));
        }
    }

    add_server_db(config);

    char *error = reconfigure_remotes(
        config->jsonrpc,
        config->all_dbs,
        config->remotes
    );
    if (!error) {
        error = reconfigure_ssl(config->all_dbs);
    }
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    memcpy(server_cfg, config, sizeof(*config));

    return 0;
}

uint32_t
ovsdb_setup_ssl_configuration_intf(
    char *private_key_file_,
    char *certificate_file_,
    char *ca_cert_file_,
    char *ssl_protocols_,
    char *ssl_ciphers_,
    bool bootstrap_ca_cert_
) {
    private_key_file = private_key_file_;
    certificate_file = certificate_file_;
    ca_cert_file = ca_cert_file_;
    ssl_protocols = ssl_protocols_;
    ssl_ciphers = ssl_ciphers_;
    bootstrap_ca_cert = bootstrap_ca_cert_;

    return 0;
}

uint32_t
ovsdb_unixctl_cmd_register_intf(
    PDB_INTERFACE_CONTEXT_T pContext
) {
    unixctl_command_register(
        "exit",
        "",
        0,
        0,
        ovsdb_server_exit,
        pContext->exiting
    );
    unixctl_command_register(
        "ovsdb-server/compact",
        "",
        0,
        1,
        ovsdb_server_compact,
        pContext->server_cfg->all_dbs
    );
    unixctl_command_register(
        "ovsdb-server/reconnect",
        "",
        0,
        0,
        ovsdb_server_reconnect,
        pContext->server_cfg->jsonrpc
    );
    unixctl_command_register(
        "ovsdb-server/add-remote",
        "REMOTE",
        1,
        1,
        ovsdb_server_add_remote,
        pContext->server_cfg
    );
    unixctl_command_register(
        "ovsdb-server/remove-remote",
        "REMOTE",
        1,
        1,
        ovsdb_server_remove_remote,
        pContext->server_cfg
    );
    unixctl_command_register(
        "ovsdb-server/list-remotes",
        "",
        0,
        0,
        ovsdb_server_list_remotes,
        pContext->server_cfg->remotes
    );
    unixctl_command_register(
        "ovsdb-server/add-db",
        "DB",
        1,
        1,
        ovsdb_server_add_database,
        pContext->server_cfg
    );
    unixctl_command_register(
        "ovsdb-server/remove-db",
        "DB",
        1,
        1,
        ovsdb_server_remove_database,
        pContext->server_cfg
    );
    unixctl_command_register(
        "ovsdb-server/list-dbs",
        "",
        0,
        0,
        ovsdb_server_list_databases,
        pContext->server_cfg->all_dbs
    );
    unixctl_command_register(
        "ovsdb-server/perf-counters-show",
        "",
        0,
        0,
        ovsdb_server_perf_counters_show,
        NULL
    );
    unixctl_command_register(
        "ovsdb-server/perf-counters-clear",
        "",
        0,
        0,
        ovsdb_server_perf_counters_clear,
        NULL
    );
    unixctl_command_register(
        "ovsdb-server/set-active-ovsdb-server",
        "",
        1,
        1,
        ovsdb_server_set_active_ovsdb_server,
        pContext->server_cfg
    );
    unixctl_command_register(
        "ovsdb-server/get-active-ovsdb-server",
        "",
        0,
        0,
        ovsdb_server_get_active_ovsdb_server,
        pContext->server_cfg
    );
    unixctl_command_register(
        "ovsdb-server/connect-active-ovsdb-server",
        "",
        0,
        0,
        ovsdb_server_connect_active_ovsdb_server,
        pContext->server_cfg
    );
    unixctl_command_register(
        "ovsdb-server/disconnect-active-ovsdb-server",
        "",
        0,
        0,
        ovsdb_server_disconnect_active_ovsdb_server,
        pContext->server_cfg
    );
    unixctl_command_register(
        "ovsdb-server/set-sync-exclude-tables",
        "",
        0,
        1,
        ovsdb_server_set_sync_exclude_tables,
        pContext->server_cfg
    );
    unixctl_command_register(
        "ovsdb-server/get-sync-exclude-tables",
        "",
        0,
        0,
        ovsdb_server_get_sync_exclude_tables,
        NULL
    );
    unixctl_command_register(
        "ovsdb-server/sync-status",
        "",
        0,
        0,
        ovsdb_server_get_sync_status,
        pContext->server_cfg
    );
    /* Simulate the behavior of OVS release prior to version 2.5 that
     * does not support the monitor_cond method.  */
    unixctl_command_register(
        "ovsdb-server/disable-monitor-cond",
        "",
        0,
        0,
        ovsdb_server_disable_monitor_cond,
        pContext->server_cfg->jsonrpc
    );

    bool *is_backup = pContext->server_cfg->is_backup;
    struct ovsdb_jsonrpc_server *jsonrpc = pContext->server_cfg->jsonrpc;
    char *sync_from = *(pContext->server_cfg->sync_from);
    char *sync_exclude = *(pContext->server_cfg->sync_exclude);
    struct shash *all_dbs = pContext->server_cfg->all_dbs;

    if (*is_backup) {
        const struct uuid *server_uuid;
        server_uuid = ovsdb_jsonrpc_server_get_uuid(jsonrpc);
        ovsdb_replication_init(sync_from, sync_exclude, all_dbs, server_uuid);
    }

    return 0;
}

uint32_t
ovsdb_memory_usage_report_intf(
    PDB_INTERFACE_CONTEXT_T pContext
) {
    struct simap usage;
    struct server_config *config = pContext->server_cfg;
    struct shash_node *node;

    simap_init(&usage);
    ovsdb_jsonrpc_server_get_memory_usage(config->jsonrpc, &usage);
    ovsdb_monitor_get_memory_usage(&usage);
    SHASH_FOR_EACH(node, config->all_dbs) {
        struct db *db = node->data;
        ovsdb_get_memory_usage(db->db, &usage);
    }
    memory_report(&usage);
    simap_destroy(&usage);

    return 0;
}

uint32_t
ovsdb_process_rpc_requests_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    DB_FUNCTION_TABLE *pDbFnTable
) {
    char *remotes_error = NULL, *ssl_error = NULL;
    struct server_config *config = pContext->server_cfg;
    struct ovsdb_jsonrpc_server *jsonrpc = config->jsonrpc;
    struct shash *all_dbs = config->all_dbs;
    bool *is_backup = config->is_backup;
    struct sset *remotes = config->remotes;
    struct shash_node *node;

    ovsdb_jsonrpc_server_set_read_only(jsonrpc, *is_backup);

    report_error_if_changed(
        reconfigure_remotes(jsonrpc, all_dbs, remotes),
        &remotes_error);

    report_error_if_changed(reconfigure_ssl(all_dbs), &ssl_error);
    ovsdb_jsonrpc_server_run(jsonrpc, pContext, pDbFnTable);

    if (*is_backup) {
        replication_run(pDbFnTable, pContext);
        if (!replication_is_alive()) {
            disconnect_active_server();
            *is_backup = false;
        }
    }

    struct shash_node *next;
    SHASH_FOR_EACH_SAFE(node, next, all_dbs) {
        struct db *db = node->data;
        if (ovsdb_trigger_run(pDbFnTable, pContext, db->db, time_msec())) {
            ovsdb_jsonrpc_server_reconnect(
                jsonrpc, false,
                xasprintf("committed %s database schema conversion",
                db->db->name)
            );
        }
        ovsdb_storage_run(db->db->storage);
        read_db(config, db);
        if (ovsdb_storage_is_dead(db->db->storage)) {
            VLOG_INFO("%s: removing database because storage disconnected "
                      "permanently", node->name);
            remove_db(config, node,
                      xasprintf("removing database %s because storage "
                                "disconnected permanently", node->name));
        } else if (ovsdb_storage_should_snapshot(db->db->storage)) {
            log_and_free_error(ovsdb_snapshot(db->db));
        }
    }

    free(remotes_error);

    return 0;
}

uint32_t
ovsdb_update_servers_and_wait_intf(
    DB_FUNCTION_TABLE *pDbFnTable,
    PDB_INTERFACE_CONTEXT_T pContext,
    struct unixctl_server *unixctl,
    struct process *run_process OVS_UNUSED
) {
    long long int status_timer = LLONG_MIN;
    struct server_config *config = pContext->server_cfg;
    struct ovsdb_jsonrpc_server *jsonrpc = config->jsonrpc;
    struct shash *all_dbs = config->all_dbs;
    bool *is_backup = config->is_backup;
    struct sset *remotes = config->remotes;
    struct shash_node *node;

    if (time_msec() >= status_timer) {
        status_timer = time_msec() + 2500;
        update_remote_status(pDbFnTable, pContext, jsonrpc, remotes,
            all_dbs);
    }

    update_server_status(pDbFnTable, pContext, all_dbs);
    memory_wait();
    if (*is_backup) {
        replication_wait();
    }

    ovsdb_jsonrpc_server_wait(jsonrpc);
    unixctl_server_wait(unixctl);

    SHASH_FOR_EACH(node, all_dbs) {
        struct db *db = node->data;
        ovsdb_trigger_wait(db->db, time_msec());
        ovsdb_storage_wait(db->db->storage);
        ovsdb_storage_read_wait(db->db->storage);
    }

    return 0;
}

uint32_t
ovsdb_terminate_state_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct sset *db_filenames
) {
    struct shash *all_dbs = pContext->server_cfg->all_dbs;
    struct sset *remotes = pContext->server_cfg->remotes;
    struct ovsdb_jsonrpc_server *jsonrpc = pContext->server_cfg->jsonrpc;
    char *sync_from = NULL;
    char *sync_exclude = NULL;
    struct shash_node *node, *next;

    if (pContext->server_cfg->sync_from) {
         sync_from = *(pContext->server_cfg->sync_from);
    }
    if (pContext->server_cfg->sync_exclude) {
         sync_exclude = *(pContext->server_cfg->sync_exclude);
    }
    SHASH_FOR_EACH_SAFE(node, next, all_dbs) {
        struct db *db = node->data;
        close_db(pContext->server_cfg, db, xasprintf("removing %s database due "
            "to server termination", db->db->name));
        shash_delete(all_dbs, node);
    }
    ovsdb_jsonrpc_server_destroy(jsonrpc);
    shash_destroy(all_dbs);
    sset_destroy(remotes);
    sset_destroy(db_filenames);
    free(sync_from);
    free(sync_exclude);
    replication_destroy();

    return 0;
}

uint32_t
ovsdb_add_session_to_context_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_jsonrpc_session *s,
    struct jsonrpc_msg *request,
    bool monitor_cond_enable__,
    struct jsonrpc_msg **reply
) {
    pContext->jsonrpc_session = s;
    char *pRequestMethod;

    if (request != NULL) {
        pRequestMethod = request->method;
        if (!strcmp(pRequestMethod, "transact") ||
            !strcmp(pRequestMethod, "convert") ||
            !strcmp(pRequestMethod, "monitor") ||
            (monitor_cond_enable__ &&
                !strcmp(pRequestMethod, "monitor_cond"))) {
                pContext->db = ovsdb_jsonrpc_lookup_db(
                    pContext->jsonrpc_session, request, reply);
            }
    }


    pContext->session = &s->up;

    return 0;
}

uint32_t
ovsdb_add_db_to_context_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb *ovsdb
) {
    pContext->db = ovsdb;

    return 0;
}

uint32_t
ovsdb_create_trigger_intf(
    DB_FUNCTION_TABLE *pDbFnTable,
    PDB_INTERFACE_CONTEXT_T pContext,
    struct jsonrpc_msg *request
) {
    struct ovsdb_jsonrpc_session *s = pContext->jsonrpc_session;
    struct ovsdb *db = pContext->db;

    /* Check for duplicate ID. */
    size_t hash = json_hash(request->id, 0);
    struct ovsdb_jsonrpc_trigger *t
        = ovsdb_jsonrpc_trigger_find(s, request->id, hash);
    if (t) {
        ovsdb_jsonrpc_session_send(
            s, syntax_error_reply(request, "duplicate request ID"));
        jsonrpc_msg_destroy(request);
        return 1;
    }

    /* Insert into trigger table. */
    t = xmalloc(sizeof *t);
    VLOG_INFO("PT: should trigger init");
    bool disconnect_all = ovsdb_trigger_init(pDbFnTable, pContext,
        &s->up, db, &t->trigger, request, time_msec(), s->read_only,
        s->remote->role, jsonrpc_session_get_id(s->js));
    t->id = json_clone(request->id);
    hmap_insert(&s->triggers, &t->hmap_node, hash);

    VLOG_INFO("PT: should trigger complete");
    /* Complete early if possible. */
    if (ovsdb_trigger_is_complete(&t->trigger)) {
        ovsdb_jsonrpc_trigger_complete(t);
    }

    if (disconnect_all) {
        /* The message below is currently the only reason to disconnect all
         * clients. */
        ovsdb_jsonrpc_server_reconnect(s->remote->server, false,
                                       xasprintf("committed %s database "
                                                 "schema conversion",
                                                 db->name));
    }

    return 0;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
open_db(struct server_config *config, const char *filename)
{
    struct db *db;

    /* If we know that the file is already open, return a good error message.
     * Otherwise, if the file is open, we'll fail later on with a harder to
     * interpret file locking error. */
    if (is_already_open(config, filename)) {
        return ovsdb_error(NULL, "%s: already open", filename);
    }

    struct ovsdb_storage *storage;
    struct ovsdb_error *error;
    error = ovsdb_storage_open(filename, true, &storage);
    if (error) {
        return error;
    }

    db = xzalloc(sizeof *db);
    db->filename = xstrdup(filename);

    struct ovsdb_schema *schema;
    if (ovsdb_storage_is_clustered(storage)) {
        schema = NULL;
    } else {
        struct json *txn_json;
        error = ovsdb_storage_read(storage, &schema, &txn_json, NULL);
        if (error) {
            ovsdb_storage_close(storage);
            return error;
        }
        ovs_assert(schema && !txn_json);
    }
    db->db = ovsdb_create(schema, storage);
    ovsdb_jsonrpc_server_add_db(config->jsonrpc, db->db);

    read_db(config, db);

    error = (db->db->name[0] == '_'
             ? ovsdb_error(NULL, "%s: names beginning with \"_\" are reserved",
                           db->db->name)
             : shash_find(config->all_dbs, db->db->name)
             ? ovsdb_error(NULL, "%s: duplicate database name", db->db->name)
             : NULL);
    if (error) {
        char *error_s = ovsdb_error_to_string(error);
        close_db(config, db,
                 xasprintf("cannot complete opening %s database (%s)",
                           db->db->name, error_s));
        free(error_s);
        return error;
    }

    add_db(config, db);
    return NULL;
}

/* Add the internal _Server database to the server configuration. */
static void
add_server_db(struct server_config *config)
{
    struct json *schema_json = json_from_string(
#include "ovsdb/_server.ovsschema.inc"
        );
    ovs_assert(schema_json->type == JSON_OBJECT);

    struct ovsdb_schema *schema;
    struct ovsdb_error *error OVS_UNUSED = ovsdb_schema_from_json(schema_json,
                                                                  &schema);
    ovs_assert(!error);
    json_destroy(schema_json);

    struct db *db = xzalloc(sizeof *db);
    db->filename = xstrdup("<internal>");
    db->db = ovsdb_create(schema, ovsdb_storage_create_unbacked());
    bool ok OVS_UNUSED = ovsdb_jsonrpc_server_add_db(config->jsonrpc, db->db);
    ovs_assert(ok);
    add_db(config, db);
}

/* Returns true if 'filename' is known to be already open as a database,
 * false if not.
 *
 * "False negatives" are possible. */
static bool
is_already_open(struct server_config *config OVS_UNUSED,
                const char *filename OVS_UNUSED)
{
#ifndef _WIN32
    struct stat s;

    if (!stat(filename, &s)) {
        struct shash_node *node;

        SHASH_FOR_EACH (node, config->all_dbs) {
            struct db *db = node->data;
            struct stat s2;

            if (!stat(db->filename, &s2)
                && s.st_dev == s2.st_dev
                && s.st_ino == s2.st_ino) {
                return true;
            }
        }
    }
#endif  /* !_WIN32 */

    return false;
}

static void
read_db(struct server_config *config, struct db *db)
{
    struct ovsdb_error *error;
    for (;;) {
        struct ovsdb_schema *schema;
        struct json *txn_json;
        struct uuid txnid;
        error = ovsdb_storage_read(db->db->storage, &schema, &txn_json,
                                   &txnid);
        if (error) {
            break;
        } else if (!schema && !txn_json) {
            /* End of file. */
            return;
        } else {
            error = parse_txn(config, db, schema, txn_json, &txnid);
            json_destroy(txn_json);
            if (error) {
                break;
            }
        }
    }

    /* Log error but otherwise ignore it.  Probably the database just
     * got truncated due to power failure etc. and we should use its
     * current contents. */
    char *msg = ovsdb_error_to_string_free(error);
    VLOG_ERR("%s", msg);
    free(msg);
}

static void
add_db(struct server_config *config, struct db *db)
{
    db->row_uuid = UUID_ZERO;
    shash_add_assert(config->all_dbs, db->db->name, db);
}

static void
close_db(struct server_config *config, struct db *db, char *comment)
{
    if (db) {
        ovsdb_jsonrpc_server_remove_db(config->jsonrpc, db->db, comment);
        ovsdb_destroy(db->db);
        free(db->filename);
        free(db);
    } else {
        free(comment);
    }
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
parse_txn(struct server_config *config, struct db *db,
          struct ovsdb_schema *schema, const struct json *txn_json,
          const struct uuid *txnid)
{
    if (schema) {
        /* We're replacing the schema (and the data).  Destroy the database
         * (first grabbing its storage), then replace it with the new schema.
         * The transaction must also include the replacement data.
         *
         * Only clustered database schema changes go through this path. */
        ovs_assert(txn_json);
        ovs_assert(ovsdb_storage_is_clustered(db->db->storage));

        struct ovsdb_error *error = ovsdb_schema_check_for_ephemeral_columns(
            schema);
        if (error) {
            return error;
        }

        ovsdb_jsonrpc_server_reconnect(
            config->jsonrpc, false,
            (db->db->schema
             ? xasprintf("database %s schema changed", db->db->name)
             : xasprintf("database %s connected to storage", db->db->name)));

        ovsdb_replace(db->db, ovsdb_create(schema, NULL));

        /* Force update to schema in _Server database. */
        db->row_uuid = UUID_ZERO;
    }

    if (txn_json) {
        if (!db->db->schema) {
            return ovsdb_error(NULL, "%s: data without schema", db->filename);
        }

        struct ovsdb_txn *txn;
        struct ovsdb_error *error;

        error = ovsdb_file_txn_from_json(db->db, txn_json, false, &txn);
        if (!error) {
            log_and_free_error(ovsdb_txn_replay_commit(txn));
        }
        if (!error && !uuid_is_zero(txnid)) {
            db->db->prereq = *txnid;
        }
        if (error) {
            ovsdb_storage_unread(db->db->storage);
            return error;
        }
    }

    return NULL;
}

static void
log_and_free_error(struct ovsdb_error *error)
{
    if (error) {
        char *s = ovsdb_error_to_string_free(error);
        VLOG_INFO("%s", s);
        free(s);
    }
}

/* Reconfigures ovsdb-server's remotes based on information in the database. */
static char *
reconfigure_remotes(struct ovsdb_jsonrpc_server *jsonrpc,
                    const struct shash *all_dbs, struct sset *remotes)
{
    struct ds errors = DS_EMPTY_INITIALIZER;
    struct shash resolved_remotes;
    const char *name;

    /* Configure remotes. */
    shash_init(&resolved_remotes);
    SSET_FOR_EACH (name, remotes) {
        if (!strncmp(name, "db:", 3)) {
            query_db_remotes(name, all_dbs, &resolved_remotes, &errors);
        } else {
            add_remote(&resolved_remotes, name);
        }
    }
    ovsdb_jsonrpc_server_set_remotes(jsonrpc, &resolved_remotes);
    free_remotes(&resolved_remotes);

    return errors.string;
}

static char *
reconfigure_ssl(const struct shash *all_dbs)
{
    struct ds errors = DS_EMPTY_INITIALIZER;
    const char *resolved_private_key;
    const char *resolved_certificate;
    const char *resolved_ca_cert;
    const char *resolved_ssl_protocols;
    const char *resolved_ssl_ciphers;

    resolved_private_key = query_db_string(all_dbs, private_key_file, &errors);
    resolved_certificate = query_db_string(all_dbs, certificate_file, &errors);
    resolved_ca_cert = query_db_string(all_dbs, ca_cert_file, &errors);
    resolved_ssl_protocols = query_db_string(all_dbs, ssl_protocols, &errors);
    resolved_ssl_ciphers = query_db_string(all_dbs, ssl_ciphers, &errors);

    stream_ssl_set_key_and_cert(resolved_private_key, resolved_certificate);
    stream_ssl_set_ca_cert_file(resolved_ca_cert, bootstrap_ca_cert);
    stream_ssl_set_protocols(resolved_ssl_protocols);
    stream_ssl_set_ciphers(resolved_ssl_ciphers);

    return errors.string;
}

/* Returns NULL if successful, otherwise a malloc()'d string describing the
 * error. */
static char * OVS_WARN_UNUSED_RESULT
parse_db_column(const struct shash *all_dbs,
                const char *name_,
                const struct db **dbp,
                const struct ovsdb_table **tablep,
                const struct ovsdb_column **columnp)
{
    char *name = xstrdup(name_);
    char *retval = parse_db_column__(all_dbs, name_, name,
                                     dbp, tablep, columnp);
    free(name);
    return retval;
}

static void
query_db_remotes(const char *name, const struct shash *all_dbs,
                 struct shash *remotes, struct ds *errors)
{
    const struct ovsdb_column *column;
    const struct ovsdb_table *table;
    const struct ovsdb_row *row;
    const struct db *db;
    char *retval;

    retval = parse_db_column(all_dbs, name, &db, &table, &column);
    if (retval) {
        if (db && !db->db->schema) {
            /* 'db' is a clustered database but it hasn't connected to the
             * cluster yet, so we can't get anything out of it, not even a
             * schema.  Not really an error. */
        } else {
            ds_put_format(errors, "%s\n", retval);
        }
        free(retval);
        return;
    }

    if (column->type.key.type == OVSDB_TYPE_STRING
        && column->type.value.type == OVSDB_TYPE_VOID) {
        HMAP_FOR_EACH (row, hmap_node, &table->rows) {
            const struct ovsdb_datum *datum;
            size_t i;

            datum = &row->fields[column->index];
            for (i = 0; i < datum->n; i++) {
                add_remote(remotes, datum->keys[i].string);
            }
        }
    } else if (column->type.key.type == OVSDB_TYPE_UUID
               && column->type.key.uuid.refTable
               && column->type.value.type == OVSDB_TYPE_VOID) {
        const struct ovsdb_table *ref_table = column->type.key.uuid.refTable;
        HMAP_FOR_EACH (row, hmap_node, &table->rows) {
            const struct ovsdb_datum *datum;
            size_t i;

            datum = &row->fields[column->index];
            for (i = 0; i < datum->n; i++) {
                const struct ovsdb_row *ref_row;

                ref_row = ovsdb_table_get_row(ref_table, &datum->keys[i].uuid);
                if (ref_row) {
                    add_manager_options(remotes, ref_row);
                }
            }
        }
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_db_column__(const struct shash *all_dbs,
                  const char *name_, char *name,
                  const struct db **dbp,
                  const struct ovsdb_table **tablep,
                  const struct ovsdb_column **columnp)
{
    const char *db_name, *table_name, *column_name;
    const char *tokens[3];
    char *save_ptr = NULL;

    *dbp = NULL;
    *tablep = NULL;
    *columnp = NULL;

    strtok_r(name, ":", &save_ptr); /* "db:" */
    tokens[0] = strtok_r(NULL, ",", &save_ptr);
    tokens[1] = strtok_r(NULL, ",", &save_ptr);
    tokens[2] = strtok_r(NULL, ",", &save_ptr);
    if (!tokens[0] || !tokens[1] || !tokens[2]) {
        return xasprintf("\"%s\": invalid syntax", name_);
    }

    db_name = tokens[0];
    table_name = tokens[1];
    column_name = tokens[2];

    *dbp = shash_find_data(all_dbs, tokens[0]);
    if (!*dbp) {
        return xasprintf("\"%s\": no database named %s", name_, db_name);
    }

    *tablep = ovsdb_get_table((*dbp)->db, table_name);
    if (!*tablep) {
        return xasprintf("\"%s\": no table named %s", name_, table_name);
    }

    *columnp = ovsdb_table_schema_get_column((*tablep)->schema, column_name);
    if (!*columnp) {
        return xasprintf("\"%s\": table \"%s\" has no column \"%s\"",
                         name_, table_name, column_name);
    }

    return NULL;
}

static struct ovsdb_jsonrpc_options *
add_remote(struct shash *remotes, const char *target)
{
    struct ovsdb_jsonrpc_options *options;

    options = shash_find_data(remotes, target);
    if (!options) {
        options = ovsdb_jsonrpc_default_options(target);
        shash_add(remotes, target, options);
    }

    return options;
}

static void
free_remotes(struct shash *remotes)
{
    if (remotes) {
        struct shash_node *node;

        SHASH_FOR_EACH (node, remotes) {
            struct ovsdb_jsonrpc_options *options = node->data;
            free(options->role);
        }
        shash_destroy_free_data(remotes);
    }
}

static const char *
query_db_string(const struct shash *all_dbs, const char *name,
                struct ds *errors)
{
    if (!name || strncmp(name, "db:", 3)) {
        return name;
    } else {
        const struct ovsdb_column *column;
        const struct ovsdb_table *table;
        const struct ovsdb_row *row;
        const struct db *db;
        char *retval;

        retval = parse_db_string_column(all_dbs, name,
                                        &db, &table, &column);
        if (retval) {
            if (db && !db->db->schema) {
                /* 'db' is a clustered database but it hasn't connected to the
                 * cluster yet, so we can't get anything out of it, not even a
                 * schema.  Not really an error. */
            } else {
                ds_put_format(errors, "%s\n", retval);
            }
            free(retval);
            return NULL;
        }

        HMAP_FOR_EACH (row, hmap_node, &table->rows) {
            const struct ovsdb_datum *datum;
            size_t i;

            datum = &row->fields[column->index];
            for (i = 0; i < datum->n; i++) {
                if (datum->keys[i].string[0]) {
                    return datum->keys[i].string;
                }
            }
        }
        return NULL;
    }
}

/* Adds a remote and options to 'remotes', based on the Manager table row in
 * 'row'. */
static void
add_manager_options(struct shash *remotes, const struct ovsdb_row *row)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    struct ovsdb_jsonrpc_options *options;
    long long int max_backoff, probe_interval;
    bool read_only;
    const char *target, *dscp_string, *role;

    if (!ovsdb_util_read_string_column(row, "target", &target) || !target) {
        VLOG_INFO_RL(&rl, "Table `%s' has missing or invalid `target' column",
                     row->table->schema->name);
        return;
    }

    options = add_remote(remotes, target);
    if (ovsdb_util_read_integer_column(row, "max_backoff", &max_backoff)) {
        options->max_backoff = max_backoff;
    }
    if (ovsdb_util_read_integer_column(row, "inactivity_probe",
                                       &probe_interval)) {
        options->probe_interval = probe_interval;
    }
    if (ovsdb_util_read_bool_column(row, "read_only", &read_only)) {
        options->read_only = read_only;
    }

    free(options->role);
    options->role = NULL;
    if (ovsdb_util_read_string_column(row, "role", &role) && role) {
        options->role = xstrdup(role);
    }

    options->dscp = DSCP_DEFAULT;
    dscp_string = ovsdb_util_read_map_string_column(row, "other_config",
                                                    "dscp");
    if (dscp_string) {
        int dscp = atoi(dscp_string);
        if (dscp >= 0 && dscp <= 63) {
            options->dscp = dscp;
        }
    }
}

/* Returns NULL if successful, otherwise a malloc()'d string describing the
 * error. */
static char * OVS_WARN_UNUSED_RESULT
parse_db_string_column(const struct shash *all_dbs,
                       const char *name,
                       const struct db **dbp,
                       const struct ovsdb_table **tablep,
                       const struct ovsdb_column **columnp)
{
    char *retval;

    retval = parse_db_column(all_dbs, name, dbp, tablep, columnp);
    if (retval) {
        return retval;
    }

    if ((*columnp)->type.key.type != OVSDB_TYPE_STRING
        || (*columnp)->type.value.type != OVSDB_TYPE_VOID) {
        return xasprintf("\"%s\": table \"%s\" column \"%s\" is "
                         "not string or set of strings",
                         name, (*tablep)->schema->name, (*columnp)->name);
    }

    return NULL;
}


void
ovsdb_server_set_active_ovsdb_server(struct unixctl_conn *conn,
                                     int argc OVS_UNUSED, const char *argv[],
                                     void *config_)
{
    struct server_config *config = config_;

    if (*config->sync_from) {
        free(*config->sync_from);
    }
    *config->sync_from = xstrdup(argv[1]);
    save_config(config);

    unixctl_command_reply(conn, NULL);
}

void
ovsdb_server_get_active_ovsdb_server(struct unixctl_conn *conn,
                                     int argc OVS_UNUSED,
                                     const char *argv[] OVS_UNUSED,
                                     void *config_ )
{
    struct server_config *config = config_;

    unixctl_command_reply(conn, *config->sync_from);
}

void
ovsdb_server_connect_active_ovsdb_server(struct unixctl_conn *conn,
                                         int argc OVS_UNUSED,
                                         const char *argv[] OVS_UNUSED,
                                         void *config_)
{
    struct server_config *config = config_;
    char *msg = NULL;

    if ( !*config->sync_from) {
        msg = "Unable to connect: active server is not specified.\n";
    } else {
        const struct uuid *server_uuid;
        server_uuid = ovsdb_jsonrpc_server_get_uuid(config->jsonrpc);
        ovsdb_replication_init(*config->sync_from, *config->sync_exclude,
                               config->all_dbs, server_uuid);
        if (!*config->is_backup) {
            *config->is_backup = true;
            save_config(config);
        }
    }
    unixctl_command_reply(conn, msg);
}

void
ovsdb_server_disconnect_active_ovsdb_server(struct unixctl_conn *conn,
                                            int argc OVS_UNUSED,
                                            const char *argv[] OVS_UNUSED,
                                            void *config_)
{
    struct server_config *config = config_;

    disconnect_active_server();
    *config->is_backup = false;
    save_config(config);
    unixctl_command_reply(conn, NULL);
}

void
ovsdb_server_set_sync_exclude_tables(struct unixctl_conn *conn,
                                     int argc OVS_UNUSED,
                                     const char *argv[],
                                     void *config_)
{
    struct server_config *config = config_;

    char *err = set_blacklist_tables(argv[1], true);
    if (!err) {
        free(*config->sync_exclude);
        *config->sync_exclude = xstrdup(argv[1]);
        save_config(config);
        if (*config->is_backup) {
            const struct uuid *server_uuid;
            server_uuid = ovsdb_jsonrpc_server_get_uuid(config->jsonrpc);
            ovsdb_replication_init(*config->sync_from, *config->sync_exclude,
                                   config->all_dbs, server_uuid);
        }
        err = set_blacklist_tables(argv[1], false);
    }
    unixctl_command_reply(conn, err);
    free(err);
}

void
ovsdb_server_get_sync_exclude_tables(struct unixctl_conn *conn,
                                     int argc OVS_UNUSED,
                                     const char *argv[] OVS_UNUSED,
                                     void *arg_ OVS_UNUSED)
{
    char *reply = get_blacklist_tables();
    unixctl_command_reply(conn, reply);
    free(reply);
}

void
ovsdb_server_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED,
                  void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}


void
ovsdb_server_perf_counters_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                                const char *argv[] OVS_UNUSED,
                                void *arg_ OVS_UNUSED)
{
    char *s = perf_counters_to_string();

    unixctl_command_reply(conn, s);
    free(s);
}

void
ovsdb_server_perf_counters_clear(struct unixctl_conn *conn, int argc OVS_UNUSED,
                                 const char *argv[] OVS_UNUSED,
                                 void *arg_ OVS_UNUSED)
{
    perf_counters_clear();
    unixctl_command_reply(conn, NULL);
}

/* "ovsdb-server/disable-monitor-cond": makes ovsdb-server drop all of its
 * JSON-RPC connections and reconnect. New sessions will not recognize
 * the 'monitor_cond' method.   */
void
ovsdb_server_disable_monitor_cond(struct unixctl_conn *conn,
                                  int argc OVS_UNUSED,
                                  const char *argv[] OVS_UNUSED,
                                  void *jsonrpc_)
{
    struct ovsdb_jsonrpc_server *jsonrpc = jsonrpc_;

    ovsdb_jsonrpc_disable_monitor_cond();
    ovsdb_jsonrpc_server_reconnect(
        jsonrpc, true, xstrdup("user ran ovsdb-server/disable-monitor"));
    unixctl_command_reply(conn, NULL);
}

void
ovsdb_server_compact(struct unixctl_conn *conn, int argc,
                     const char *argv[], void *dbs_)
{
    const char *db_name = argc < 2 ? NULL : argv[1];
    struct shash *all_dbs = dbs_;
    struct ds reply;
    struct shash_node *node;
    int n = 0;

    if (db_name && db_name[0] == '_') {
        unixctl_command_reply_error(conn, "cannot compact built-in databases");
        return;
    }

    ds_init(&reply);
    SHASH_FOR_EACH(node, all_dbs) {
        struct db *db = node->data;
        if (db_name
            ? !strcmp(node->name, db_name)
            : node->name[0] != '_') {
            if (db->db) {
                VLOG_INFO("compacting %s database by user request",
                          node->name);

                struct ovsdb_error *error = ovsdb_snapshot(db->db);
                if (error) {
                    char *s = ovsdb_error_to_string(error);
                    ds_put_format(&reply, "%s\n", s);
                    free(s);
                    ovsdb_error_destroy(error);
                }

                n++;
            }
        }
    }

    if (!n) {
        unixctl_command_reply_error(conn, "no database by that name");
    } else if (reply.length) {
        unixctl_command_reply_error(conn, ds_cstr(&reply));
    } else {
        unixctl_command_reply(conn, NULL);
    }
    ds_destroy(&reply);
}

/* "ovsdb-server/reconnect": makes ovsdb-server drop all of its JSON-RPC
 * connections and reconnect. */
void
ovsdb_server_reconnect(struct unixctl_conn *conn, int argc OVS_UNUSED,
                       const char *argv[] OVS_UNUSED, void *jsonrpc_)
{
    struct ovsdb_jsonrpc_server *jsonrpc = jsonrpc_;
    ovsdb_jsonrpc_server_reconnect(
        jsonrpc, true, xstrdup("user ran ovsdb-server/reconnect"));
    unixctl_command_reply(conn, NULL);
}

/* "ovsdb-server/add-remote REMOTE": adds REMOTE to the set of remotes that
 * ovsdb-server services. */
void
ovsdb_server_add_remote(struct unixctl_conn *conn, int argc OVS_UNUSED,
                        const char *argv[], void *config_)
{
    struct server_config *config = config_;
    const char *remote = argv[1];

    const struct ovsdb_column *column;
    const struct ovsdb_table *table;
    const struct db *db;
    char *retval;

    retval = (strncmp("db:", remote, 3)
              ? NULL
              : parse_db_column(config->all_dbs, remote,
                                &db, &table, &column));
    if (!retval) {
        if (sset_add(config->remotes, remote)) {
            save_config(config);
        }
        unixctl_command_reply(conn, NULL);
    } else {
        unixctl_command_reply_error(conn, retval);
        free(retval);
    }
}

/* "ovsdb-server/remove-remote REMOTE": removes REMOTE frmo the set of remotes
 * that ovsdb-server services. */
void
ovsdb_server_remove_remote(struct unixctl_conn *conn, int argc OVS_UNUSED,
                           const char *argv[], void *config_)
{
    struct server_config *config = config_;
    struct sset_node *node;

    node = sset_find(config->remotes, argv[1]);
    if (node) {
        sset_delete(config->remotes, node);
        save_config(config);
        unixctl_command_reply(conn, NULL);
    } else {
        unixctl_command_reply_error(conn, "no such remote");
    }
}

/* "ovsdb-server/list-remotes": outputs a list of configured rmeotes. */
void
ovsdb_server_list_remotes(struct unixctl_conn *conn, int argc OVS_UNUSED,
                          const char *argv[] OVS_UNUSED, void *remotes_)
{
    struct sset *remotes = remotes_;
    const char **list, **p;
    struct ds s;

    ds_init(&s);

    list = sset_sort(remotes);
    for (p = list; *p; p++) {
        ds_put_format(&s, "%s\n", *p);
    }
    free(list);

    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}

/* "ovsdb-server/add-db DB": adds the DB to ovsdb-server. */
void
ovsdb_server_add_database(struct unixctl_conn *conn, int argc OVS_UNUSED,
                          const char *argv[], void *config_)
{
    struct server_config *config = config_;
    const char *filename = argv[1];

    char *error = ovsdb_error_to_string_free(open_db(config, filename));
    if (!error) {
        save_config(config);
        if (*config->is_backup) {
            const struct uuid *server_uuid;
            server_uuid = ovsdb_jsonrpc_server_get_uuid(config->jsonrpc);
            ovsdb_replication_init(*config->sync_from, *config->sync_exclude,
                                   config->all_dbs, server_uuid);
        }
        unixctl_command_reply(conn, NULL);
    } else {
        unixctl_command_reply_error(conn, error);
        free(error);
    }
}


static void
remove_db(struct server_config *config, struct shash_node *node, char *comment)
{
    struct db *db = node->data;

    close_db(config, db, comment);
    shash_delete(config->all_dbs, node);

    save_config(config);
    if (*config->is_backup) {
        const struct uuid *server_uuid;
        server_uuid = ovsdb_jsonrpc_server_get_uuid(config->jsonrpc);
        ovsdb_replication_init(*config->sync_from, *config->sync_exclude,
                               config->all_dbs, server_uuid);
    }
}

void
ovsdb_server_remove_database(struct unixctl_conn *conn, int argc OVS_UNUSED,
                             const char *argv[], void *config_)
{
    struct server_config *config = config_;
    struct shash_node *node;

    node = shash_find(config->all_dbs, argv[1]);
    if (!node) {
        unixctl_command_reply_error(conn, "Failed to find the database.");
        return;
    }
    if (node->name[0] == '_') {
        unixctl_command_reply_error(conn, "Cannot remove reserved database.");
        return;
    }

    remove_db(config, node, xasprintf("removing %s database by user request",
                                      node->name));
    unixctl_command_reply(conn, NULL);
}

void
ovsdb_server_list_databases(struct unixctl_conn *conn, int argc OVS_UNUSED,
                            const char *argv[] OVS_UNUSED, void *all_dbs_)
{
    struct shash *all_dbs = all_dbs_;
    const struct shash_node **nodes;
    struct ds s;
    size_t i;

    ds_init(&s);

    nodes = shash_sort(all_dbs);
    for (i = 0; i < shash_count(all_dbs); i++) {
        const struct shash_node *node = nodes[i];
        struct db *db = node->data;
        if (db->db) {
            ds_put_format(&s, "%s\n", node->name);
        }
    }
    free(nodes);

    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}

void
ovsdb_server_get_sync_status(struct unixctl_conn *conn, int argc OVS_UNUSED,
                             const char *argv[] OVS_UNUSED, void *config_)
{
    struct server_config *config = config_;
    bool is_backup = *config->is_backup;
    struct ds ds = DS_EMPTY_INITIALIZER;

    ds_put_format(&ds, "state: %s\n", is_backup ? "backup" : "active");

    if (is_backup) {
        ds_put_and_free_cstr(&ds, replication_status());
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
ovsdb_replication_init(const char *sync_from, const char *exclude,
                       struct shash *all_dbs, const struct uuid *server_uuid)
{
    replication_init(sync_from, exclude, server_uuid);
    struct shash_node *node;
    SHASH_FOR_EACH (node, all_dbs) {
        struct db *db = node->data;
        if (node->name[0] != '_' && db->db) {
            replication_add_local_db(node->name, db->db);
        }
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

/* Truncates and replaces the contents of 'config_file' by a representation of
 * 'config'. */
static void
save_config(struct server_config *config)
{
    struct sset db_filenames;
    struct shash_node *node;

    sset_init(&db_filenames);
    SHASH_FOR_EACH (node, config->all_dbs) {
        struct db *db = node->data;
        if (node->name[0] != '_') {
            sset_add(&db_filenames, db->filename);
        }
    }

    save_config__(config->config_tmpfile, config->remotes, &db_filenames,
                  *config->sync_from, *config->sync_exclude,
                  *config->is_backup);

    sset_destroy(&db_filenames);
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
report_error_if_changed(char *error, char **last_errorp)
{
    if (error) {
        if (!*last_errorp || strcmp(error, *last_errorp)) {
            VLOG_WARN("%s", error);
            free(*last_errorp);
            *last_errorp = error;
            return;
        }
        free(error);
    } else {
        free(*last_errorp);
        *last_errorp = NULL;
    }
}

static void
update_remote_status(DB_FUNCTION_TABLE *pDbFnTable,
                     PDB_INTERFACE_CONTEXT_T pContext,
                     const struct ovsdb_jsonrpc_server *jsonrpc,
                     const struct sset *remotes,
                     struct shash *all_dbs)
{
    struct shash_node *node;
    SHASH_FOR_EACH (node, all_dbs) {
        struct db *db = node->data;
        if (!db->db || ovsdb_storage_is_clustered(db->db->storage)) {
            continue;
        }

        struct ovsdb_txn *txn = ovsdb_txn_create(db->db);
        const char *remote;
        SSET_FOR_EACH (remote, remotes) {
            update_remote_rows(all_dbs, db, remote, jsonrpc, txn);
        }
        commit_txn(pDbFnTable, pContext, txn, "remote status");
    }
}

static void
update_remote_rows(const struct shash *all_dbs, const struct db *db_,
                   const char *remote_name,
                   const struct ovsdb_jsonrpc_server *jsonrpc,
                   struct ovsdb_txn *txn)
{
    const struct ovsdb_table *table, *ref_table;
    const struct ovsdb_column *column;
    const struct ovsdb_row *row;
    const struct db *db;
    char *retval;

    if (strncmp("db:", remote_name, 3)) {
        return;
    }

    retval = parse_db_column(all_dbs, remote_name, &db, &table, &column);
    if (retval) {
        free(retval);
        return;
    }

    if (db != db_
        || column->type.key.type != OVSDB_TYPE_UUID
        || !column->type.key.uuid.refTable
        || column->type.value.type != OVSDB_TYPE_VOID) {
        return;
    }

    ref_table = column->type.key.uuid.refTable;

    HMAP_FOR_EACH (row, hmap_node, &table->rows) {
        const struct ovsdb_datum *datum;
        size_t i;

        datum = &row->fields[column->index];
        for (i = 0; i < datum->n; i++) {
            const struct ovsdb_row *ref_row;

            ref_row = ovsdb_table_get_row(ref_table, &datum->keys[i].uuid);
            if (ref_row) {
                update_remote_row(ref_row, txn, jsonrpc);
            }
        }
    }
}


static void
update_remote_row(const struct ovsdb_row *row, struct ovsdb_txn *txn,
                  const struct ovsdb_jsonrpc_server *jsonrpc)
{
    struct ovsdb_jsonrpc_remote_status status;
    struct ovsdb_row *rw_row;
    const char *target;
    char *keys[9], *values[9];
    size_t n = 0;

    /* Get the "target" (protocol/host/port) spec. */
    if (!ovsdb_util_read_string_column(row, "target", &target)) {
        /* Bad remote spec or incorrect schema. */
        return;
    }
    rw_row = ovsdb_txn_row_modify(txn, row);
    ovsdb_jsonrpc_server_get_remote_status(jsonrpc, target, &status);

    /* Update status information columns. */
    ovsdb_util_write_bool_column(rw_row, "is_connected", status.is_connected);

    if (status.state) {
        keys[n] = xstrdup("state");
        values[n++] = xstrdup(status.state);
    }
    if (status.sec_since_connect != UINT_MAX) {
        keys[n] = xstrdup("sec_since_connect");
        values[n++] = xasprintf("%u", status.sec_since_connect);
    }
    if (status.sec_since_disconnect != UINT_MAX) {
        keys[n] = xstrdup("sec_since_disconnect");
        values[n++] = xasprintf("%u", status.sec_since_disconnect);
    }
    if (status.last_error) {
        keys[n] = xstrdup("last_error");
        values[n++] =
            xstrdup(ovs_retval_to_string(status.last_error));
    }
    if (status.locks_held && status.locks_held[0]) {
        keys[n] = xstrdup("locks_held");
        values[n++] = xstrdup(status.locks_held);
    }
    if (status.locks_waiting && status.locks_waiting[0]) {
        keys[n] = xstrdup("locks_waiting");
        values[n++] = xstrdup(status.locks_waiting);
    }
    if (status.locks_lost && status.locks_lost[0]) {
        keys[n] = xstrdup("locks_lost");
        values[n++] = xstrdup(status.locks_lost);
    }
    if (status.n_connections > 1) {
        keys[n] = xstrdup("n_connections");
        values[n++] = xasprintf("%d", status.n_connections);
    }
    if (status.bound_port != htons(0)) {
        keys[n] = xstrdup("bound_port");
        values[n++] = xasprintf("%"PRIu16, ntohs(status.bound_port));
    }
    ovsdb_util_write_string_string_column(rw_row, "status", keys, values, n);

    ovsdb_jsonrpc_server_free_remote_status(&status);
}

static void
commit_txn(DB_FUNCTION_TABLE *pDbFnTable, PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_txn *txn, const char *name)
{
    struct ovsdb_error *error = ovsdb_txn_propose_commit_block(pDbFnTable,
        pContext, txn, false);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        char *msg = ovsdb_error_to_string_free(error);
        VLOG_ERR_RL(&rl, "Failed to update %s: %s", name, msg);
        free(msg);
    }
}

/* Updates 'row', a row in the _Server database's Database table, to match
 * 'db'. */
static void
update_database_status(struct ovsdb_row *row, struct db *db)
{
    ovsdb_util_write_string_column(row, "name", db->db->name);
    ovsdb_util_write_string_column(row, "model",
                                   ovsdb_storage_get_model(db->db->storage));
    ovsdb_util_write_bool_column(row, "connected",
                                 ovsdb_storage_is_connected(db->db->storage));
    ovsdb_util_write_bool_column(row, "leader",
                                 ovsdb_storage_is_leader(db->db->storage));
    ovsdb_util_write_uuid_column(row, "cid",
                                 ovsdb_storage_get_cid(db->db->storage));
    ovsdb_util_write_uuid_column(row, "sid",
                                 ovsdb_storage_get_sid(db->db->storage));

    uint64_t index = ovsdb_storage_get_applied_index(db->db->storage);
    if (index) {
        ovsdb_util_write_integer_column(row, "index", index);
    } else {
        ovsdb_util_clear_column(row, "index");
    }

    const struct uuid *row_uuid = ovsdb_row_get_uuid(row);
    if (!uuid_equals(row_uuid, &db->row_uuid)) {
        db->row_uuid = *row_uuid;

        /* The schema can only change if the row UUID changes, so only update
         * it in that case.  Presumably, this is worth optimizing because
         * schemas are often kilobytes in size and nontrivial to serialize. */
        char *schema = NULL;
        if (db->db->schema) {
            struct json *json_schema = ovsdb_schema_to_json(db->db->schema);
            schema = json_to_string(json_schema, JSSF_SORT);
            json_destroy(json_schema);
        }
        ovsdb_util_write_string_column(row, "schema", schema);
        free(schema);
    }
}

/* Updates the Database table in the _Server database. */
static void
update_server_status(DB_FUNCTION_TABLE *pDbFnTable,
    PDB_INTERFACE_CONTEXT_T pContext, struct shash *all_dbs)
{
    struct db *server_db = shash_find_data(all_dbs, "_Server");
    struct ovsdb_table *database_table = shash_find_data(
        &server_db->db->tables, "Database");
    struct ovsdb_txn *txn = ovsdb_txn_create(server_db->db);

    /* Update rows for databases that still exist.
     * Delete rows for databases that no longer exist. */
    const struct ovsdb_row *row, *next_row;
    HMAP_FOR_EACH_SAFE (row, next_row, hmap_node, &database_table->rows) {
        const char *name;
        ovsdb_util_read_string_column(row, "name", &name);
        struct db *db = shash_find_data(all_dbs, name);
        if (!db || !db->db) {
            ovsdb_txn_row_delete(txn, row);
        } else {
            update_database_status(ovsdb_txn_row_modify(txn, row), db);
        }
    }

    /* Add rows for new databases.
     *
     * This is O(n**2) but usually there are only 2 or 3 databases. */
    struct shash_node *node;
    SHASH_FOR_EACH (node, all_dbs) {
        struct db *db = node->data;

        if (!db->db) {
            continue;
        }

        HMAP_FOR_EACH (row, hmap_node, &database_table->rows) {
            const char *name;
            ovsdb_util_read_string_column(row, "name", &name);
            if (!strcmp(name, node->name)) {
                goto next;
            }
        }

        /* Add row. */
        struct ovsdb_row *new_row = ovsdb_row_create(database_table);
        uuid_generate(ovsdb_row_get_uuid_rw(new_row));
        update_database_status(new_row, db);
        ovsdb_txn_row_insert(txn, new_row);

    next:;
    }

    commit_txn(pDbFnTable, pContext, txn, "_Server");
}
