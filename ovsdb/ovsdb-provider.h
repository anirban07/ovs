#ifndef OVSDB_PROVIDER_H
#define OVSDB_PROVIDER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>

#include "column.h"
#include "file.h"
#include "jsonrpc.h"
#include "jsonrpc-server.h"
#include "memory.h"
#include "ovsdb.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "ovsdb-intf.h"
#include "ovsdb-types.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/vlog.h"
#include "row.h"
#include "ovsdb-util.h"
#include "replication.h"
#include "simap.h"
#include "socket-util.h"
#include "storage.h"
#include "stream-ssl.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "trigger.h"
#include "util.h"
#include "unixctl.h"
#include "jsonrpc-server.h"
#include "monitor.h"
#include "perf-counter.h"
#include "uuid.h"

struct db {
    char *filename;
    struct ovsdb *db;
    struct uuid row_uuid;
};

typedef struct _DB_INTERFACE_CONTEXT_T {
    /**
     * @brief the OVSDB implementation of the database that contains the tables,
     * rows, data of the storage.
     */
    struct ovsdb *db;
    /**
     * @brief a structure of ovsdb_servers which are a map of DB names to DB
     * objects, locks in use in the servers, uuid of the server, list of
     * completed triggers, and map of waiters by lock name
     */
    struct ovsdb_session *session;
    /** @brief if the state of the database is read only */
    bool read_only;
    /** @brief session maintained by the JSONRPC server */
    struct ovsdb_jsonrpc_session *jsonrpc_session;
    /** @brief store the server config */
    struct server_config *server_cfg;
    /** @brief to indicate if the service is exiting */
    bool *exiting;
} DB_INTERFACE_CONTEXT_T;

uint32_t
ovsdb_open_context(DB_INTERFACE_CONTEXT_T **ppContext, int argc, ...);

uint32_t
ovsdb_close_context(DB_INTERFACE_CONTEXT_T *pContext);

struct ovsdb_txn *
ovsdb_execute_compose_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    bool read_only,
    const struct json *params,
    const char *role,
    const char *id,
    long long int elapsed_msec,
    long long int *timeout_msec,
    bool *durable,
    struct json **resultsp
);

struct ovsdb_txn_progress *
ovsdb_txn_propose_commit_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_txn *txn,
    bool durable
);

bool
ovsdb_txn_progress_is_complete_intf(PDB_INTERFACE_CONTEXT_T pContext,
    const struct ovsdb_txn_progress *p);

struct jsonrpc_msg *
ovsdb_monitor_create_intf(PDB_INTERFACE_CONTEXT_T pContext,
    struct json *params, enum ovsdb_monitor_version version, struct json *id);

struct jsonrpc_msg *
ovsdb_monitor_cond_change_intf(PDB_INTERFACE_CONTEXT_T pContext,
    struct json *params, struct json *id);

struct jsonrpc_msg *
ovsdb_monitor_cancel_intf(PDB_INTERFACE_CONTEXT_T pContext,
    struct json_array *params, struct json *id);

uint32_t
ovsdb_initialize_state_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct sset *remotes,
    FILE *config_tmpfile,
    struct shash *all_dbs,
    struct ovsdb_jsonrpc_server *jsonrpc,
    char **sync_from,
    char **sync_exclude,
    bool *is_backup,
    struct sset *db_filenames,
    bool *exiting,
    struct server_config *server_cfg
);

uint32_t
ovsdb_setup_ssl_configuration_intf(
    char *private_key_file,
    char *certificate_file,
    char *ca_cert_file,
    char *ssl_protocols,
    char *ssl_ciphers,
    bool bootstrap_ca_cert
);

uint32_t
ovsdb_unixctl_cmd_register_intf(
    PDB_INTERFACE_CONTEXT_T pContext
);

uint32_t
ovsdb_memory_usage_report_intf(
    PDB_INTERFACE_CONTEXT_T pContext
);

uint32_t
ovsdb_process_rpc_requests_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    DB_FUNCTION_TABLE *pDbFnTable
);

uint32_t
ovsdb_update_servers_and_wait_intf(
    DB_FUNCTION_TABLE *pDbFnTable,
    PDB_INTERFACE_CONTEXT_T pContext,
    struct unixctl_server *unixctl,
    struct process *run_process
);

uint32_t
ovsdb_terminate_state_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct sset *db_filenames
);

uint32_t
ovsdb_add_session_to_context_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_jsonrpc_session *s,
    struct jsonrpc_msg *request,
    bool monitor_cond_enable__,
    struct jsonrpc_msg **reply
);

uint32_t
ovsdb_create_trigger_intf(
    DB_FUNCTION_TABLE *pDbFnTable,
    PDB_INTERFACE_CONTEXT_T pContext,
    struct jsonrpc_msg *request
);

uint32_t
ovsdb_add_db_to_context_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb *ovsdb
);
#endif /* OVSDB_PROVIDER_H */
