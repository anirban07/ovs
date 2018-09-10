#ifndef LDAP_PROVIDER_H
#define LDAP_PROVIDER_H

#include <ctype.h>
#include <ldap.h>
#include <sasl/sasl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>


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
#include "ovsdb-parser.h"
#include "perf-counter.h"
#include "uuid.h"

struct db {
    char *filename;
    struct ovsdb *db;
    struct uuid row_uuid;
};

#define OVS_SAFE_FREE_STRING(pStr) \
        if ((pStr)) { \
            OvsFreeString(pStr); \
            (pStr) = NULL; \
        }

#define BAIL_ON_ERROR(err) \
            if ((err) != 0) { \
                fprintf( \
                        stderr, \
                        "(%d) at %s:%d", \
                        err, \
                        __FILE__, \
                        __LINE__ \
                ); \
                goto error; \
            }



#define LDAP_PORT 389

#define ERROR_OVS_NOT_ENOUGH_MEMORY   800008
#define ERROR_OVS_INVALID_CONFIG      800009
#define ERROR_OVS_INVALID_PARAMETER   800019
#define ERROR_OVS_VSNPRINTF_FAILED    800048

#define DEFAULT_NAMING_CONTEXT "defaultNamingContext"

#define LDAP_SERVER "192.168.114.3"
#define LDAP_USER "administrator@lightwave.local"
#define LDAP_PASSWORD "Admin!23"

typedef struct _ovs_ldap_context_t {
    LDAP *pLd;
    char *pBaseDn;
} ovs_ldap_context_t;

typedef struct _ovs_sasl_creds_t {
    const char *realm;
    const char *authname;
    const char *user;
    const char *passwd;
} ovs_sasl_creds_t;

typedef struct _DB_INTERFACE_CONTEXT_T {
    ovs_ldap_context_t *ldap_conn;
    ovs_sasl_creds_t *sasl_creds;

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
    struct server_config *server_cfg;
    bool *exiting;
} DB_INTERFACE_CONTEXT_T;

void
OvsFreeConnection(
    ovs_ldap_context_t* pConnection
);

uint32_t
OvsCreateConnection(
    const char* pszServer,
    const char* pszUser,
    const char* pszPassword,
    ovs_ldap_context_t ** ppConnection
);

/** Frees a string that was allocated using OvsAllocateString
 * @param pString Pointer to string which must be freed.
 */
void
OvsFreeString(
    char* pString
);

/** Frees a contiguous block of memory that was allocated using OvsAllocateMemory.
 * @param pMemory Pointer to block of memory that must be freed.
 *        if pMemory is NULL, this function will not do any operations.
 */
void
OvsFreeMemory(
    void* pMemory
);

/** Allocates a string matching the input string
 * @param pSourceStr Pointer to valid source string.
 *                   This string may not be NULL.
 *                   This string may be empty.
 *                   This string is expected to be null terminated.
 * @param ppTargetStr Pointer that receives the pointer to the allocated string.
 *                    This pointer may not be NULL.
 * @return 0 if a copy of the input string was successfully allocated.
 *         ERROR_OVS_INVALID_PARAMETER if invalid parameters were passed.
 *         ERROR_OVS_NOT_ENOUGH_MEMORY if enough memory was not available.
 */
uint32_t
OvsAllocateString(
    char**      ppTargetStr,
    const char* pSourceStr
);

/** Allocates a string using the format specified
 * @param ppTarget Pointer that receives the pointer to the allocated string.
 *                 The pointer is expected to be NULL.
 * @param pFormat Pointer to the format of the string.
 *                The pointer should not be NULL.
 * @return 0 if the source data was present and formatted successfully in a
 *           destination location.
 *         ERROR_OVS_INVALID_PARAMETER if invalid parameters were passed.
 *         ERROR_OVS_VSNPRINTF_FAILED if it failed to format the string.
 *         ERROR_OVS_NOT_ENOUGH_MEMORY if enough memory was not available.
 */
uint32_t
OvsAllocateStringPrintf(
    char **ppTarget,
    const char *pFormat,
    ...
);

/**
 * Allocates a contiguous block of memory matching the requested size.
 * @param size     The size of memory requested. This value must be greater
 *                 than 0.
 * @param ppMemory A pointer that receives the pointer to the allocated
 *                 memory block.
 * @return 0 if memory was allocated successfully.
 *         ERROR_OVS_INVALID_PARAMETER if invalid parameters were passed.
 *         ERROR_OVS_NOT_ENOUGH_MEMORY if enough memory was not available.
 */
uint32_t
OvsAllocateMemory(
    void** ppMemory,
    size_t size
);

uint32_t
GetDSERootAttribute(
    LDAP* pLd,
    char* pszAttribute,
    char** ppAttrValue
);


uint32_t
ldap_open_context(DB_INTERFACE_CONTEXT_T **ppContext, int argc, ...);

uint32_t
ldap_close_context(DB_INTERFACE_CONTEXT_T *pContext);

struct ovsdb_txn *
ldap_execute_compose_intf(
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
ldap_txn_propose_commit_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_txn *txn,
    bool durable
);

bool
ldap_txn_progress_is_complete_intf(PDB_INTERFACE_CONTEXT_T pContext,
    const struct ovsdb_txn_progress *p);


struct jsonrpc_msg *
ldap_monitor_create_intf(PDB_INTERFACE_CONTEXT_T pContext,
    struct json *params, enum ovsdb_monitor_version version, struct json *id);

struct jsonrpc_msg *
ldap_monitor_cond_change_intf(PDB_INTERFACE_CONTEXT_T pContext,
    struct json *params, struct json *id);

struct jsonrpc_msg *
ldap_monitor_cancel_intf(PDB_INTERFACE_CONTEXT_T pContext,
    struct json_array *params, struct json *id);

uint32_t
ldap_initialize_state_intf(
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
ldap_setup_ssl_configuration_intf(
    char *private_key_file,
    char *certificate_file,
    char *ca_cert_file,
    char *ssl_protocols,
    char *ssl_ciphers,
    bool bootstrap_ca_cert
);

uint32_t
ldap_unixctl_cmd_register_intf(
    PDB_INTERFACE_CONTEXT_T pContext
);

uint32_t
ldap_memory_usage_report_intf(
    PDB_INTERFACE_CONTEXT_T pContext
);

uint32_t
ldap_process_rpc_requests_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    DB_FUNCTION_TABLE *pDbFnTable
);

uint32_t
ldap_update_servers_and_wait_intf(
    DB_FUNCTION_TABLE *pDbFnTable,
    PDB_INTERFACE_CONTEXT_T pContext,
    struct unixctl_server *unixctl,
    struct process *run_process
);

uint32_t
ldap_terminate_state_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct sset *db_filenames
);

uint32_t
ldap_add_session_to_context_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_jsonrpc_session *s,
    struct jsonrpc_msg *request,
    bool monitor_cond_enable__,
    struct jsonrpc_msg **reply
);

uint32_t
ldap_create_trigger_intf(
    DB_FUNCTION_TABLE *pDbFnTable,
    PDB_INTERFACE_CONTEXT_T pContext,
    struct jsonrpc_msg *request
);

uint32_t
ldap_add_db_to_context_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb *ovsdb
);

/** Following functions are useful for implementing data operations on DNs */
typedef uint32_t FN_LDAP_OPERATION (
    PDB_INTERFACE_CONTEXT_T,
    struct ovsdb_parser *,
    struct json *
);

typedef struct __LDAP_FUNCTION_TABLE
{
    FN_LDAP_OPERATION *pfn_ldap_insert;
    FN_LDAP_OPERATION *pfn_ldap_select;
    FN_LDAP_OPERATION *pfn_ldap_delete;
    FN_LDAP_OPERATION *pfn_ldap_update;
} LDAP_FUNCTION_TABLE;

typedef LDAP_FUNCTION_TABLE LDAP_FUNCTION_TABLE_INIT (void);

#endif /* LDAP_PROVIDER_H */
