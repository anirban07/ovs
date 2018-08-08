#ifndef LDAP_PROVIDER_H
#define LDAP_PROVIDER_H

#include <ctype.h>
#include <ldap.h>
#include <sasl/sasl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>


#include "ovsdb.h"
#include "ovsdb-intf.h"
#include "openvswitch/json.h"
#include "transaction.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "jsonrpc-server.h"
#include "monitor.h"

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
ldap_open_context(DB_INTERFACE_CONTEXT_T **ppContext, ...);

uint32_t
ldap_close_context(DB_INTERFACE_CONTEXT_T *pContext);

struct ovsdb_txn *
ldap_execute_compose_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
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

bool ldap_txn_progress_is_complete_intf(PDB_INTERFACE_CONTEXT_T pContext,
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

#endif /* LDAP_PROVIDER_H */
