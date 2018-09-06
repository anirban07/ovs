/**
 * @file ovsdb-intf.h
 *
 * @brief Interface for OVSDB Management Protocol Interface
 *
 * @date July 24, 2018
 * @author Prasoon Telang <telangp@vmware.com>
 */

#ifndef OVSDB_INTF_H_
#define OVSDB_INTF_H_

// #define JSON_RPC_DEBUG

#include "openvswitch/json.h"

enum ovsdb_monitor_version;
struct ovsdb;
struct ovsdb_jsonrpc_session;
struct ovsdb_session;
enum ovsdb_lock_mode;

/**
 * @brief structure object that contains the backend specific structure. This
 * could be the database session information for example, or anything that is
 * very specific to the backend and not generic.
 */
typedef struct _DB_INTERFACE_CONTEXT_T * PDB_INTERFACE_CONTEXT_T;

/**
 * @brief load the context using the provider specified.
 *
 * @param[out] ppContext pointer that receives the pointer to the context.
 *
 * @return 0 for success, non-zero for error
 */
typedef uint32_t (*PFN_DB_OPEN_CONTEXT) (
    PDB_INTERFACE_CONTEXT_T * ppContext,
    ...
);

/**
 * @brief interface for ovsdb_execute_compose where state changes from client
 * are persisted into the database.
 *
 * @param [in] pContext pointer to the context
 * @param [in] params pointer to the parameters passed by wire protocol in JSON
 * @param [in] role used for determing the role of the client for RBAC
 * @param [in] id ID of the client
 * @param [in] elapsed_msec used during "wait" to indicate the number of
 *      milliseconds passed
 * @param [in] timeout_msec the time at which the transaction will timeout
 * @param [in] durable if set to true, the response is generated only when the
 *      changes made by transaction is persisted.
 * @param [out] resultsp if nonnull, it is the results to return to the client.
 *      if resultsp is NULL, then the execution failed.
 *
 * @return ovsdb_txn object that has the DB, list of tables involved in this
 * transaction, and each table has a list of rows involved and so on
 */
typedef struct ovsdb_txn * (*PFN_DB_EXECUTE_COMPOSE)(
    PDB_INTERFACE_CONTEXT_T pContext,
    const struct json *params,
    const char *role,
    const char *id,
    long long int elapsed_msec,
    long long int *timeout_msec,
    bool *durable,
    struct json **resultsp
);

/**
 * @brief interface for ovsdb_txn_propose_commit
 * it returns a transaction progress object and the implementation must update
 * as per following conditions. If 'error' is nonnull, the transaction is
 * complete, with the given error as the result. Otherwise, if 'write' is
 * nonnull, then the transaction is waiting for 'write' to complete. Otherwise,
 * if 'commit_index' is nonzero, then the transaction is waiting for
 * 'commit_index' to be applied to the storage. Otherwise, the transaction is
 * complete and successful.
 *
 * @param [in] pContext pointer to the context
 * @param [in] txn transaction object used to track transaction changes
 * @param [in] durable indicate if the commit should be made asynchronously
 *
 * @return ovsdb_txn_progress object to indicate the progress of the transaction
 */
typedef struct ovsdb_txn_progress * (*PFN_DB_TXN_PROPOSE_COMMIT)(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_txn *txn,
    bool durable
);

/**
 * @brief check if the transaction progress has been completed. The implementation
 * should update the write / error member of the ovsdb_txn_progress struct
 * to indicate the progress of the transaction.
 * TODO determine the transaction steps and format of log
 */
typedef bool (*PFN_DB_TXN_PROGRESS_IS_COMPLETE) (
    PDB_INTERFACE_CONTEXT_T pContext,
    const struct ovsdb_txn_progress *progress
);

/**
 * @brief destroy the transaction progress and any implementation specific
 * objects.
 */
typedef void (*PFN_DB_TXN_PROGRESS_DESTROY) (
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_txn_progress
);

/*
 * The following are not needed for POC, but for future
 */

/**
 * @brief This for "monitor" action as per RFC 7047 for replicating table or a
 * subset of table in the OVSDB. The response must match the fields described
 * in RFC 7047 for "Monitor"
 */
typedef struct jsonrpc_msg * (*PFN_DB_MONITOR_CREATE)(
    PDB_INTERFACE_CONTEXT_T pContext,

    /*
     * JSON object of the parameters passed by the wire protocol (RFC 7047).
     */
    struct json *params,

    /*
     * version number of the OVSDB monitor (OVSDB_MONITOR_V1 or
     * OVSDB_MONITOR_V2)
     */
    enum ovsdb_monitor_version version,

    /*
     * JSON object to track the request ID
     */
    struct json *id
);

/**
 * @brief using the request ID, update the condition for the monitor used by
 * that. The response must match the fields described in RFC 7047
 */
typedef struct jsonrpc_msg * (*PFN_DB_MONITOR_COND_CHANGE)(
    PDB_INTERFACE_CONTEXT_T pContext,

    /*
     * JSON object of the parameters passed by the wire protocol (RFC 7047).
     */
    struct json *params,

    /*
     * JSON object to track the request ID
     */
    struct json *id
);

/**
 * @brief This request cancels a previously issued monitor request.
 * The response must match the fields described in RFC 7047 "monitor_cancel"
 */
typedef struct jsonrpc_msg * (*PFN_DB_MONITOR_CANCEL) (
    PDB_INTERFACE_CONTEXT_T pContext,

    /*
     * JSON object of the parameters passed by the wire protocol (RFC 7047).
     */
    struct json_array *params,

    /*
     * JSON object to track the request ID
     */
    struct json *id
);

/**
 * @brief This request should be responded by the implementing backend
 */
typedef struct jsonrpc_msg * (*PFN_DB_ECHO) (
    PDB_INTERFACE_CONTEXT_T pContext,
    /*
     * arguments from the client which should be responded as is by the plugged
     * backend implementation
     */
    const struct json *params,

    /*
     * JSON object to track the request ID
     */
     struct json *id
);

/**
 * @brief retrives database schema that describes the hosted database
 * TODO it should take no args, the current implementation uses db->schema
 */
typedef struct json * (*PFN_DB_GET_SCHEMA) (
    PDB_INTERFACE_CONTEXT_T pContext

);

/**
 * @brief The OVSDB only ensures that it grants only one client with the lock.
 * The clients need to decide on the lock's name among themselves to ensure
 * concurrency. If the database is in read-only, or the same client issues a
 * lock request without unlocking - error out.
 * Attempts to acquire the lock named 'lock_name' for 'session' within
 * 'server'.  Returns the new lock waiter.
 *
 * If 'mode' is OVSDB_LOCK_STEAL, then the new lock waiter is always the owner
 * of the lock.  '*victimp' receives the session of the previous owner or NULL
 * if the lock was previously unowned.  (If the victim itself originally
 * obtained the lock through a "steal" operation, then this function also
 * removes the victim from the lock's waiting list.)
 *
 * If 'mode' is OVSDB_LOCK_WAIT, then the new lock waiter is the owner of the
 * lock only if this lock had no existing owner.  '*victimp' is set to NULL.
 */
typedef struct jsonrpc_msg * (*PFN_DB_SESSION_LOCK) (
    PDB_INTERFACE_CONTEXT_T pContext,
    /*
     * a structure containing ovsdb_session, db_change_aware to enable tracking
     * of changes in the DB, triggers, monitors, and read-only status.
     */
    struct ovsdb_jsonrpc_session *session,

    /*
     * The request message sent from the client.
     */
    struct jsonrpc_msg *request,

    /*
     * Lock modes: OVSDB_LOCK_WAIT and OVSDB_LOCK_STEAL.
     */
    enum ovsdb_lock_mode mode
);

/**
 * @brief If client owns the lock, this operation releases it. If client has
 * requested for a lock, this cancels it. More details in RFC 7047
 */
typedef struct jsonrpc_msg * (*PFN_DB_SESSION_UNLOCK) (
    PDB_INTERFACE_CONTEXT_T pContext,
    /*
     * a structure containing ovsdb_session, db_change_aware to enable tracking
     * of changes in the DB, triggers, monitors, and read-only status.
     */
    struct ovsdb_jsonrpc_session *session,

    /*
     * The request message sent from the client.
     */
    struct jsonrpc_msg *request
);

/**
 * @brief List all the DB names known to the backend storage
 */
typedef struct jsonrpc_msg * (*PFN_DB_LIST_DBS) (
    PDB_INTERFACE_CONTEXT_T pContext
    // no args
);

/**
 * @brief Set DB's state to be change aware
 *
 * @param pContext pointer to the context
 * @param change_aware boolean argument to imply if it is change aware or not
 */
 typedef struct jsonrpc_msg * (*PFN_DB_SET_CHANGE_AWARE) (
    PDB_INTERFACE_CONTEXT_T pContext,
    bool change_aware
    // no args
 );

 /**
  * @brief DB_CONVERT - for patching/updating the backend storage metadata
  */
typedef void (*PFN_DB_CONVERT) (
    PDB_INTERFACE_CONTEXT_T pContext
    // args to be decided
);


typedef uint32_t (*PFN_DB_CLOSE_CONTEXT) (
    PDB_INTERFACE_CONTEXT_T pContext
);

/**
 * @brief function table to implement OVSDB Mgmt Protocol's storage
 */
typedef struct __DB_FUNCTION_TABLE
{
    /** @brief to gather the context required by the backend */
    PFN_DB_OPEN_CONTEXT pfn_db_open_context;
    /** @brief to compose a set of DB operations to perform on storage */
    PFN_DB_EXECUTE_COMPOSE pfn_db_execute_compose;
    /** @brief to transition transaction to "commit" phase */
    PFN_DB_TXN_PROPOSE_COMMIT pfn_db_txn_propose_commit;
    /** @brief to indicate transaction progress is complete */
    PFN_DB_TXN_PROGRESS_IS_COMPLETE pfn_db_txn_progress_is_complete;
    /** @brief to create a monitoring condition for replication */
    PFN_DB_MONITOR_CREATE pfn_db_monitor_create;
    /** @brief to change the monitoring condition for replication */
    PFN_DB_MONITOR_COND_CHANGE pfn_db_monitor_cond_change;
    /** @brief to delete the monitoring condition */
    PFN_DB_MONITOR_CANCEL pfn_db_monitor_cancel;
    /** @brief to indicate the backend implementation is responsive */
    PFN_DB_ECHO pfn_db_echo;
    /** @brief to destroy the transaction progress */
    PFN_DB_TXN_PROGRESS_DESTROY pfn_db_txn_progress_destroy;
    /** @brief to get the schema for a given DB */
    PFN_DB_GET_SCHEMA pfn_db_get_schema;
    /** @brief to get a lock on the OVSDB for transaction */
    PFN_DB_SESSION_LOCK pfn_db_session_lock;
    /** @brief to unlock the OVSDB for transaction */
    PFN_DB_SESSION_UNLOCK pfn_db_session_unlock;
    /** @brief list all the DBs known to the backend */
    PFN_DB_LIST_DBS pfn_db_list_dbs;
    /** @brief set the DB's state to be change aware */
    PFN_DB_SET_CHANGE_AWARE pfn_db_set_change_aware;
    /** @brief to patch and update the database metadata */
    PFN_DB_CONVERT pfn_db_convert;
    /** @brief to destroy the context required by the backend */
    PFN_DB_CLOSE_CONTEXT pfn_db_close_context;
} DB_FUNCTION_TABLE;


uint32_t
db_provider_init(DB_FUNCTION_TABLE **ppOvsdbFnTable);

void
db_provider_shutdown(DB_FUNCTION_TABLE *pOvsdbFnTable);

#endif /* OVSDB_INTF_H_ */
