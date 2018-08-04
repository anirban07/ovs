#include <config.h> // every C source file must include this

#include "ovsdb-provider.h"

uint32_t
ovsdb_open_context(DB_INTERFACE_CONTEXT_T **ppContext, ...)
{
    va_list argList = { 0 };
    DB_INTERFACE_CONTEXT_T *pContext = NULL;

    pContext = xzalloc(sizeof *pContext);

    va_start(argList, ppContext);
    pContext->db = va_arg(argList, struct ovsdb *);
    pContext->session = va_arg(argList, struct ovsdb_session *);
    pContext->read_only = va_arg(argList, int);
    va_end(argList);

    *ppContext = pContext;

    return 0;
}

uint32_t
ovsdb_close_context(DB_INTERFACE_CONTEXT_T *pContext)
{
    if (pContext) {
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

struct ovsdb_txn * ovsdb_execute_compose_intf(
    PDB_INTERFACE_CONTEXT_T pContext, const struct json *params,
    const char *role, const char *id, long long int elapsed_msec,
    long long int *timeout_msec, bool *durable, struct json **resultsp)
{
    return ovsdb_execute_compose(
        pContext->db, pContext->session, params, pContext->read_only, role, id,
        elapsed_msec, timeout_msec, durable, resultsp
    );
}

struct ovsdb_txn_progress *ovsdb_txn_propose_commit_intf(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED, struct ovsdb_txn *txn,
    bool durable)
{
    return ovsdb_txn_propose_commit(txn, durable);
}

bool ovsdb_txn_progress_is_complete_intf(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    const struct ovsdb_txn_progress *p)
{
    return ovsdb_txn_progress_is_complete(p);
}
