#include <config.h> // every C source file must include this
#include <sys/stat.h>

#include "ldap-provider.h"
#include "ovsdb-error.h"
#include "ovsdb-data.h"
#include <sys/time.h>

VLOG_DEFINE_THIS_MODULE(ldap_provider)

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

static
int
OvsSASLInteraction (
    LDAP *      pLd OVS_UNUSED,
    unsigned    flags OVS_UNUSED,
    void *      pDefaults,
    void *      pIn
    )
{
    sasl_interact_t* pInteract = (sasl_interact_t*)pIn;
    ovs_sasl_creds_t * pDef = (ovs_sasl_creds_t *)pDefaults;

    while( (pDef != NULL) && (pInteract->id != SASL_CB_LIST_END) )
    {
        switch( pInteract->id )
        {
        case SASL_CB_GETREALM:
                pInteract->defresult = pDef->realm;
                break;
        case SASL_CB_AUTHNAME:
                pInteract->defresult = pDef->authname;
                break;
        case SASL_CB_PASS:
                pInteract->defresult = pDef->passwd;
                break;
        case SASL_CB_USER:
                pInteract->defresult = pDef->user;
                break;
        default:
                break;
        }

        pInteract->result = (pInteract->defresult) ? pInteract->defresult : "";
        pInteract->len    = (unsigned long)strlen( (const char *)pInteract->result );

        pInteract++;
    }

    return LDAP_SUCCESS;
}

void
OvsFreeConnection(
    ovs_ldap_context_t* pConnection
    )
{
    if (pConnection) {
        if (pConnection->pLd) {
            ldap_unbind_ext(pConnection->pLd, NULL, NULL);
        }
        OVS_SAFE_FREE_STRING(pConnection->pBaseDn);
        OvsFreeMemory(pConnection);
    }
}

uint32_t
GetDSERootAttribute(
    LDAP* pLd,
    char* pszAttribute,
    char** ppAttrValue
    )
{
    uint32_t error = 0; // LDAP_SUCCESS
    char* pDcFilter = "(objectClass=*)";
    char* pDcAttr[] = { pszAttribute, NULL };
    char* pAttribute = NULL;
    char* pAttrValue = NULL;
    BerElement* pBer = NULL;
    BerValue** ppValue = NULL;
    LDAPMessage* pSearchResult = NULL;
    LDAPMessage* pResults = NULL;

    error = ldap_search_ext_s(
        pLd,
        "",
        LDAP_SCOPE_BASE,
        pDcFilter,
        pDcAttr,
        0,
        NULL,
        NULL,
        NULL,
        0,
        &pSearchResult);

    BAIL_ON_ERROR(error);

    if (ldap_count_entries(pLd, pSearchResult) != 1) {
        error = ERROR_OVS_INVALID_CONFIG;
        BAIL_ON_ERROR(error);
    }

    pResults = ldap_first_entry(pLd, pSearchResult);
    if (pResults == NULL) {
        ldap_get_option(pLd, LDAP_OPT_ERROR_NUMBER, &error);
        BAIL_ON_ERROR(error);
    }

    pAttribute = ldap_first_attribute(pLd, pResults, &pBer);
    if (pAttribute == NULL)
    {
        ldap_get_option(pLd, LDAP_OPT_ERROR_NUMBER, &error);
        BAIL_ON_ERROR(error);
    }

    ppValue = ldap_get_values_len(pLd, pResults, pAttribute);
    if (ppValue == NULL) {
        ldap_get_option(pLd, LDAP_OPT_ERROR_NUMBER, &error);
        BAIL_ON_ERROR(error);
    }

    error = OvsAllocateString(&pAttrValue, ppValue[0]->bv_val);
    BAIL_ON_ERROR(error);

    *ppAttrValue = pAttrValue;

cleanup:

    if (ppValue != NULL)
    {
        ldap_value_free_len(ppValue);
    }
    if (pAttribute != NULL)
    {
        ldap_memfree(pAttribute);
    }
    if (pBer != NULL)
    {
        ber_free(pBer, 0);
    }
    if (pSearchResult != NULL)
    {
        ldap_msgfree(pSearchResult);
    }

    return error;

error:

    goto cleanup;
}

uint32_t
OvsAllocateString(
    char**      ppTargetStr,
    const char* pSourceStr
    )
{
    uint32_t error = 0;
    size_t len = 0;
    char* pTargetStr = NULL;

    if (!pSourceStr)  {
        error = ERROR_OVS_INVALID_PARAMETER;
        BAIL_ON_ERROR(error);
    }

    len = strlen(pSourceStr);

    error = OvsAllocateMemory((void**)&pTargetStr, len+1);
    BAIL_ON_ERROR(error);

    if (len > 0) {
        strncpy(pTargetStr, pSourceStr, len);
    }

    *ppTargetStr = pTargetStr;

error:

    return error;
}

void
OvsFreeString(
    char* pString
    )
{
    if (pString) {
        OvsFreeMemory(pString);
    }
}

uint32_t
OvsAllocateStringPrintf(
    char **ppTarget,
    const char *pFormat,
    ...
) {
    uint32_t error = 0;
    char tmp[1] = "";
    int bytes = 0;
    va_list argList = {0};
    va_list* pArgList = NULL;
    char* pTarget = NULL;

    if (!ppTarget || !pFormat) {
        error = ERROR_OVS_INVALID_PARAMETER;
        BAIL_ON_ERROR(error);
    }

    va_start(argList, pFormat);
    pArgList = &argList;
    bytes = vsnprintf(tmp, sizeof(tmp), pFormat, argList);
    va_end(argList);
    pArgList = NULL;

    if (bytes < 0) {
        error = ERROR_OVS_VSNPRINTF_FAILED;
        BAIL_ON_ERROR(error);
    }

    bytes++; // for terminating null

    va_start(argList, pFormat);
    pArgList = &argList;

    error = OvsAllocateMemory((void **)&pTarget, bytes);
    BAIL_ON_ERROR(error);

    if (vsnprintf(pTarget, bytes, pFormat, argList) < 0) {
        error = ERROR_OVS_VSNPRINTF_FAILED;
        BAIL_ON_ERROR(error);
    }

    *ppTarget = pTarget;

cleanup:
    if (pArgList) {
      va_end(argList);
    }
    return error;

error:
    OVS_SAFE_FREE_STRING(pTarget);

    goto cleanup;
}

uint32_t
OvsAllocateMemory(
    void** ppMemory,
    size_t size
    )
{
    uint32_t error = 0;
    void* pMemory = NULL;

    if (!ppMemory || size <= 0) {
        error = ERROR_OVS_INVALID_PARAMETER;
        BAIL_ON_ERROR(error);
    }

    pMemory = calloc(size, sizeof(uint8_t));
    if (!pMemory) {
        error = ERROR_OVS_NOT_ENOUGH_MEMORY;
        BAIL_ON_ERROR(error);
    }

    *ppMemory = pMemory;

error:

    return error;
}

void
OvsFreeMemory(
    void* pMemory
    )
{
    if (pMemory) {
        free(pMemory);
    }
}


/**
 * Create a connection with LDAP server
 */
uint32_t
OvsCreateConnection(
    const char* pszServer,
    const char* pszUser,
    const char* pszPassword,
    ovs_ldap_context_t ** ppConnection
    )
{
    uint32_t error = 0;
    const int ldap_version = LDAP_VERSION3;
    const int iSaslNoCanon = 1;
    uint32_t ldap_port = LDAP_PORT;
    char *pszUrl = NULL;
    ovs_sasl_creds_t srp_creds = {0};
    char* pszUPNLower = NULL;
    char* pszCursor = NULL;

    ovs_ldap_context_t *pConnection = NULL;

    error = OvsAllocateMemory((void **)&pConnection, sizeof(*pConnection));
    BAIL_ON_ERROR(error);

    error = OvsAllocateStringPrintf(
        &pszUrl,
        "ldap://%s:%d",
        pszServer,
        ldap_port
    );
    BAIL_ON_ERROR(error);

    error = ldap_initialize(&pConnection->pLd, pszUrl);
    BAIL_ON_ERROR(error);

    error = ldap_set_option(
        pConnection->pLd,
        LDAP_OPT_PROTOCOL_VERSION,
        &ldap_version);
    BAIL_ON_ERROR(error);

    // turn off SASL hostname canonicalization for SRP mech
    error = ldap_set_option(
                pConnection->pLd,
                LDAP_OPT_X_SASL_NOCANON,
                &iSaslNoCanon
            );
    BAIL_ON_ERROR(error);

    error = OvsAllocateString(&pszUPNLower, pszUser);
    BAIL_ON_ERROR(error);

    for (pszCursor = pszUPNLower; pszCursor && *pszCursor; pszCursor++) {
         *pszCursor = tolower(*pszCursor);
    }

    srp_creds.authname = pszUPNLower;
    srp_creds.passwd = pszPassword;

    error = ldap_sasl_interactive_bind_s(
               pConnection->pLd,
               NULL,
               "SRP",
               NULL,
               NULL,
               LDAP_SASL_QUIET,
               OvsSASLInteraction,
               &srp_creds
           );
    BAIL_ON_ERROR(error);

    error = GetDSERootAttribute(pConnection->pLd,
        DEFAULT_NAMING_CONTEXT,
        &pConnection->pBaseDn);
    BAIL_ON_ERROR(error);

    *ppConnection = pConnection;

cleanup:

    OVS_SAFE_FREE_STRING(pszUPNLower);
    OVS_SAFE_FREE_STRING(pszUrl);

    return error;

error:

    if (pConnection) {
        OvsFreeConnection(pConnection);
    }
    goto cleanup;
}

uint32_t
OvsLdapAddImpl(
    ovs_ldap_context_t *pConnection,
    LDAPMod **attrs,
    char *pDn,
    char *bucket,
    char *pUuid
) {
    uint32_t error = 0;
    char *pNewDn = NULL;
    char *pElemDn = NULL;

    error = OvsAllocateStringPrintf(
        &pNewDn,
        "%s=%s,%s",
        LDAP_CN,
        bucket,
        pDn
    );
    BAIL_ON_ERROR(error);
    error = ldap_add_ext_s(
        pConnection->pLd,
        pNewDn,
        attrs,
        NULL,
        NULL
    );
    if (error == LDAP_ALREADY_EXISTS) {
        error = 0;
    }
    BAIL_ON_ERROR(error);

    error = OvsAllocateStringPrintf(
        &pElemDn,
        "%s=%s,%s",
        LDAP_CN,
        pUuid,
        pNewDn
    );
    BAIL_ON_ERROR(error);
    error = ldap_add_ext_s(
        pConnection->pLd,
        pElemDn,
        attrs,
        NULL,
        NULL
    );
    if (error == LDAP_ALREADY_EXISTS) {
        error = 0;
    }
    BAIL_ON_ERROR(error);

error:
    OVS_SAFE_FREE_STRING(pNewDn);
    OVS_SAFE_FREE_STRING(pElemDn);
    return error;
}

static
uint32_t
ovs_get_str_sequence(
    LDAPMod *pSequence,
    char **ppModv,
    int modv_index,
    char *pModType,
    char *pStr
) {
    uint32_t error = 0;

    if (OVS_IS_NULL_OR_EMPTY_STRING(pStr)) {
        pStr = LDAP_DEFAULT_STRING;
    }

    ppModv[modv_index] = pStr;
    pSequence->mod_op = LDAP_MOD_ADD;
    pSequence->mod_type = pModType;
    pSequence->mod_vals.modv_strvals = ppModv;

    return error;
}

static
uint32_t
ovs_get_bool_sequence(
    LDAPMod *pSequence,
    char **ppModv,
    int modv_index,
    char *pModType,
    bool value
) {
    char *pStr = NULL;
    uint32_t error = 0;
    if (value) {
        error = OvsAllocateString(&pStr, "TRUE");
    } else {
        error = OvsAllocateString(&pStr, "FALSE");
    }
    BAIL_ON_ERROR(error);
    error = ovs_get_str_sequence(
        pSequence,
        ppModv,
        modv_index,
        pModType,
        pStr
    );

error:
    return error;
}

// returns the allocated string for the given int
static
uint32_t
ovs_get_int_sequence(
    LDAPMod *pSequence,
    char **ppModv,
    int modv_index,
    char *pModType,
    int value
) {
    uint32_t error = 0;
    char *pDestStr = NULL;

    error = OvsAllocateStringPrintf(&pDestStr, "%d", value);
    BAIL_ON_ERROR(error);

    error = ovs_get_str_sequence(
        pSequence,
        ppModv,
        modv_index,
        pModType,
        pDestStr
    );
    BAIL_ON_ERROR(error);

cleanup:
    return error;
error:
    if (pDestStr) {
        OVS_SAFE_FREE_STRING(pDestStr);
    }
    goto cleanup;
}


static
uint32_t
ovs_get_map_sequence(
    LDAPMod *pSequence,
    char **ppModv,
    int modv_index,
    char *pModType,
    ovs_map_t *pMap,
    int mapLen
) {
    uint32_t error = 0;
    char *pStr = NULL;
    char *pTmp = NULL;
    int i = 0;

    if (mapLen > 0) {
        error = OvsAllocateStringPrintf(
            &pStr,
            "%s%s%s",
            pMap[0].pKey,
            KEY_SEP,
            pMap[0].pValue
        );
        BAIL_ON_ERROR(error);
        for (i = 1; i < mapLen; i++) {
            // TODO we can do a batched allocation for overcoming repeated
            // malloc/free.
            error = OvsAllocateStringPrintf(
                &pTmp,
                "%s%s%s%s%s",
                pStr,
                ENTRY_SEP,
                pMap[i].pKey,
                KEY_SEP,
                pMap[i].pValue
            );
            BAIL_ON_ERROR(error);
            OVS_SAFE_FREE_STRING(pStr);
            pStr = pTmp;
            pTmp = NULL;
        }
    } else {
        error = OvsAllocateString(&pStr, LDAP_DEFAULT_STRING);
        BAIL_ON_ERROR(error);
    }

    error = ovs_get_str_sequence(
        pSequence,
        ppModv,
        modv_index,
        pModType,
        pStr
    );
    BAIL_ON_ERROR(error);

cleanup:
    return error;

error:
    if (pStr) {
        OVS_SAFE_FREE_STRING(pStr);
        OVS_SAFE_FREE_STRING(pTmp);
    }
    goto cleanup;
}

static
uint32_t
ovs_get_set_sequence(
    LDAPMod *pSequence,
    char **ppModv,
    int modv_index,
    char *pModType,
    ovs_set_t *pSet,
    int setLen
) {
    uint32_t error = 0;
    char *pStr = NULL;
    char *pTmp = NULL;
    int i = 0;

    if (setLen > 0) {
        error = OvsAllocateString(&pStr, pSet[0].pValue);
        BAIL_ON_ERROR(error);
        for (i = 1; i < setLen; i++) {
            // TODO we can do a batched allocation for overcoming repeated
            // malloc/free.
            error = OvsAllocateStringPrintf(
                &pTmp,
                "%s%s%s",
                pSet[i].pValue,
                ENTRY_SEP,
                pStr
            );
            BAIL_ON_ERROR(error);
            OVS_SAFE_FREE_STRING(pStr);
            pStr = pTmp;
            pTmp = NULL;
        }
    } else {
        error = OvsAllocateString(&pStr, LDAP_DEFAULT_STRING);
        BAIL_ON_ERROR(error);
    }

    error = ovs_get_str_sequence(
        pSequence,
        ppModv,
        modv_index,
        pModType,
        pStr
    );
    BAIL_ON_ERROR(error);

cleanup:
    return error;

error:
    if (pStr) {
        OVS_SAFE_FREE_STRING(pStr);
        OVS_SAFE_FREE_STRING(pTmp);
    }
    goto cleanup;
}

static
void
destroy_ovs_map(ovs_map_t *ovs_map, size_t map_len) {
    size_t i;
    if (ovs_map) {
        for (i = 0; i < map_len; i++) {
            if (ovs_map->pKey) {
                OvsFreeMemory(ovs_map->pKey);
            }
            if (ovs_map->pValue) {
                OvsFreeMemory(ovs_map->pValue);
            }
        }
        OvsFreeMemory(ovs_map);
    }
}

static
uint32_t
ovsdb_datum_to_ovs_map(
    struct ovsdb_datum *datum,
    ovs_map_t ** ppovs_map,
    const struct ovsdb_type *povsdb_type
) {
    size_t i;
    ovs_map_t *povs_map = NULL;
    uint32_t error = 0;
    char *pKeyStr = NULL;
    char *pValueStr = NULL;

    if (datum->n == 0) {
        goto error;
    }

    error = OvsAllocateMemory((void **) &povs_map, datum->n * sizeof(*povs_map));
    BAIL_ON_ERROR(error)

    for (i = 0; i < datum->n; i++) {
        // Currently the only types of maps are string-string and string-integer
        error = OvsAllocateString(&pKeyStr, datum->keys[i].string);
        BAIL_ON_ERROR(error)
        char *valueStr = NULL;
        if (povsdb_type->value.type == OVSDB_TYPE_INTEGER) {
            error = OvsAllocateStringPrintf(&valueStr, "%d", datum->values[i].integer);
        } else if (povsdb_type->value.type == OVSDB_TYPE_STRING) {
            error = OvsAllocateString(&pValueStr, datum->values[i].string);
        } else {
            error = ERROR_OVS_INVALID_PARAMETER;
        }
        BAIL_ON_ERROR(error)
        povs_map[i].pKey = pKeyStr;
        povs_map[i].pValue = pValueStr;
    }

error:
    *ppovs_map = povs_map;
    return error;
}

static
void
destroy_ovs_set(ovs_set_t *ovs_set, size_t set_len) {
    size_t i;
    if (ovs_set) {
        for (i = 0; i < set_len; i++) {
            if (ovs_set->pValue) {
                OvsFreeMemory(ovs_set->pValue);
            }
        }
        OvsFreeMemory(ovs_set);
    }
}

static
uint32_t
ovsdb_datum_to_ovs_set(
    struct ovsdb_datum *datum,
    const struct ovsdb_type *ovsdb_type,
    ovs_set_t ** ppovs_set
) {
    size_t i;
    ovs_set_t *povs_set = NULL;
    uint32_t error = 0;
    char *pStr = NULL;

    if (datum->n == 0) {
        goto error;
    }
    error = OvsAllocateMemory((void **) &povs_set, datum->n * sizeof(*povs_set));
    BAIL_ON_ERROR(error)

    for (i = 0; i < datum->n; i++) {
        if (ovsdb_type->key.type == OVSDB_TYPE_STRING) {
            povs_set[i].type = STRING;
        } else if (ovsdb_type->key.type == OVSDB_TYPE_INTEGER) {
            povs_set[i].type = INTEGER;
        } else {
            error = ERROR_OVS_UNKNOWN_OVS_SET_TYPE;
            BAIL_ON_ERROR(error)
        }
        // TODO: Check the type of data. May not be string
        error = OvsAllocateString(&pStr, datum->keys[i].string);
        BAIL_ON_ERROR(error)
        povs_set[i].pValue = pStr;
    }

error:
    *ppovs_set = povs_set;
    return error;
}

static
uint32_t
LDAPMod_creater(
    const struct ovs_column *pOvsColumn,
    struct ovsdb_datum *datum,
    LDAPMod *pLDAPMod
) {
    uint32_t error = 0;
    char *pStr = NULL;
    char *column_name = NULL;
    ovs_set_t *povs_set = NULL;
    ovs_map_t *povs_map = NULL;

    char **modv;
    error = OvsAllocateMemory((void **) &modv, 2 * sizeof(char *));
    BAIL_ON_ERROR(error)

    OvsAllocateString(
        &column_name,
        pOvsColumn->ldap_column_name
    );

    switch (pOvsColumn->column_type) {
        case OVS_COLUMN_UUID :
            OvsAllocateString(
                &pStr,
                xasprintf(UUID_FMT, UUID_ARGS(&datum->keys->uuid))
            );
            error = ovs_get_str_sequence(
                pLDAPMod,
                modv,
                0,
                column_name,
                pStr
            );
            BAIL_ON_ERROR(error)
            break;
        case OVS_COLUMN_STRING :
            error = OvsAllocateString(&pStr, datum->keys->string);
            BAIL_ON_ERROR(error)
            error = ovs_get_str_sequence(
                pLDAPMod,
                modv,
                0,
                column_name,
                pStr
            );
            BAIL_ON_ERROR(error)
            break;
        case OVS_COLUMN_BOOLEAN :
            error = ovs_get_bool_sequence(
                pLDAPMod,
                modv,
                0,
                column_name,
                datum->keys->boolean
            );
            BAIL_ON_ERROR(error)
            break;
        case OVS_COLUMN_INTEGER :
            error = ovs_get_int_sequence(
                pLDAPMod,
                modv,
                0,
                column_name,
                datum->keys->integer
            );
            BAIL_ON_ERROR(error)
            break;
        case OVS_COLUMN_SET :
            error = ovsdb_datum_to_ovs_set(
                datum,
                pOvsColumn->pcolumn_ovsdb_type,
                &povs_set
            );
            BAIL_ON_ERROR(error)
            error = ovs_get_set_sequence(
                pLDAPMod,
                modv,
                0,
                column_name,
                povs_set,
                datum->n
            );
            BAIL_ON_ERROR(error)
            break;
        case OVS_COLUMN_MAP :
            error = ovsdb_datum_to_ovs_map(
                datum,
                &povs_map,
                pOvsColumn->pcolumn_ovsdb_type
            );
            BAIL_ON_ERROR(error)
            error = ovs_get_map_sequence(
                pLDAPMod,
                modv,
                0,
                column_name,
                povs_map,
                datum->n
            );
            BAIL_ON_ERROR(error)
            break;
        case OVS_COLUMN_DEFAULT :
        default :
            error = ERROR_OVS_INVALID_COLUMN_TYPE;
            goto error;
    }
error:
    destroy_ovs_map(povs_map, datum->n);
    destroy_ovs_set(povs_set, datum->n);
    return error;
}

static uint32_t
ldap_parse_row(
    const struct json *row_json,
    const struct ovs_column_set *povs_column_set,
    char *class_name,
    LDAPMod ***pattrs
) {
    size_t i;
    struct shash_node *node;
    struct sset columns_from_json;
    char **modv;
    uint32_t error = 0;
    size_t num_columns_found = 0;
    struct ovsdb_error *ovsdb_error = NULL;
    LDAPMod **attrs = NULL;

    error = OvsAllocateMemory(
        (void **) &attrs,
        sizeof(*attrs) * (povs_column_set->n_columns + 2)
    );
    BAIL_ON_ERROR(error)

    if (row_json->type != JSON_OBJECT) {
        error = ERROR_OVS_JSON_SYNTAX_ERROR;
        BAIL_ON_ERROR(error);
    }

    sset_init(&columns_from_json);

    // Fill columns from json
    const struct ovs_column *ovs_columns = povs_column_set->ovs_columns;
    SHASH_FOR_EACH (node, json_object(row_json)) {
        struct ovsdb_datum datum;
        const char *column_name = node->name;

        for (i = 0; i < povs_column_set->n_columns; i++) {
            if (!strcmp(ovs_columns[i].ovsdb_column_name, column_name)) {
                const struct ovs_column *pOvsColumn = &ovs_columns[i];
        ovsdb_error = ovsdb_datum_from_json(
            &datum,
            pOvsColumn->pcolumn_ovsdb_type,
            node->data,
            NULL
        );
        if (ovsdb_error) {
            error = ovsdb_error->errno_;
            BAIL_ON_ERROR(error);
        }
                LDAPMod *pLDAPMod = NULL;
                OvsAllocateMemory(
                    (void **) &pLDAPMod,
                    sizeof(*pLDAPMod)
                );
                error = LDAPMod_creater(pOvsColumn, &datum, pLDAPMod);
        BAIL_ON_ERROR(error)
        ovsdb_datum_destroy(&datum, pOvsColumn->pcolumn_ovsdb_type);
                attrs[num_columns_found++] = pLDAPMod;
                sset_add(&columns_from_json, column_name);
    }
}
    }

    // Fill default columns
    for (i = 0; i < povs_column_set->n_columns; i++) {
        const char *column_name = ovs_columns[i].ovsdb_column_name;
        if (!sset_contains(&columns_from_json, column_name)) {
            const struct ovs_column *pOvsColumn = &ovs_columns[i];
            struct ovsdb_datum default_datum;
            ovsdb_datum_init_default(&default_datum, pOvsColumn->pcolumn_ovsdb_type);
            // Default string of OVSDB is "", LDAP needs "null"
            if (pOvsColumn->column_type == OVS_COLUMN_STRING) {
                OvsFreeMemory(default_datum.keys->string);
                char *default_str = NULL;
                OvsAllocateString(&default_str, LDAP_DEFAULT_STRING);
                default_datum.keys->string = default_str;
            } else if (pOvsColumn->column_type == OVS_COLUMN_UUID) {
                uuid_generate(&default_datum.keys->uuid);
    }
            LDAPMod *pLDAPMod = NULL;
            OvsAllocateMemory(
                (void **) &pLDAPMod,
                sizeof(*pLDAPMod)
            );
            error = LDAPMod_creater(pOvsColumn, &default_datum, pLDAPMod);
            BAIL_ON_ERROR(error)
            ovsdb_datum_destroy(&default_datum, pOvsColumn->pcolumn_ovsdb_type);
            attrs[num_columns_found++] = pLDAPMod;
}
    }

    // Allocate Object Class LDAPMod struct
    error = OvsAllocateMemory((void **) &modv, 3 * sizeof(char *));
    BAIL_ON_ERROR(error);

    char *class_name_copy = NULL;
    char *ldap_top = NULL;
    char *ldap_object_class = NULL;
    OvsAllocateString(&class_name_copy, class_name);
    OvsAllocateString(&ldap_top, LDAP_TOP);
    OvsAllocateString(&ldap_object_class, LDAP_OBJECT_CLASS);

    modv[0] = class_name_copy;
    modv[1] = ldap_top;

    LDAPMod *pObjectClassLDAPMod = NULL;
    OvsAllocateMemory(
        (void **) &pObjectClassLDAPMod,
        sizeof(*pObjectClassLDAPMod)
    );

    pObjectClassLDAPMod->mod_op = LDAP_MOD_ADD;
    pObjectClassLDAPMod->mod_type = ldap_object_class;
    pObjectClassLDAPMod->mod_vals.modv_strvals = modv;
    attrs[povs_column_set->n_columns] = pObjectClassLDAPMod;

error:
    ovsdb_error_destroy(ovsdb_error);
    sset_destroy(&columns_from_json);
    *pattrs = attrs;
    return error;
}

static void attrs_cleanup(LDAPMod *attrs[], size_t num_columns) {
    size_t i;
    if (attrs) {
        for (i = 0; i < num_columns + 1; i++) {
            if (attrs[i]) {
                OvsFreeMemory(attrs[i]->mod_vals.modv_strvals[0]);
                if (strcmp(LDAP_OBJECT_CLASS, attrs[i]->mod_type) == 0) {
                    OvsFreeMemory(attrs[i]->mod_vals.modv_strvals[1]);
                    OvsFreeMemory(attrs[i]->mod_type);
                }
                OvsFreeMemory(attrs[i]->mod_vals.modv_strvals);
            }
        }
    }
}

static LDAP_FUNCTION_TABLE_INIT nb_north_bound_init;
static LDAP_FUNCTION_TABLE_INIT nb_connection_init;
static LDAP_FUNCTION_TABLE_INIT nb_ssl_init;
static LDAP_FUNCTION_TABLE_INIT nb_address_set_init;
static LDAP_FUNCTION_TABLE_INIT nb_logical_router_init;
static LDAP_FUNCTION_TABLE_INIT nb_logical_router_port_init;
static LDAP_FUNCTION_TABLE_INIT nb_gateway_chassis_init;
static LDAP_FUNCTION_TABLE_INIT nb_nat_init;
static LDAP_FUNCTION_TABLE_INIT nb_logical_router_static_route_init;
static LDAP_FUNCTION_TABLE_INIT nb_load_balancer_init;
static LDAP_FUNCTION_TABLE_INIT nb_logical_switch_init;
static LDAP_FUNCTION_TABLE_INIT nb_logical_switch_port_init;
static LDAP_FUNCTION_TABLE_INIT nb_dhcp_options_init;
static LDAP_FUNCTION_TABLE_INIT nb_qos_init;
static LDAP_FUNCTION_TABLE_INIT nb_dns_config_init;
static LDAP_FUNCTION_TABLE_INIT nb_acl_init;


static FN_LDAP_OPERATION nb_acl_ldap_delete;
static FN_LDAP_OPERATION nb_acl_ldap_insert;
static FN_LDAP_OPERATION nb_acl_ldap_select;
static FN_LDAP_OPERATION nb_acl_ldap_update;
static FN_LDAP_OPERATION nb_address_set_ldap_delete;
static FN_LDAP_OPERATION nb_address_set_ldap_insert;
static FN_LDAP_OPERATION nb_address_set_ldap_select;
static FN_LDAP_OPERATION nb_address_set_ldap_update;
static FN_LDAP_OPERATION nb_connection_ldap_delete;
static FN_LDAP_OPERATION nb_connection_ldap_insert;
static FN_LDAP_OPERATION nb_connection_ldap_select;
static FN_LDAP_OPERATION nb_connection_ldap_update;
static FN_LDAP_OPERATION nb_dhcp_options_ldap_delete;
static FN_LDAP_OPERATION nb_dhcp_options_ldap_insert;
static FN_LDAP_OPERATION nb_dhcp_options_ldap_select;
static FN_LDAP_OPERATION nb_dhcp_options_ldap_update;
static FN_LDAP_OPERATION nb_dns_config_ldap_delete;
static FN_LDAP_OPERATION nb_dns_config_ldap_insert;
static FN_LDAP_OPERATION nb_dns_config_ldap_select;
static FN_LDAP_OPERATION nb_dns_config_ldap_update;
static FN_LDAP_OPERATION nb_gateway_chassis_ldap_delete;
static FN_LDAP_OPERATION nb_gateway_chassis_ldap_insert;
static FN_LDAP_OPERATION nb_gateway_chassis_ldap_select;
static FN_LDAP_OPERATION nb_gateway_chassis_ldap_update;
static FN_LDAP_OPERATION nb_load_balancer_ldap_delete;
static FN_LDAP_OPERATION nb_load_balancer_ldap_insert;
static FN_LDAP_OPERATION nb_load_balancer_ldap_select;
static FN_LDAP_OPERATION nb_load_balancer_ldap_update;
static FN_LDAP_OPERATION nb_logical_router_ldap_delete;
static FN_LDAP_OPERATION nb_logical_router_ldap_insert;
static FN_LDAP_OPERATION nb_logical_router_ldap_select;
static FN_LDAP_OPERATION nb_logical_router_ldap_update;
static FN_LDAP_OPERATION nb_logical_router_port_ldap_delete;
static FN_LDAP_OPERATION nb_logical_router_port_ldap_insert;
static FN_LDAP_OPERATION nb_logical_router_port_ldap_select;
static FN_LDAP_OPERATION nb_logical_router_port_ldap_update;
static FN_LDAP_OPERATION nb_logical_router_static_route_ldap_delete;
static FN_LDAP_OPERATION nb_logical_router_static_route_ldap_insert;
static FN_LDAP_OPERATION nb_logical_router_static_route_ldap_select;
static FN_LDAP_OPERATION nb_logical_router_static_route_ldap_update;
static FN_LDAP_OPERATION nb_logical_switch_ldap_delete;
static FN_LDAP_OPERATION nb_logical_switch_ldap_insert;
static FN_LDAP_OPERATION nb_logical_switch_ldap_select;
static FN_LDAP_OPERATION nb_logical_switch_ldap_update;
static FN_LDAP_OPERATION nb_logical_switch_port_ldap_delete;
static FN_LDAP_OPERATION nb_logical_switch_port_ldap_insert;
static FN_LDAP_OPERATION nb_logical_switch_port_ldap_select;
static FN_LDAP_OPERATION nb_logical_switch_port_ldap_update;
static FN_LDAP_OPERATION nb_nat_ldap_delete;
static FN_LDAP_OPERATION nb_nat_ldap_insert;
static FN_LDAP_OPERATION nb_nat_ldap_select;
static FN_LDAP_OPERATION nb_nat_ldap_update;
static FN_LDAP_OPERATION nb_north_bound_ldap_delete;
static FN_LDAP_OPERATION nb_north_bound_ldap_insert;
static FN_LDAP_OPERATION nb_north_bound_ldap_select;
static FN_LDAP_OPERATION nb_north_bound_ldap_update;
static FN_LDAP_OPERATION nb_qos_ldap_delete;
static FN_LDAP_OPERATION nb_qos_ldap_insert;
static FN_LDAP_OPERATION nb_qos_ldap_select;
static FN_LDAP_OPERATION nb_qos_ldap_update;
static FN_LDAP_OPERATION nb_ssl_ldap_delete;
static FN_LDAP_OPERATION nb_ssl_ldap_insert;
static FN_LDAP_OPERATION nb_ssl_ldap_select;
static FN_LDAP_OPERATION nb_ssl_ldap_update;

static FN_LDAP_GET_OVS_COLUMN_SET nb_north_bound_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_connection_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_ssl_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_address_set_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_logical_router_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_logical_router_port_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_gateway_chassis_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_nat_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_logical_router_static_route_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_load_balancer_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_logical_switch_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_logical_switch_port_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_dhcp_options_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_qos_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_dns_config_ldap_get_column_set;
static FN_LDAP_GET_OVS_COLUMN_SET nb_acl_ldap_get_column_set;

uint32_t
get_obj_function_table_from_table(LDAP_FUNCTION_TABLE *, struct ovsdb_parser *);

static FN_LDAP_OPERATION *
lookup_ldap_operation(
    LDAP_FUNCTION_TABLE *pldap_obj_fn_table,
    const char *op_name,
    bool *read_only
) {
    struct ldap_operation {
        const char *name;
        bool read_only;
        FN_LDAP_OPERATION *pfn_ldap_operation;
    };

    const struct ldap_operation operations[] = {
        { "insert", false, pldap_obj_fn_table->pfn_ldap_insert },
        { "select", true, pldap_obj_fn_table->pfn_ldap_select },
        { "update", false, pldap_obj_fn_table->pfn_ldap_update },
        { "delete", false, pldap_obj_fn_table->pfn_ldap_delete },
    };

    size_t i;
    for (i = 0; i < ARRAY_SIZE(operations); i++) {
        const struct ldap_operation *c = &operations[i];
        if (!strcmp(c->name, op_name)) {
            *read_only = c->read_only;
            return c->pfn_ldap_operation;
        }
    }
    return NULL;
}

LDAP_FUNCTION_TABLE
nb_north_bound_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_north_bound_ldap_insert,
        nb_north_bound_ldap_select,
        nb_north_bound_ldap_delete,
        nb_north_bound_ldap_update,
        nb_north_bound_ldap_get_column_set
    };
    VLOG_INFO("nb_north_bound_init called\n");
    return ldap_fn_table;
}


static uint32_t
nb_ldap_insert_helper(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set,
    char *class_name
) {
        size_t i;
    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod **attrs = NULL;

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }

    error = ldap_parse_row(
        row_json,
        povs_column_set,
        class_name,
        &attrs
    );
    BAIL_ON_ERROR(error);

    char *uuid = NULL;
    for (i = 0; i <= povs_column_set->n_columns; i++) {
        if (strcmp(LDAP_CN, attrs[i]->mod_type) == 0) {
            uuid = attrs[i]->mod_vals.modv_strvals[0];
        }
    }
    char *pDn = NULL;
    GetDSERootAttribute(
        pContext->ldap_conn->pLd,
        DEFAULT_NAMING_CONTEXT,
        &pDn
    );
    error = OvsLdapAddImpl(
        pContext->ldap_conn,
        attrs,
        pDn,
        class_name,
        uuid
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    uuid
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, povs_column_set->n_columns);
    ovsdb_error_destroy(ovsdb_error);

    return error;

}

static
struct ovs_column_set
nb_north_bound_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_GLOBAL_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_hv_sequence = NULL;
    char *ovs_nb_sequence = NULL;
    char *ovs_sb_sequence = NULL;
    char *ovs_connection_set = NULL;
    char *ovs_external_ids = NULL;
    char *ovs_ssl_config = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_hv_sequence = NULL;
    char *ovsdb_nb_sequence = NULL;
    char *ovsdb_sb_sequence = NULL;
    char *ovsdb_connection_set = NULL;
    char *ovsdb_external_ids = NULL;
    char *ovsdb_ssl_config = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_hv_sequence, OVS_HV_SEQUENCE);
    OvsAllocateString(&ovs_nb_sequence, OVS_NB_SEQUENCE);
    OvsAllocateString(&ovs_sb_sequence, OVS_SB_SEQUENCE);
    OvsAllocateString(&ovs_connection_set, OVS_CONNECTION_SET);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovs_ssl_config, OVS_SSL_CONFIG);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_hv_sequence, OVSDB_HV_SEQUENCE);
    OvsAllocateString(&ovsdb_nb_sequence, OVSDB_NB_SEQUENCE);
    OvsAllocateString(&ovsdb_sb_sequence, OVSDB_SB_SEQUENCE);
    OvsAllocateString(&ovsdb_connection_set, OVSDB_CONNECTION_SET);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_ssl_config, OVSDB_SSL_CONFIG);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_hv_sequence, OVS_COLUMN_INTEGER, ovsdb_hv_sequence, &ovsdb_type_integer},
        {ovs_nb_sequence, OVS_COLUMN_INTEGER, ovsdb_nb_sequence, &ovsdb_type_integer},
        {ovs_sb_sequence, OVS_COLUMN_INTEGER, ovsdb_sb_sequence, &ovsdb_type_integer},
        {ovs_connection_set, OVS_COLUMN_SET, ovsdb_connection_set, &ovsdb_type_string_set},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
        {ovs_ssl_config, OVS_COLUMN_STRING, ovsdb_ssl_config, &ovsdb_type_string},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_GLOBAL_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_north_bound_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    VLOG_INFO("nb_north_bound_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
        result,
        povs_column_set,
        NB_GLOBAL_OBJ_CLASS_NAME
    );
}

static uint32_t
nb_north_bound_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_north_bound_ldap_select called\n");
    return error;
}

static uint32_t
nb_north_bound_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_north_bound_ldap_delete called\n");
    return error;
}

static uint32_t
nb_north_bound_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_north_bound_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_connection_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_connection_ldap_insert,
        nb_connection_ldap_select,
        nb_connection_ldap_delete,
        nb_connection_ldap_update,
        nb_connection_ldap_get_column_set
    };
    VLOG_INFO("nb_connection_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_connection_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_CONN_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_connection_target = NULL;
    char *ovs_conn_is_connected = NULL;
    char *ovs_max_back_off = NULL;
    char *ovs_inactivity_probe = NULL;
    char *ovs_status = NULL;
    char *ovs_configs = NULL;
    char *ovs_external_ids = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_connection_target = NULL;
    char *ovsdb_conn_is_connected = NULL;
    char *ovsdb_max_back_off = NULL;
    char *ovsdb_inactivity_probe = NULL;
    char *ovsdb_status = NULL;
    char *ovsdb_configs = NULL;
    char *ovsdb_external_ids = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_connection_target, OVS_CONNECTION_TARGET);
    OvsAllocateString(&ovs_conn_is_connected, OVS_CONN_IS_CONNECTED);
    OvsAllocateString(&ovs_max_back_off, OVS_MAX_BACK_OFF);
    OvsAllocateString(&ovs_inactivity_probe, OVS_INACTIVITY_PROBE);
    OvsAllocateString(&ovs_status, OVS_STATUS);
    OvsAllocateString(&ovs_configs, OVS_CONFIGS);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_connection_target, OVSDB_CONNECTION_TARGET);
    OvsAllocateString(&ovsdb_conn_is_connected, OVSDB_CONN_IS_CONNECTED);
    OvsAllocateString(&ovsdb_max_back_off, OVSDB_MAX_BACK_OFF);
    OvsAllocateString(&ovsdb_inactivity_probe, OVSDB_INACTIVITY_PROBE);
    OvsAllocateString(&ovsdb_status, OVSDB_STATUS);
    OvsAllocateString(&ovsdb_configs, OVSDB_CONFIGS);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_connection_target, OVS_COLUMN_STRING, ovsdb_connection_target, &ovsdb_type_string},
        {ovs_conn_is_connected, OVS_COLUMN_BOOLEAN, ovsdb_conn_is_connected, &ovsdb_type_boolean},
        {ovs_max_back_off, OVS_COLUMN_INTEGER, ovsdb_max_back_off, &ovsdb_type_integer},
        {ovs_inactivity_probe, OVS_COLUMN_INTEGER, ovsdb_inactivity_probe, &ovsdb_type_integer},
        {ovs_status, OVS_COLUMN_MAP, ovsdb_status, &ovsdb_type_string_string_map},
        {ovs_configs, OVS_COLUMN_MAP, ovsdb_configs, &ovsdb_type_string_string_map},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_CONN_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_connection_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    VLOG_INFO("nb_connection_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
            result,
        povs_column_set,
        NB_CONN_OBJ_CLASS_NAME
        );
    }

static uint32_t
nb_connection_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_connection_ldap_select called\n");
    return error;
}

static uint32_t
nb_connection_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_connection_ldap_delete called\n");
    return error;
}

static uint32_t
nb_connection_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_connection_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_ssl_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_ssl_ldap_insert,
        nb_ssl_ldap_select,
        nb_ssl_ldap_delete,
        nb_ssl_ldap_update,
        nb_ssl_ldap_get_column_set
    };
    VLOG_INFO("nb_ssl_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_ssl_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_SSL_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_ssl_private_key = NULL;
    char *ovs_ssl_cert = NULL;
    char *ovs_ssl_ca_cert = NULL;
    char *ovs_ssl_bootstrap_ca_cert = NULL;
    char *ovs_ssl_protocols = NULL;
    char *ovs_ssl_ciphers = NULL;
    char *ovs_external_ids = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_ssl_private_key = NULL;
    char *ovsdb_ssl_cert = NULL;
    char *ovsdb_ssl_ca_cert = NULL;
    char *ovsdb_ssl_bootstrap_ca_cert = NULL;
    char *ovsdb_ssl_protocols = NULL;
    char *ovsdb_ssl_ciphers = NULL;
    char *ovsdb_external_ids = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_ssl_private_key, OVS_SSL_PRIVATE_KEY);
    OvsAllocateString(&ovs_ssl_cert, OVS_SSL_CERT);
    OvsAllocateString(&ovs_ssl_ca_cert, OVS_SSL_CA_CERT);
    OvsAllocateString(&ovs_ssl_bootstrap_ca_cert, OVS_SSL_BOOTSTRAP_CA_CERT);
    OvsAllocateString(&ovs_ssl_protocols, OVS_SSL_PROTOCOLS);
    OvsAllocateString(&ovs_ssl_ciphers, OVS_SSL_CIPHERS);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_ssl_private_key, OVSDB_SSL_PRIVATE_KEY);
    OvsAllocateString(&ovsdb_ssl_cert, OVSDB_SSL_CERT);
    OvsAllocateString(&ovsdb_ssl_ca_cert, OVSDB_SSL_CA_CERT);
    OvsAllocateString(&ovsdb_ssl_bootstrap_ca_cert, OVSDB_SSL_BOOTSTRAP_CA_CERT);
    OvsAllocateString(&ovsdb_ssl_protocols, OVSDB_SSL_PROTOCOLS);
    OvsAllocateString(&ovsdb_ssl_ciphers, OVSDB_SSL_CIPHERS);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_ssl_private_key, OVS_COLUMN_STRING, ovsdb_ssl_private_key, &ovsdb_type_string},
        {ovs_ssl_cert, OVS_COLUMN_STRING, ovsdb_ssl_cert, &ovsdb_type_string},
        {ovs_ssl_ca_cert, OVS_COLUMN_STRING, ovsdb_ssl_ca_cert, &ovsdb_type_string},
        {ovs_ssl_bootstrap_ca_cert, OVS_COLUMN_BOOLEAN, ovsdb_ssl_bootstrap_ca_cert, &ovsdb_type_boolean},
        {ovs_ssl_protocols, OVS_COLUMN_STRING, ovsdb_ssl_protocols, &ovsdb_type_string},
        {ovs_ssl_ciphers, OVS_COLUMN_STRING, ovsdb_ssl_ciphers, &ovsdb_type_string},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_SSL_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_ssl_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    VLOG_INFO("nb_ssl_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
            result,
        povs_column_set,
        NB_SSL_OBJ_CLASS_NAME
        );
    }

static uint32_t
nb_ssl_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_ssl_ldap_select called\n");
    return error;
}

static uint32_t
nb_ssl_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_ssl_ldap_delete called\n");
    return error;
}

static uint32_t
nb_ssl_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
   VLOG_INFO("nb_ssl_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_address_set_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_address_set_ldap_insert,
        nb_address_set_ldap_select,
        nb_address_set_ldap_delete,
        nb_address_set_ldap_update,
        nb_address_set_ldap_get_column_set
    };
    VLOG_INFO("nb_address_set_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_address_set_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_ADDRESS_SET_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_addresses = NULL;
    char *ovs_external_ids = NULL;
    char *ovs_name = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_addresses = NULL;
    char *ovsdb_external_ids = NULL;
    char *ovsdb_name = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_addresses, OVS_ADDRESSES);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovs_name, OVS_NAME);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_addresses, OVSDB_ADDRESSES);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_name, OVSDB_NAME);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_addresses, OVS_COLUMN_SET, ovsdb_addresses, &ovsdb_type_string_set},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
        {ovs_name, OVS_COLUMN_STRING, ovsdb_name, &ovsdb_type_string}
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_ADDRESS_SET_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_address_set_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    VLOG_INFO("nb_address_set_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
            result,
        povs_column_set,
        NB_ADDRESS_SET_OBJ_CLASS_NAME
        );
    }

static uint32_t
nb_address_set_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_address_set_ldap_select called\n");
    return error;
}

static uint32_t
nb_address_set_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_address_set_ldap_delete called\n");
    return error;
}

static uint32_t
nb_address_set_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_address_set_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_logical_router_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_logical_router_ldap_insert,
        nb_logical_router_ldap_select,
        nb_logical_router_ldap_delete,
        nb_logical_router_ldap_update,
        nb_logical_router_ldap_get_column_set
    };
    VLOG_INFO("nb_logical_router_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_logical_router_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_LOGICAL_RT_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_is_enabled = NULL;
    char *ovs_name = NULL;
    char *ovs_port_set = NULL;
    char *ovs_static_routes_set = NULL;
    char *ovs_nat = NULL;
    char *ovs_lb_set = NULL;
    char *ovs_options = NULL;
    char *ovs_external_ids = NULL;

    char *ovsdb_uuid = NULL;
    char *ovsdb_is_enabled = NULL;
    char *ovsdb_name = NULL;
    char *ovsdb_port_set = NULL;
    char *ovsdb_static_routes_set = NULL;
    char *ovsdb_nat = NULL;
    char *ovsdb_lb_set = NULL;
    char *ovsdb_options = NULL;
    char *ovsdb_external_ids = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_is_enabled, OVS_IS_ENABLED);
    OvsAllocateString(&ovs_name, OVS_NAME);
    OvsAllocateString(&ovs_port_set, OVS_PORT_SET);
    OvsAllocateString(&ovs_static_routes_set, OVS_STATIC_ROUTES_SET);
    OvsAllocateString(&ovs_nat, OVS_NAT);
    OvsAllocateString(&ovs_lb_set, OVS_LB_SET);
    OvsAllocateString(&ovs_options, OVS_OPTIONS);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_is_enabled, OVSDB_IS_ENABLED);
    OvsAllocateString(&ovsdb_name, OVSDB_NAME);
    OvsAllocateString(&ovsdb_port_set, OVSDB_PORT_SET);
    OvsAllocateString(&ovsdb_static_routes_set, OVSDB_STATIC_ROUTES_SET);
    OvsAllocateString(&ovsdb_nat, OVSDB_NAT);
    OvsAllocateString(&ovsdb_lb_set, OVSDB_LB_SET);
    OvsAllocateString(&ovsdb_options, OVSDB_OPTIONS);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_is_enabled, OVS_COLUMN_BOOLEAN, ovsdb_is_enabled, &ovsdb_type_boolean},
        {ovs_name, OVS_COLUMN_STRING, ovsdb_name, &ovsdb_type_string},
        {ovs_port_set, OVS_COLUMN_SET, ovsdb_port_set, &ovsdb_type_string_set},
        {ovs_static_routes_set, OVS_COLUMN_SET, ovsdb_static_routes_set, &ovsdb_type_string_set},
        {ovs_nat, OVS_COLUMN_STRING, ovsdb_nat, &ovsdb_type_string},
        {ovs_lb_set, OVS_COLUMN_SET, ovsdb_lb_set, &ovsdb_type_string_set},
        {ovs_options, OVS_COLUMN_MAP, ovsdb_options, &ovsdb_type_string_string_map},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_LOGICAL_RT_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_logical_router_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    VLOG_INFO("nb_logical_router_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
        result,
        povs_column_set,
        NB_LOGICAL_RT_OBJ_CLASS_NAME
    );
}

static uint32_t
nb_logical_router_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_logical_router_ldap_select called\n");
    return error;
}

static uint32_t
nb_logical_router_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    return error;
}

static uint32_t
nb_logical_router_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_router_ldap_update called\n");
    result->count = 0;
    return error;
}

LDAP_FUNCTION_TABLE
nb_logical_router_port_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_logical_router_port_ldap_insert,
        nb_logical_router_port_ldap_select,
        nb_logical_router_port_ldap_delete,
        nb_logical_router_port_ldap_update,
        nb_logical_router_port_ldap_get_column_set
    };
    VLOG_INFO("nb_logical_router_port_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_logical_router_port_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_LOGICAL_RT_PORT_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_name = NULL;
    char *ovs_lr_mac = NULL;
    char *ovs_is_enabled = NULL;
    char *ovs_external_ids = NULL;
    char *ovs_gw_chassis_set = NULL;
    char *ovs_networks = NULL;
    char *ovs_options = NULL;
    char *ovs_lr_peer = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_name = NULL;
    char *ovsdb_lr_mac = NULL;
    char *ovsdb_is_enabled = NULL;
    char *ovsdb_external_ids = NULL;
    char *ovsdb_gw_chassis_set = NULL;
    char *ovsdb_networks = NULL;
    char *ovsdb_options = NULL;
    char *ovsdb_lr_peer = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_name, OVS_NAME);
    OvsAllocateString(&ovs_lr_mac, OVS_LR_MAC);
    OvsAllocateString(&ovs_is_enabled, OVS_IS_ENABLED);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovs_gw_chassis_set, OVS_GW_CHASSIS_SET);
    OvsAllocateString(&ovs_networks, OVS_NETWORKS);
    OvsAllocateString(&ovs_options, OVS_OPTIONS);
    OvsAllocateString(&ovs_lr_peer, OVS_LR_PEER);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_name, OVSDB_NAME);
    OvsAllocateString(&ovsdb_lr_mac, OVSDB_LR_MAC);
    OvsAllocateString(&ovsdb_is_enabled, OVSDB_IS_ENABLED);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_gw_chassis_set, OVSDB_GW_CHASSIS_SET);
    OvsAllocateString(&ovsdb_networks, OVSDB_NETWORKS);
    OvsAllocateString(&ovsdb_options, OVSDB_OPTIONS);
    OvsAllocateString(&ovsdb_lr_peer, OVSDB_LR_PEER);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_name, OVS_COLUMN_STRING, ovsdb_name, &ovsdb_type_string},
        {ovs_lr_mac, OVS_COLUMN_STRING, ovsdb_lr_mac, &ovsdb_type_string},
        {ovs_is_enabled, OVS_COLUMN_BOOLEAN, ovsdb_is_enabled, &ovsdb_type_boolean},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
        {ovs_gw_chassis_set, OVS_COLUMN_SET, ovsdb_gw_chassis_set, &ovsdb_type_string_set},
        {ovs_networks, OVS_COLUMN_STRING, ovsdb_networks, &ovsdb_type_string},
        {ovs_options, OVS_COLUMN_MAP, ovsdb_options, &ovsdb_type_string_set},
        {ovs_lr_peer, OVS_COLUMN_STRING, ovsdb_lr_peer, &ovsdb_type_string},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_LOGICAL_RT_PORT_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_logical_router_port_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set
) {
    VLOG_INFO("nb_logical_router_port_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
            result,
        povs_column_set,
        NB_LOGICAL_RT_PORT_OBJ_CLASS_NAME
        );
    }

static uint32_t
nb_logical_router_port_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    VLOG_INFO("nb_logical_router_port_ldap_select called\n");

    static uint32_t error = 0;
    result->count = 0;
    return error;
}

static uint32_t
nb_logical_router_port_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_logical_router_port_ldap_delete called\n");
    return error;
}

static uint32_t
nb_logical_router_port_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_logical_router_port_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_gateway_chassis_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_gateway_chassis_ldap_insert,
        nb_gateway_chassis_ldap_select,
        nb_gateway_chassis_ldap_delete,
        nb_gateway_chassis_ldap_update,
        nb_gateway_chassis_ldap_get_column_set
    };
    VLOG_INFO("nb_gateway_chassis_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_gateway_chassis_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_GW_CHASSIS_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_name = NULL;
    char *ovs_gw_chassis_ovs_name = NULL;
    char *ovs_priority = NULL;
    char *ovs_options = NULL;
    char *ovs_external_ids = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_name = NULL;
    char *ovsdb_gw_chassis_ovs_name = NULL;
    char *ovsdb_priority = NULL;
    char *ovsdb_options = NULL;
    char *ovsdb_external_ids = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_name, OVS_NAME);
    OvsAllocateString(&ovs_gw_chassis_ovs_name, OVS_GW_CHASSIS_OVS_NAME);
    OvsAllocateString(&ovs_priority, OVS_PRIORITY);
    OvsAllocateString(&ovs_options, OVS_OPTIONS);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_name, OVSDB_NAME);
    OvsAllocateString(&ovsdb_gw_chassis_ovs_name, OVSDB_GW_CHASSIS_OVS_NAME);
    OvsAllocateString(&ovsdb_priority, OVSDB_PRIORITY);
    OvsAllocateString(&ovsdb_options, OVSDB_OPTIONS);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_name, OVS_COLUMN_STRING, ovsdb_name, &ovsdb_type_string},
        {ovs_gw_chassis_ovs_name, OVS_COLUMN_STRING, ovsdb_gw_chassis_ovs_name, &ovsdb_type_string},
        {ovs_priority, OVS_COLUMN_INTEGER, ovsdb_priority, &ovsdb_type_integer},
        {ovs_options, OVS_COLUMN_MAP, ovsdb_options, &ovsdb_type_string_string_map},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_GW_CHASSIS_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_gateway_chassis_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set
) {
    VLOG_INFO("nb_gateway_chassis_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
            result,
        povs_column_set,
        NB_GW_CHASSIS_OBJ_CLASS_NAME
        );
    }

static uint32_t
nb_gateway_chassis_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_gateway_chassis_ldap_select called\n");
    return error;
}

static uint32_t
nb_gateway_chassis_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_gateway_chassis_ldap_delete called\n");
    return error;
}

static uint32_t
nb_gateway_chassis_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_gateway_chassis_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_nat_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_nat_ldap_insert,
        nb_nat_ldap_select,
        nb_nat_ldap_delete,
        nb_nat_ldap_update,
        nb_nat_ldap_get_column_set
    };
    VLOG_INFO("nb_nat_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_nat_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_NAT_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_external_ip = NULL;
    char *ovs_external_mac = NULL;
    char *ovs_logical_ip = NULL;
    char *ovs_logical_port = NULL;
    char *ovs_nat_type = NULL;
    char *ovs_external_ids = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_external_ip = NULL;
    char *ovsdb_external_mac = NULL;
    char *ovsdb_logical_ip = NULL;
    char *ovsdb_logical_port = NULL;
    char *ovsdb_nat_type = NULL;
    char *ovsdb_external_ids = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_external_ip, OVS_EXTERNAL_IP);
    OvsAllocateString(&ovs_external_mac, OVS_EXTERNAL_MAC);
    OvsAllocateString(&ovs_logical_ip, OVS_LOGICAL_IP);
    OvsAllocateString(&ovs_logical_port, OVS_LOGICAL_PORT);
    OvsAllocateString(&ovs_nat_type, OVS_NAT_TYPE);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_external_ip, OVSDB_EXTERNAL_IP);
    OvsAllocateString(&ovsdb_external_mac, OVSDB_EXTERNAL_MAC);
    OvsAllocateString(&ovsdb_logical_ip, OVSDB_LOGICAL_IP);
    OvsAllocateString(&ovsdb_logical_port, OVSDB_LOGICAL_PORT);
    OvsAllocateString(&ovsdb_nat_type, OVSDB_NAT_TYPE);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_external_ip, OVS_COLUMN_STRING, ovsdb_external_ip, &ovsdb_type_string},
        {ovs_external_mac, OVS_COLUMN_STRING, ovsdb_external_mac, &ovsdb_type_string},
        {ovs_logical_ip, OVS_COLUMN_STRING, ovsdb_logical_ip, &ovsdb_type_string},
        {ovs_logical_port, OVS_COLUMN_STRING, ovsdb_logical_port, &ovsdb_type_string},
        {ovs_nat_type, OVS_COLUMN_STRING, ovsdb_nat_type, &ovsdb_type_string},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_NAT_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_nat_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set
) {
    VLOG_INFO("nb_nat_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
            result,
        povs_column_set,
        NB_NAT_OBJ_CLASS_NAME
        );
    }

static uint32_t
nb_nat_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_nat_ldap_select called\n");
    return error;
}

static uint32_t
nb_nat_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_nat_ldap_delete called\n");
    return error;
}

static uint32_t
nb_nat_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_nat_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_logical_router_static_route_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_logical_router_static_route_ldap_insert,
        nb_logical_router_static_route_ldap_select,
        nb_logical_router_static_route_ldap_delete,
        nb_logical_router_static_route_ldap_update,
        nb_logical_router_static_route_ldap_get_column_set
    };
    VLOG_INFO("nb_logical_router_static_route_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_logical_router_static_route_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_LOGICAL_RT_STATIC_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_policy = NULL;
    char *ovs_next_hop = NULL;
    char *ovs_ip_prefix = NULL;
    char *ovs_output_port = NULL;
    char *ovs_external_ids = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_policy = NULL;
    char *ovsdb_next_hop = NULL;
    char *ovsdb_ip_prefix = NULL;
    char *ovsdb_output_port = NULL;
    char *ovsdb_external_ids = NULL;

    OvsAllocateString(&ldap_cn,LDAP_CN);
    OvsAllocateString(&ovs_policy,OVS_POLICY);
    OvsAllocateString(&ovs_next_hop,OVS_NEXT_HOP);
    OvsAllocateString(&ovs_ip_prefix,OVS_IP_PREFIX);
    OvsAllocateString(&ovs_output_port,OVS_OUTPUT_PORT);
    OvsAllocateString(&ovs_external_ids,OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_uuid,OVSDB_UUID);
    OvsAllocateString(&ovsdb_policy,OVSDB_POLICY);
    OvsAllocateString(&ovsdb_next_hop,OVSDB_NEXT_HOP);
    OvsAllocateString(&ovsdb_ip_prefix,OVSDB_IP_PREFIX);
    OvsAllocateString(&ovsdb_output_port,OVSDB_OUTPUT_PORT);
    OvsAllocateString(&ovsdb_external_ids,OVSDB_EXTERNAL_IDS);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_policy, OVS_COLUMN_STRING, ovsdb_policy, &ovsdb_type_string},
        {ovs_next_hop, OVS_COLUMN_STRING, ovsdb_next_hop, &ovsdb_type_string},
        {ovs_ip_prefix, OVS_COLUMN_STRING, ovsdb_ip_prefix, &ovsdb_type_string},
        {ovs_output_port, OVS_COLUMN_STRING, ovsdb_output_port, &ovsdb_type_string},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_LOGICAL_RT_STATIC_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_logical_router_static_route_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set
) {
    VLOG_INFO("nb_logical_router_static_route_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
            result,
        povs_column_set,
        NB_LOGICAL_RT_STATIC_OBJ_CLASS_NAME
        );
    }

static uint32_t
nb_logical_router_static_route_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_logical_router_static_route_ldap_select called\n");
    return error;
}

static uint32_t
nb_logical_router_static_route_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_logical_router_static_route_ldap_delete called\n");
    return error;
}

static uint32_t
nb_logical_router_static_route_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_logical_router_static_route_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_load_balancer_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_load_balancer_ldap_insert,
        nb_load_balancer_ldap_select,
        nb_load_balancer_ldap_delete,
        nb_load_balancer_ldap_update,
        nb_load_balancer_ldap_get_column_set
    };
    VLOG_INFO("nb_load_balancer_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_load_balancer_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_LB_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_name = NULL;
    char *ovs_protocol = NULL;
    char *ovs_vips = NULL;
    char *ovs_external_ids = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_name = NULL;
    char *ovsdb_protocol = NULL;
    char *ovsdb_vips = NULL;
    char *ovsdb_external_ids = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_name, OVS_NAME);
    OvsAllocateString(&ovs_protocol, OVS_PROTOCOL);
    OvsAllocateString(&ovs_vips, OVS_VIPS);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_name, OVSDB_NAME);
    OvsAllocateString(&ovsdb_protocol, OVSDB_PROTOCOL);
    OvsAllocateString(&ovsdb_vips, OVSDB_VIPS);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_name, OVS_COLUMN_STRING, ovsdb_name, &ovsdb_type_string},
        {ovs_protocol, OVS_COLUMN_STRING, ovsdb_protocol, &ovsdb_type_string},
        {ovs_vips, OVS_COLUMN_MAP, ovsdb_vips, &ovsdb_type_string_string_map},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_LB_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_load_balancer_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set
) {
    VLOG_INFO("nb_load_balancer_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
            result,
        povs_column_set,
        NB_LB_OBJ_CLASS_NAME
        );
    }

static uint32_t
nb_load_balancer_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_load_balancer_ldap_select called\n");
    return error;
}

static uint32_t
nb_load_balancer_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_load_balancer_ldap_delete called\n");
    return error;
}

static uint32_t
nb_load_balancer_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_load_balancer_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_logical_switch_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_logical_switch_ldap_insert,
        nb_logical_switch_ldap_select,
        nb_logical_switch_ldap_delete,
        nb_logical_switch_ldap_update,
        nb_logical_switch_ldap_get_column_set
    };
    VLOG_INFO("nb_logical_switch_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_logical_switch_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_LOGICAL_SWITCH_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_name = NULL;
    char *ovs_port_set = NULL;
    char *ovs_lb_set = NULL;
    char *ovs_acl_set = NULL;
    char *ovs_qos_set = NULL;
    char *ovs_dns_set = NULL;
    char *ovs_configs = NULL;
    char *ovs_external_ids = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_name = NULL;
    char *ovsdb_port_set = NULL;
    char *ovsdb_lb_set = NULL;
    char *ovsdb_acl_set = NULL;
    char *ovsdb_qos_set = NULL;
    char *ovsdb_dns_set = NULL;
    char *ovsdb_configs = NULL;
    char *ovsdb_external_ids = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_name, OVS_NAME);
    OvsAllocateString(&ovs_port_set, OVS_PORT_SET);
    OvsAllocateString(&ovs_lb_set, OVS_LB_SET);
    OvsAllocateString(&ovs_acl_set, OVS_ACL_SET);
    OvsAllocateString(&ovs_qos_set, OVS_QOS_SET);
    OvsAllocateString(&ovs_dns_set, OVS_DNS_SET);
    OvsAllocateString(&ovs_configs, OVS_CONFIGS);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_name, OVSDB_NAME);
    OvsAllocateString(&ovsdb_port_set, OVSDB_PORT_SET);
    OvsAllocateString(&ovsdb_lb_set, OVSDB_LB_SET);
    OvsAllocateString(&ovsdb_acl_set, OVSDB_ACL_SET);
    OvsAllocateString(&ovsdb_qos_set, OVSDB_QOS_SET);
    OvsAllocateString(&ovsdb_dns_set, OVSDB_DNS_SET);
    OvsAllocateString(&ovsdb_configs, OVSDB_CONFIGS);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_name, OVS_COLUMN_STRING, ovsdb_name, &ovsdb_type_string},
        {ovs_port_set, OVS_COLUMN_SET, ovsdb_port_set, &ovsdb_type_string_set},
        {ovs_lb_set, OVS_COLUMN_SET, ovsdb_lb_set, &ovsdb_type_string_set},
        {ovs_acl_set, OVS_COLUMN_SET, ovsdb_acl_set, &ovsdb_type_string_set},
        {ovs_qos_set, OVS_COLUMN_SET, ovsdb_qos_set, &ovsdb_type_string_set},
        {ovs_dns_set, OVS_COLUMN_SET, ovsdb_dns_set, &ovsdb_type_string_set},
        {ovs_configs, OVS_COLUMN_MAP, ovsdb_configs, &ovsdb_type_string_string_map},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_LOGICAL_SWITCH_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_logical_switch_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set
) {
    VLOG_INFO("nb_logical_switch_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
            result,
        povs_column_set,
        NB_LOGICAL_SW_OBJ_CLASS_NAME
        );
    }

static uint32_t
nb_logical_switch_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_logical_switch_ldap_select called\n");
    return error;
}

static uint32_t
nb_logical_switch_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_logical_switch_ldap_delete called\n");
    return error;
}

static uint32_t
nb_logical_switch_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_logical_switch_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_logical_switch_port_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_logical_switch_port_ldap_insert,
        nb_logical_switch_port_ldap_select,
        nb_logical_switch_port_ldap_delete,
        nb_logical_switch_port_ldap_update,
        nb_logical_switch_port_ldap_get_column_set
    };
    VLOG_INFO("nb_logical_switch_port_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_logical_switch_port_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_LOGICAL_SW_PORT_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_name = NULL;
    char *ovs_logical_sw_port_ovs_type = NULL;
    char *ovs_addresses = NULL;
    char *ovs_logical_sw_port_ovs_security = NULL;
    char *ovs_parent_name = NULL;
    char *ovs_tag_request = NULL;
    char *ovs_tag = NULL;
    char *ovs_is_up = NULL;
    char *ovs_is_enabled = NULL;
    char *ovs_dyn_addresses = NULL;
    char *ovs_dhcp_v4 = NULL;
    char *ovs_dhcp_v6 = NULL;
    char *ovs_options = NULL;
    char *ovs_external_ids = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_name = NULL;
    char *ovsdb_logical_sw_port_ovs_type = NULL;
    char *ovsdb_addresses = NULL;
    char *ovsdb_logical_sw_port_ovs_security = NULL;
    char *ovsdb_parent_name = NULL;
    char *ovsdb_tag_request = NULL;
    char *ovsdb_tag = NULL;
    char *ovsdb_is_up = NULL;
    char *ovsdb_is_enabled = NULL;
    char *ovsdb_dyn_addresses = NULL;
    char *ovsdb_dhcp_v4 = NULL;
    char *ovsdb_dhcp_v6 = NULL;
    char *ovsdb_options = NULL;
    char *ovsdb_external_ids = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_name, OVS_NAME);
    OvsAllocateString(&ovs_logical_sw_port_ovs_type, OVS_LOGICAL_SW_PORT_OVS_TYPE);
    OvsAllocateString(&ovs_addresses, OVS_ADDRESSES);
    OvsAllocateString(&ovs_logical_sw_port_ovs_security, OVS_LOGICAL_SW_PORT_OVS_SECURITY);
    OvsAllocateString(&ovs_parent_name, OVS_PARENT_NAME);
    OvsAllocateString(&ovs_tag_request, OVS_TAG_REQUEST);
    OvsAllocateString(&ovs_tag, OVS_TAG);
    OvsAllocateString(&ovs_is_up, OVS_IS_UP);
    OvsAllocateString(&ovs_is_enabled, OVS_IS_ENABLED);
    OvsAllocateString(&ovs_dyn_addresses, OVS_DYN_ADDRESSES);
    OvsAllocateString(&ovs_dhcp_v4, OVS_DHCP_V4);
    OvsAllocateString(&ovs_dhcp_v6, OVS_DHCP_V6);
    OvsAllocateString(&ovs_options, OVS_OPTIONS);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_name, OVSDB_NAME);
    OvsAllocateString(&ovsdb_logical_sw_port_ovs_type, OVSDB_LOGICAL_SW_PORT_OVS_TYPE);
    OvsAllocateString(&ovsdb_addresses, OVSDB_ADDRESSES);
    OvsAllocateString(&ovsdb_logical_sw_port_ovs_security, OVSDB_LOGICAL_SW_PORT_OVS_SECURITY);
    OvsAllocateString(&ovsdb_parent_name, OVSDB_PARENT_NAME);
    OvsAllocateString(&ovsdb_tag_request, OVSDB_TAG_REQUEST);
    OvsAllocateString(&ovsdb_tag, OVSDB_TAG);
    OvsAllocateString(&ovsdb_is_up, OVSDB_IS_UP);
    OvsAllocateString(&ovsdb_is_enabled, OVSDB_IS_ENABLED);
    OvsAllocateString(&ovsdb_dyn_addresses, OVSDB_DYN_ADDRESSES);
    OvsAllocateString(&ovsdb_dhcp_v4, OVSDB_DHCP_V4);
    OvsAllocateString(&ovsdb_dhcp_v6, OVSDB_DHCP_V6);
    OvsAllocateString(&ovsdb_options, OVSDB_OPTIONS);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_name, OVS_COLUMN_STRING, ovsdb_name, &ovsdb_type_string},
        {ovs_logical_sw_port_ovs_type, OVS_COLUMN_STRING, ovsdb_logical_sw_port_ovs_type, &ovsdb_type_string},
        {ovs_addresses, OVS_COLUMN_SET, ovsdb_addresses, &ovsdb_type_string_set},
        {ovs_logical_sw_port_ovs_security, OVS_COLUMN_SET, ovsdb_logical_sw_port_ovs_security, &ovsdb_type_string_set},
        {ovs_parent_name, OVS_COLUMN_STRING, ovsdb_parent_name, &ovsdb_type_string},
        {ovs_tag_request, OVS_COLUMN_INTEGER, ovsdb_tag_request, &ovsdb_type_integer},
        {ovs_tag, OVS_COLUMN_INTEGER, ovsdb_tag, &ovsdb_type_integer},
        {ovs_is_up, OVS_COLUMN_BOOLEAN, ovsdb_is_up, &ovsdb_type_boolean},
        {ovs_is_enabled, OVS_COLUMN_BOOLEAN, ovsdb_is_enabled, &ovsdb_type_boolean},
        {ovs_dyn_addresses, OVS_COLUMN_STRING, ovsdb_dyn_addresses, &ovsdb_type_string},
        {ovs_dhcp_v4, OVS_COLUMN_SET, ovsdb_dhcp_v4, &ovsdb_type_string_set},
        {ovs_dhcp_v6, OVS_COLUMN_SET, ovsdb_dhcp_v6, &ovsdb_type_string_set},
        {ovs_options, OVS_COLUMN_MAP, ovsdb_options, &ovsdb_type_string_string_map},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_LOGICAL_SW_PORT_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_logical_switch_port_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set
) {
    VLOG_INFO("nb_logical_switch_port_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
            result,
        povs_column_set,
        NB_LOGICAL_SW_PORT_OBJ_CLASS_NAME
        );
    }

static uint32_t
nb_logical_switch_port_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_logical_switch_port_ldap_select called\n");
    return error;
}

static uint32_t
nb_logical_switch_port_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_logical_switch_port_ldap_delete called\n");
    return error;
}

static uint32_t
nb_logical_switch_port_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_logical_switch_port_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_dhcp_options_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_dhcp_options_ldap_insert,
        nb_dhcp_options_ldap_select,
        nb_dhcp_options_ldap_delete,
        nb_dhcp_options_ldap_update,
        nb_dhcp_options_ldap_get_column_set
    };
    VLOG_INFO("nb_dhcp_options_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_dhcp_options_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_DHCP_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_cidr = NULL;
    char *ovs_options = NULL;
    char *ovs_external_ids = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_cidr = NULL;
    char *ovsdb_options = NULL;
    char *ovsdb_external_ids = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_cidr, OVS_CIDR);
    OvsAllocateString(&ovs_options, OVS_OPTIONS);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_cidr, OVSDB_CIDR);
    OvsAllocateString(&ovsdb_options, OVSDB_OPTIONS);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_cidr, OVS_COLUMN_STRING, ovsdb_cidr, &ovsdb_type_string},
        {ovs_options, OVS_COLUMN_MAP, ovsdb_options, &ovsdb_type_string_string_map},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_DHCP_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_dhcp_options_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set
) {
    VLOG_INFO("nb_dhcp_options_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
            result,
        povs_column_set,
        NB_DHCP_OBJ_CLASS_NAME
        );
    }

static uint32_t
nb_dhcp_options_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_dhcp_options_ldap_select called\n");
    return error;
}

static uint32_t
nb_dhcp_options_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_dhcp_options_ldap_delete called\n");
    return error;
}

static uint32_t
nb_dhcp_options_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_dhcp_options_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_qos_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_qos_ldap_insert,
        nb_qos_ldap_select,
        nb_qos_ldap_delete,
        nb_qos_ldap_update,
        nb_qos_ldap_get_column_set
    };
    VLOG_INFO("nb_qos_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_qos_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_QOS_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_direction = NULL;
    char *ovs_match = NULL;
    char *ovs_priority = NULL;
    char *ovs_dscp_action = NULL;
    char *ovs_external_ids = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_direction = NULL;
    char *ovsdb_match = NULL;
    char *ovsdb_priority = NULL;
    char *ovsdb_dscp_action = NULL;
    char *ovsdb_external_ids = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_direction, OVS_DIRECTION);
    OvsAllocateString(&ovs_match, OVS_MATCH);
    OvsAllocateString(&ovs_priority, OVS_PRIORITY);
    OvsAllocateString(&ovs_dscp_action, OVS_DSCP_ACTION);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_direction, OVSDB_DIRECTION);
    OvsAllocateString(&ovsdb_match, OVSDB_MATCH);
    OvsAllocateString(&ovsdb_priority, OVSDB_PRIORITY);
    OvsAllocateString(&ovsdb_dscp_action, OVSDB_DSCP_ACTION);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_direction, OVS_COLUMN_STRING, ovsdb_direction, &ovsdb_type_string},
        {ovs_match, OVS_COLUMN_STRING, ovsdb_match, &ovsdb_type_string},
        {ovs_priority, OVS_COLUMN_INTEGER, ovsdb_priority, &ovsdb_type_integer},
        {ovs_dscp_action, OVS_COLUMN_MAP, ovsdb_dscp_action, &ovsdb_type_string_integer_map},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_QOS_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_qos_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set
) {
    VLOG_INFO("nb_qos_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
            result,
        povs_column_set,
        NB_QOS_OBJ_CLASS_NAME
        );
    }

static uint32_t
nb_qos_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_qos_ldap_select called\n");
    return error;
}

static uint32_t
nb_qos_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_qos_ldap_delete called\n");
    return error;
}

static uint32_t
nb_qos_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_qos_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_dns_config_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_dns_config_ldap_insert,
        nb_dns_config_ldap_select,
        nb_dns_config_ldap_delete,
        nb_dns_config_ldap_update,
        nb_dns_config_ldap_get_column_set
    };
    VLOG_INFO("nb_dns_config_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_dns_config_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_DNS_RECORDS_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_external_ids = NULL;
    char *ovs_dns_records = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_external_ids = NULL;
    char *ovsdb_dns_records = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovs_dns_records, OVS_DNS_RECORDS);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_dns_records, OVSDB_DNS_RECORDS);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
        {ovs_dns_records, OVS_COLUMN_MAP, ovsdb_dns_records, &ovsdb_type_string_string_map},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_DNS_RECORDS_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_dns_config_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set
) {
    VLOG_INFO("nb_dns_config_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
            result,
        povs_column_set,
        NB_DNS_RECORDS_OBJ_CLASS_NAME
        );
    }

static uint32_t
nb_dns_config_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_dns_config_ldap_select called\n");
    return error;
}

static uint32_t
nb_dns_config_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_dns_config_ldap_delete called\n");
    return error;
}

static uint32_t
nb_dns_config_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_dns_config_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_acl_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_acl_ldap_insert,
        nb_acl_ldap_select,
        nb_acl_ldap_delete,
        nb_acl_ldap_update,
        nb_acl_ldap_get_column_set
    };
    VLOG_INFO("nb_acl_init called\n");
    return ldap_fn_table;
}

static
struct ovs_column_set
nb_acl_ldap_get_column_set(void) {
    struct ovs_column *columns = NULL;
    OvsAllocateMemory((void **) &columns, NB_ACL_COL_COUNT * sizeof(*columns));

    char *ldap_cn = NULL;
    char *ovs_name = NULL;
    char *ovs_acl_action = NULL;
    char *ovs_direction = NULL;
    char *ovs_match = NULL;
    char *ovs_external_ids = NULL;
    char *ovs_acl_log = NULL;
    char *ovs_priority = NULL;
    char *ovs_acl_severity = NULL;
    char *ovsdb_uuid = NULL;
    char *ovsdb_name = NULL;
    char *ovsdb_acl_action = NULL;
    char *ovsdb_direction = NULL;
    char *ovsdb_match = NULL;
    char *ovsdb_external_ids = NULL;
    char *ovsdb_acl_log = NULL;
    char *ovsdb_priority = NULL;
    char *ovsdb_acl_severity = NULL;

    OvsAllocateString(&ldap_cn, LDAP_CN);
    OvsAllocateString(&ovs_name, OVS_NAME);
    OvsAllocateString(&ovs_acl_action, OVS_ACL_ACTION);
    OvsAllocateString(&ovs_direction, OVS_DIRECTION);
    OvsAllocateString(&ovs_match, OVS_MATCH);
    OvsAllocateString(&ovs_external_ids, OVS_EXTERNAL_IDS);
    OvsAllocateString(&ovs_acl_log, OVS_ACL_LOG);
    OvsAllocateString(&ovs_priority, OVS_PRIORITY);
    OvsAllocateString(&ovs_acl_severity, OVS_ACL_SEVERITY);
    OvsAllocateString(&ovsdb_uuid, OVSDB_UUID);
    OvsAllocateString(&ovsdb_name, OVSDB_NAME);
    OvsAllocateString(&ovsdb_acl_action, OVSDB_ACL_ACTION);
    OvsAllocateString(&ovsdb_direction, OVSDB_DIRECTION);
    OvsAllocateString(&ovsdb_match, OVSDB_MATCH);
    OvsAllocateString(&ovsdb_external_ids, OVSDB_EXTERNAL_IDS);
    OvsAllocateString(&ovsdb_acl_log, OVSDB_ACL_LOG);
    OvsAllocateString(&ovsdb_priority, OVSDB_PRIORITY);
    OvsAllocateString(&ovsdb_acl_severity, OVSDB_ACL_SEVERITY);

    struct ovs_column columns_data[] = {
        {ldap_cn, OVS_COLUMN_UUID, ovsdb_uuid, &ovsdb_type_uuid},
        {ovs_name, OVS_COLUMN_STRING, ovsdb_name, &ovsdb_type_string},
        {ovs_acl_action, OVS_COLUMN_STRING, ovsdb_acl_action, &ovsdb_type_string},
        {ovs_direction, OVS_COLUMN_STRING, ovsdb_direction, &ovsdb_type_string},
        {ovs_match, OVS_COLUMN_STRING, ovsdb_match, &ovsdb_type_string},
        {ovs_external_ids, OVS_COLUMN_MAP, ovsdb_external_ids, &ovsdb_type_string_string_map},
        {ovs_acl_log, OVS_COLUMN_BOOLEAN, ovsdb_acl_log, &ovsdb_type_boolean},
        {ovs_priority, OVS_COLUMN_INTEGER, ovsdb_priority, &ovsdb_type_integer},
        {ovs_acl_severity, OVS_COLUMN_STRING, ovsdb_acl_severity, &ovsdb_type_string},
    };
    memcpy(columns, columns_data, sizeof(columns_data));
    struct ovs_column_set ovs_column_set = {columns, NB_ACL_COL_COUNT};
    return ovs_column_set;
}

static uint32_t
nb_acl_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result,
    const struct ovs_column_set *povs_column_set
) {
    VLOG_INFO("nb_acl_ldap_insert called\n");

    return nb_ldap_insert_helper(
        pContext,
        parser,
            result,
        povs_column_set,
        NB_ACL_OBJ_CLASS_NAME
        );
    }

static uint32_t
nb_acl_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_acl_ldap_select called\n");
    return error;
}

static uint32_t
nb_acl_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_acl_ldap_delete called\n");
    return error;
}

static uint32_t
nb_acl_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED,
    const struct ovs_column_set *povs_column_set OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
    VLOG_INFO("nb_acl_ldap_update called\n");
    return error;
}

uint32_t
get_obj_function_table_from_table(
    LDAP_FUNCTION_TABLE *pldap_obj_fn_table,
    struct ovsdb_parser *parser
)
{
    const char *table_name;
    const struct json *json;
    uint32_t error = 0;
    size_t i;

    json = ovsdb_parser_member(parser, "table", OP_ID);
    if (!json) {
        error = ERROR_OVS_INVALID_PARAMETER;
        goto error;
    }
    table_name = json_string(json);

    struct dn_name_t {
        const char *table_name;
        LDAP_FUNCTION_TABLE (*dn_init)(void);
    };

    static const struct dn_name_t dn_names[] = {
        {NB_GLOBAL, nb_north_bound_init},
        {CONNECTION, nb_connection_init},
        {SSL, nb_ssl_init},
        {ADDRESS_SET, nb_address_set_init},
        {LOGICAL_ROUTER, nb_logical_router_init},
        {LOGICAL_ROUTER_PORT, nb_logical_router_port_init},
        {GATEWAY_CHASSIS, nb_gateway_chassis_init},
        {NAT, nb_nat_init},
        {LOGICAL_ROUTER_STATIC_ROUTE, nb_logical_router_static_route_init},
        {LOAD_BALANCER, nb_load_balancer_init},
        {LOGICAL_SWITCH, nb_logical_switch_init},
        {LOGICAL_SWITCH_PORT, nb_logical_switch_port_init},
        {DHCP_OPTIONS, nb_dhcp_options_init},
        {QOS, nb_qos_init},
        {DNS, nb_dns_config_init},
        {ACL, nb_acl_init}
    };

    error = ERROR_OVS_INVALID_PARAMETER;
    for (i = 0; i < ARRAY_SIZE(dn_names); i++) {
        if (!strcmp(dn_names[i].table_name, table_name)) {
            error = 0;
            *pldap_obj_fn_table =  dn_names[i].dn_init();
        }
    }

error:
    return error;
}

uint32_t
ldap_open_context(DB_INTERFACE_CONTEXT_T **ppContext, int argc, ...)
{
    uint32_t err = 0;
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
    err = OvsCreateConnection(
        LDAP_SERVER,
        LDAP_USER,
        LDAP_PASSWORD,
        &pContext->ldap_conn
    );
    BAIL_ON_ERROR(err);
    *ppContext = pContext;

cleanup:
    return err;

error:
    VLOG_INFO("LDAP create connection ERROR\n");
    ldap_close_context(pContext);
    goto cleanup;

}

uint32_t
ldap_close_context(DB_INTERFACE_CONTEXT_T *pContext)
{
    if (pContext) {
        OvsFreeConnection(pContext->ldap_conn);
        free(pContext);
    }
    return 0;
}

uint32_t
db_provider_init(DB_FUNCTION_TABLE **ppLdapFnTable)
{
    DB_FUNCTION_TABLE *pLdapFnTable = NULL;

    pLdapFnTable = xzalloc(sizeof *pLdapFnTable);

    pLdapFnTable->pfn_db_open_context = &ldap_open_context;
    pLdapFnTable->pfn_db_close_context = &ldap_close_context;
    pLdapFnTable->pfn_db_execute_compose = &ldap_execute_compose_intf;
    pLdapFnTable->pfn_db_txn_propose_commit = &ldap_txn_propose_commit_intf;
    pLdapFnTable->pfn_db_txn_progress_is_complete =
        &ldap_txn_progress_is_complete_intf;
    pLdapFnTable->pfn_db_monitor_create = &ldap_monitor_create_intf;
    pLdapFnTable->pfn_db_monitor_cond_change = &ldap_monitor_cond_change_intf;
    pLdapFnTable->pfn_db_monitor_cancel = &ldap_monitor_cancel_intf;
    pLdapFnTable->pfn_db_initialize_state = &ldap_initialize_state_intf;
    pLdapFnTable->pfn_db_setup_ssl_configuration =
        &ldap_setup_ssl_configuration_intf;
    pLdapFnTable->pfn_db_unixctl_cmd_register =
        &ldap_unixctl_cmd_register_intf;
    pLdapFnTable->pfn_db_memory_usage_report = &ldap_memory_usage_report_intf;
    pLdapFnTable->pfn_db_process_rpc_requests =
        &ldap_process_rpc_requests_intf;
    pLdapFnTable->pfn_db_update_servers_and_wait =
        &ldap_update_servers_and_wait_intf;
    pLdapFnTable->pfn_db_terminate_state = &ldap_terminate_state_intf;
    pLdapFnTable->pfn_db_add_session_to_context =
        &ldap_add_session_to_context_intf;
    pLdapFnTable->pfn_db_add_db_to_context = &ldap_add_db_to_context_intf;
    pLdapFnTable->pfn_db_create_trigger = &ldap_create_trigger_intf;

    *ppLdapFnTable = pLdapFnTable;

    return 0;
}

void
db_provider_shutdown(DB_FUNCTION_TABLE *pLdapFnTable)
{
    if (pLdapFnTable) {
        free(pLdapFnTable);
    }
}

static
void
ovs_column_set_cleanup(const struct ovs_column_set *povs_column_set) {
    size_t i;
    for (i = 0; i < povs_column_set->n_columns; i++) {
        OvsFreeString(povs_column_set->ovs_columns[i].ldap_column_name);
        OvsFreeString(povs_column_set->ovs_columns[i].ovsdb_column_name);
    }
    OvsFreeMemory(povs_column_set->ovs_columns);
}

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
)
{
    size_t n_operations;
    size_t i;
    uint32_t error;
    struct ovsdb_txn *txn = NULL;
    struct json *results = NULL;

    txn = ovsdb_execute_compose(
        pContext->db, pContext->session, params, pContext->read_only, role, id,
        elapsed_msec, timeout_msec, durable, resultsp
    );

    results = json_array_create_empty();

    if (txn != NULL) {
        n_operations = params->array.n - 1;

        for (i = 1; i <= n_operations; i++) {
            struct json *operation = params->array.elems[i];
            const struct json *op;
            struct json *result;
            LDAP_FUNCTION_TABLE ldap_obj_fn_table;
            const char *op_name = NULL;
            bool ro = false;
            struct ovsdb_parser parser;

            ovsdb_parser_init(&parser, operation,
                              "ovsdb operation %"PRIuSIZE" or %"PRIuSIZE, i,
                              n_operations);
            op = ovsdb_parser_member(&parser, "op", OP_ID);
            result = json_object_create();
            if (op) {
                op_name = json_string(op);
                error = get_obj_function_table_from_table(&ldap_obj_fn_table, &parser);
                if (error) {
                    continue;
                }
                FN_LDAP_OPERATION *pfn_ldap_operation = lookup_ldap_operation(
                    &ldap_obj_fn_table,
                    op_name,
                    &ro
                );
                if (pfn_ldap_operation) {
                    const struct ovs_column_set ovs_column_set =
                        ldap_obj_fn_table.pfn_ldap_get_column_set();
                    error = pfn_ldap_operation(
                        pContext,
                        &parser,
                        result,
                        &ovs_column_set
                    );
                    ovs_column_set_cleanup(&ovs_column_set);
                    if (error) {
                        VLOG_INFO("pfn_ldap_operation encountered an error %d\n", error);
                    }
                } else {
                    VLOG_INFO("No pfn_ldap_operation found for op:%s\n", op_name);
                }
            }
            json_array_add(results, result);
        }
    }

    return txn;
}

struct ovsdb_txn_progress *
ldap_txn_propose_commit_intf(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_txn *txn,
    bool durable
)
{
    return ovsdb_txn_propose_commit(txn, durable);
}

bool ldap_txn_progress_is_complete_intf(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    const struct ovsdb_txn_progress *p
)
{
    return ovsdb_txn_progress_is_complete(p);
}

struct jsonrpc_msg *
ldap_monitor_create_intf(PDB_INTERFACE_CONTEXT_T pContext,
    struct json *params, enum ovsdb_monitor_version version, struct json *id)
{
    struct ovsdb_jsonrpc_session *s = pContext->jsonrpc_session;
    struct ovsdb *db = pContext->db;

    return ovsdb_jsonrpc_monitor_create(s, db, params, version, id);
}

struct jsonrpc_msg *
ldap_monitor_cond_change_intf(PDB_INTERFACE_CONTEXT_T pContext,
    struct json *params, struct json *id)
{
    return ovsdb_jsonrpc_monitor_cond_change(pContext->jsonrpc_session, params,
                                             id);
}

struct jsonrpc_msg *
ldap_monitor_cancel_intf(PDB_INTERFACE_CONTEXT_T pContext,
    struct json_array *params, struct json *id)
{
    return ovsdb_jsonrpc_monitor_cancel(pContext->jsonrpc_session, params, id);
}


uint32_t
ldap_initialize_state_intf(
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
ldap_setup_ssl_configuration_intf(
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
ldap_unixctl_cmd_register_intf(
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
    char *sync_from = NULL;
    if (pContext->server_cfg->sync_from) {
        sync_from = *(pContext->server_cfg->sync_from);
    }
    char *sync_exclude = NULL;
    if (pContext->server_cfg->sync_exclude) {
        sync_exclude = *(pContext->server_cfg->sync_exclude);
    }
    struct shash *all_dbs = pContext->server_cfg->all_dbs;

    if (*is_backup) {
        const struct uuid *server_uuid;
        server_uuid = ovsdb_jsonrpc_server_get_uuid(jsonrpc);
        ovsdb_replication_init(sync_from, sync_exclude, all_dbs, server_uuid);
    }

    return 0;
}

uint32_t
ldap_memory_usage_report_intf(
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
ldap_process_rpc_requests_intf(
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
ldap_update_servers_and_wait_intf(
    DB_FUNCTION_TABLE *pDbFnTable,
    PDB_INTERFACE_CONTEXT_T pContext,
    struct unixctl_server *unixctl,
    struct process *run_process
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
ldap_terminate_state_intf(
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
ldap_add_session_to_context_intf(
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
ldap_add_db_to_context_intf(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb *ovsdb
) {
    pContext->db = ovsdb;

    return 0;
}

uint32_t
ldap_create_trigger_intf(
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
