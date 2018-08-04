#include <config.h> // every C source file must include this

#include "ldap-provider.h"

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
 * Create a connection
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
ldap_open_context(DB_INTERFACE_CONTEXT_T **ppContext, ...) 
{
    uint32_t err = 0;
    va_list argList = { 0 };
    DB_INTERFACE_CONTEXT_T *pContext = NULL;

    pContext = xzalloc(sizeof *pContext);

    va_start(argList, ppContext);
    pContext->db = va_arg(argList, struct ovsdb *);
    pContext->session = va_arg(argList, struct ovsdb_session *);
    pContext->read_only = va_arg(argList, int);
    va_end(argList);
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
) 
{
    return ovsdb_execute_compose(
        pContext->db, pContext->session, params, pContext->read_only, role, id,
        elapsed_msec, timeout_msec, durable, resultsp
    );
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

