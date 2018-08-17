#include <config.h> // every C source file must include this

#include "ldap-provider.h"

VLOG_DEFINE_THIS_MODULE(ldap_provider)

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
        nb_north_bound_ldap_update
    };
    VLOG_INFO("nb_north_bound_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_north_bound_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_north_bound_ldap_insert called\n");
    return error;
}

static uint32_t
nb_north_bound_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_north_bound_ldap_select called\n");
    return error;
}

static uint32_t
nb_north_bound_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_north_bound_ldap_delete called\n");
    return error;
}

static uint32_t
nb_north_bound_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_north_bound_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_connection_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_connection_ldap_insert,
        nb_connection_ldap_select,
        nb_connection_ldap_delete,
        nb_connection_ldap_update
    };
    VLOG_INFO("nb_connection_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_connection_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_connection_ldap_insert called\n");
    return error;
}

static uint32_t
nb_connection_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_connection_ldap_select called\n");
    return error;
}

static uint32_t
nb_connection_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_connection_ldap_delete called\n");
    return error;
}

static uint32_t
nb_connection_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_connection_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_ssl_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_ssl_ldap_insert,
        nb_ssl_ldap_select,
        nb_ssl_ldap_delete,
        nb_ssl_ldap_update
    };
    VLOG_INFO("nb_ssl_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_ssl_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_ssl_ldap_insert called\n");
    return error;
}

static uint32_t
nb_ssl_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_ssl_ldap_select called\n");
    return error;
}

static uint32_t
nb_ssl_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_ssl_ldap_delete called\n");
    return error;
}

static uint32_t
nb_ssl_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_ssl_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_address_set_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_address_set_ldap_insert,
        nb_address_set_ldap_select,
        nb_address_set_ldap_delete,
        nb_address_set_ldap_update
    };
    VLOG_INFO("nb_address_set_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_address_set_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_address_set_ldap_insert called\n");
    return error;
}

static uint32_t
nb_address_set_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_address_set_ldap_select called\n");
    return error;
}

static uint32_t
nb_address_set_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_address_set_ldap_delete called\n");
    return error;
}

static uint32_t
nb_address_set_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_address_set_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_logical_router_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_logical_router_ldap_insert,
        nb_logical_router_ldap_select,
        nb_logical_router_ldap_delete,
        nb_logical_router_ldap_update
    };
    VLOG_INFO("nb_logical_router_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_logical_router_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_router_ldap_insert called\n");
    return error;
}

static uint32_t
nb_logical_router_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_router_ldap_select called\n");
    return error;
}

static uint32_t
nb_logical_router_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;

    return error;
}

static uint32_t
nb_logical_router_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_router_ldap_update called\n");

    return error;
}

LDAP_FUNCTION_TABLE
nb_logical_router_port_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_logical_router_port_ldap_insert,
        nb_logical_router_port_ldap_select,
        nb_logical_router_port_ldap_delete,
        nb_logical_router_port_ldap_update
    };
    VLOG_INFO("nb_logical_router_port_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_logical_router_port_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_router_port_ldap_insert called\n");
    return error;
}

static uint32_t
nb_logical_router_port_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_router_port_ldap_select called\n");
    return error;
}

static uint32_t
nb_logical_router_port_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_router_port_ldap_delete called\n");
    return error;
}

static uint32_t
nb_logical_router_port_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_router_port_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_gateway_chassis_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_gateway_chassis_ldap_insert,
        nb_gateway_chassis_ldap_select,
        nb_gateway_chassis_ldap_delete,
        nb_gateway_chassis_ldap_update
    };
    VLOG_INFO("nb_gateway_chassis_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_gateway_chassis_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_gateway_chassis_ldap_insert called\n");
    return error;
}

static uint32_t
nb_gateway_chassis_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_gateway_chassis_ldap_select called\n");
    return error;
}

static uint32_t
nb_gateway_chassis_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_gateway_chassis_ldap_delete called\n");
    return error;
}

static uint32_t
nb_gateway_chassis_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_gateway_chassis_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_nat_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_nat_ldap_insert,
        nb_nat_ldap_select,
        nb_nat_ldap_delete,
        nb_nat_ldap_update
    };
    VLOG_INFO("nb_nat_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_nat_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_nat_ldap_insert called\n");
    return error;
}

static uint32_t
nb_nat_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_nat_ldap_select called\n");
    return error;
}

static uint32_t
nb_nat_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_nat_ldap_delete called\n");
    return error;
}

static uint32_t
nb_nat_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_nat_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_logical_router_static_route_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_logical_router_static_route_ldap_insert,
        nb_logical_router_static_route_ldap_select,
        nb_logical_router_static_route_ldap_delete,
        nb_logical_router_static_route_ldap_update
    };
    VLOG_INFO("nb_logical_router_static_route_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_logical_router_static_route_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_router_static_route_ldap_insert called\n");
    return error;
}

static uint32_t
nb_logical_router_static_route_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_router_static_route_ldap_select called\n");
    return error;
}

static uint32_t
nb_logical_router_static_route_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_router_static_route_ldap_delete called\n");
    return error;
}

static uint32_t
nb_logical_router_static_route_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_router_static_route_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_load_balancer_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_load_balancer_ldap_insert,
        nb_load_balancer_ldap_select,
        nb_load_balancer_ldap_delete,
        nb_load_balancer_ldap_update
    };
    VLOG_INFO("nb_load_balancer_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_load_balancer_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_load_balancer_ldap_insert called\n");
    return error;
}

static uint32_t
nb_load_balancer_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_load_balancer_ldap_select called\n");
    return error;
}

static uint32_t
nb_load_balancer_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_load_balancer_ldap_delete called\n");
    return error;
}

static uint32_t
nb_load_balancer_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_load_balancer_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_logical_switch_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_logical_switch_ldap_insert,
        nb_logical_switch_ldap_select,
        nb_logical_switch_ldap_delete,
        nb_logical_switch_ldap_update
    };
    VLOG_INFO("nb_logical_switch_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_logical_switch_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_switch_ldap_insert called\n");
    return error;
}

static uint32_t
nb_logical_switch_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_switch_ldap_select called\n");
    return error;
}

static uint32_t
nb_logical_switch_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_switch_ldap_delete called\n");
    return error;
}

static uint32_t
nb_logical_switch_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_switch_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_logical_switch_port_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_logical_switch_port_ldap_insert,
        nb_logical_switch_port_ldap_select,
        nb_logical_switch_port_ldap_delete,
        nb_logical_switch_port_ldap_update
    };
    VLOG_INFO("nb_logical_switch_port_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_logical_switch_port_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_switch_port_ldap_insert called\n");
    return error;
}

static uint32_t
nb_logical_switch_port_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_switch_port_ldap_select called\n");
    return error;
}

static uint32_t
nb_logical_switch_port_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_switch_port_ldap_delete called\n");
    return error;
}

static uint32_t
nb_logical_switch_port_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_logical_switch_port_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_dhcp_options_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_dhcp_options_ldap_insert,
        nb_dhcp_options_ldap_select,
        nb_dhcp_options_ldap_delete,
        nb_dhcp_options_ldap_update
    };
    VLOG_INFO("nb_dhcp_options_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_dhcp_options_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_dhcp_options_ldap_insert called\n");
    return error;
}

static uint32_t
nb_dhcp_options_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_dhcp_options_ldap_select called\n");
    return error;
}

static uint32_t
nb_dhcp_options_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_dhcp_options_ldap_delete called\n");
    return error;
}

static uint32_t
nb_dhcp_options_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_dhcp_options_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_qos_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_qos_ldap_insert,
        nb_qos_ldap_select,
        nb_qos_ldap_delete,
        nb_qos_ldap_update
    };
    VLOG_INFO("nb_qos_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_qos_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_qos_ldap_insert called\n");
    return error;
}

static uint32_t
nb_qos_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_qos_ldap_select called\n");
    return error;
}

static uint32_t
nb_qos_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_qos_ldap_delete called\n");
    return error;
}

static uint32_t
nb_qos_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_qos_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_dns_config_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_dns_config_ldap_insert,
        nb_dns_config_ldap_select,
        nb_dns_config_ldap_delete,
        nb_dns_config_ldap_update
    };
    VLOG_INFO("nb_dns_config_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_dns_config_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_dns_config_ldap_insert called\n");
    return error;
}

static uint32_t
nb_dns_config_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_dns_config_ldap_select called\n");
    return error;
}

static uint32_t
nb_dns_config_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_dns_config_ldap_delete called\n");
    return error;
}

static uint32_t
nb_dns_config_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_dns_config_ldap_update called\n");
    return error;
}

LDAP_FUNCTION_TABLE
nb_acl_init(void) {
    LDAP_FUNCTION_TABLE ldap_fn_table = {
        nb_acl_ldap_insert,
        nb_acl_ldap_select,
        nb_acl_ldap_delete,
        nb_acl_ldap_update
    };
    VLOG_INFO("nb_acl_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_acl_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_acl_ldap_insert called\n");
    return error;
}

static uint32_t
nb_acl_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_acl_ldap_select called\n");
    return error;
}

static uint32_t
nb_acl_ldap_delete(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    VLOG_INFO("nb_acl_ldap_delete called\n");
    return error;
}

static uint32_t
nb_acl_ldap_update(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
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
        {"NB_Global", nb_north_bound_init},
        {"Connection", nb_connection_init},
        {"SSL", nb_ssl_init},
        {"Address_Set", nb_address_set_init},
        {"Logical_Router", nb_logical_router_init},
        {"Logical_Router_Port", nb_logical_router_port_init},
        {"Gateway_Chassis", nb_gateway_chassis_init},
        {"NAT", nb_nat_init},
        {"Logical_Router_Static_Route", nb_logical_router_static_route_init},
        {"Load_Balancer", nb_load_balancer_init},
        {"Logical_Switch", nb_logical_switch_init},
        {"Logical_Switch_Port", nb_logical_switch_port_init},
        {"DHCP_Options", nb_dhcp_options_init},
        {"QoS", nb_qos_init},
        {"DNS", nb_dns_config_init},
        {"ACL", nb_acl_init}
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
    pContext->jsonrpc_session = va_arg(argList, struct ovsdb_jsonrpc_session *);
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
    pLdapFnTable->pfn_db_monitor_create = &ldap_monitor_create_intf;
    pLdapFnTable->pfn_db_monitor_cond_change = &ldap_monitor_cond_change_intf;
    pLdapFnTable->pfn_db_monitor_cancel = &ldap_monitor_cancel_intf;

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
    size_t n_operations;
    size_t i;
    uint32_t error;
    struct ovsdb_txn *txn = NULL;

    txn = ovsdb_execute_compose(
        pContext->db, pContext->session, params, pContext->read_only, role, id,
        elapsed_msec, timeout_msec, durable, resultsp
    );

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
                    VLOG_INFO(
                        "get_obj_function_table_from_table encountered an error %d\n", 
                        error
                    );
                    continue;
                }
                FN_LDAP_OPERATION *pfn_ldap_operation = lookup_ldap_operation(
                    &ldap_obj_fn_table,
                    op_name,
                    &ro
                );
                if (pfn_ldap_operation) {
                    error = pfn_ldap_operation(pContext, &parser, result);
                    if (error) {
                        VLOG_INFO("pfn_ldap_operation encountered an error %d\n", error);
                    }
                } else {
                    VLOG_INFO("No pfn_ldap_operation found for op:%s\n", op_name);
                }
            }
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
