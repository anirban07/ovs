#include <config.h> // every C source file must include this

#include "ldap-provider.h"
#include "ovsdb-error.h"
#include "ovsdb-data.h"
#include <sys/time.h>

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
    struct ovs_column *pOvsColumn,
    struct ovsdb_datum *datum
) {
    uint32_t error = 0;
    char *pStr = NULL;
    ovs_set_t *povs_set = NULL;
    ovs_map_t *povs_map = NULL;

    char **modv;
    error = OvsAllocateMemory((void **) &modv, 2 * sizeof(char *));
    BAIL_ON_ERROR(error)

    switch (pOvsColumn->column_type) {
        case OVS_COLUMN_UUID :
            OvsAllocateString(
                &pStr,
                xasprintf(UUID_FMT, UUID_ARGS(&datum->keys->uuid))
            );
            error = ovs_get_str_sequence(
                pOvsColumn->pLDAPMod,
                modv,
                0,
                pOvsColumn->ldap_column_name,
                pStr
            );
            BAIL_ON_ERROR(error)
            break;
        case OVS_COLUMN_STRING :
            error = OvsAllocateString(&pStr, datum->keys->string);
            BAIL_ON_ERROR(error)
            error = ovs_get_str_sequence(
                pOvsColumn->pLDAPMod,
                modv,
                0,
                pOvsColumn->ldap_column_name,
                pStr
            );
            BAIL_ON_ERROR(error)
            break;
        case OVS_COLUMN_BOOLEAN :
            error = ovs_get_bool_sequence(
                pOvsColumn->pLDAPMod,
                modv,
                0,
                pOvsColumn->ldap_column_name,
                datum->keys->boolean
            );
            BAIL_ON_ERROR(error)
            break;
        case OVS_COLUMN_INTEGER :
            error = ovs_get_int_sequence(
                pOvsColumn->pLDAPMod,
                modv,
                0,
                pOvsColumn->ldap_column_name,
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
                pOvsColumn->pLDAPMod,
                modv,
                0,
                pOvsColumn->ldap_column_name,
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
                pOvsColumn->pLDAPMod,
                modv,
                0,
                pOvsColumn->ldap_column_name,
                povs_map,
                datum->n
            );
            BAIL_ON_ERROR(error)
            break;
        default :
            error = ERROR_OVS_INVALID_COLUMN_TYPE;
            goto error;
    }
error:
    destroy_ovs_map(povs_map, datum->n);
    destroy_ovs_set(povs_set, datum->n);
    return error;
}

static uint32_t ldap_default_fill_columns(
    struct ovs_column pOvsColumns[],
    size_t num_columns
) {
    uint32_t error = 0;
    size_t i;

    for (i = 0; i < num_columns; i++) {
        if (pOvsColumns[i].pLDAPMod->mod_type == 0) {
            struct ovsdb_datum default_datum;
            ovsdb_datum_init_default(&default_datum, pOvsColumns[i].pcolumn_ovsdb_type);
            // Default string of OVSDB is "", LDAP needs "null"
            if (pOvsColumns[i].column_type == OVS_COLUMN_STRING) {
                OvsFreeMemory(default_datum.keys->string);
                char *default_str = NULL;
                OvsAllocateString(&default_str, LDAP_DEFAULT_STRING);
                default_datum.keys->string = default_str;
            } else if (pOvsColumns[i].column_type == OVS_COLUMN_UUID) {
                uuid_generate(&default_datum.keys->uuid);
            }
            error = LDAPMod_creater(&pOvsColumns[i], &default_datum);
            BAIL_ON_ERROR(error)

            ovsdb_datum_destroy(&default_datum, pOvsColumns[i].pcolumn_ovsdb_type);
        }
    }
error:
    return error;
}

static uint32_t
ldap_parse_row(
    const struct json *row_json,
    struct ovs_column columns[],
    size_t num_columns
) {
    uint32_t error = 0;
    struct ovsdb_error *ovsdb_error = NULL;
    struct shash_node *node;
    if (row_json->type != JSON_OBJECT) {
        error = ERROR_OVS_JSON_SYNTAX_ERROR;
        BAIL_ON_ERROR(error);
    }
    SHASH_FOR_EACH (node, json_object(row_json)) {
        struct ovsdb_datum datum;
        struct ovs_column *pOvsColumn = NULL;
        const char *column_name = node->name;

        size_t i;
        for (i = 0; i < num_columns; i++) {
            if (!strcmp(columns[i].ovsdb_column_name, column_name)) {
                pOvsColumn = &columns[i];
            }
        }
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

        error = LDAPMod_creater(pOvsColumn, &datum);
        BAIL_ON_ERROR(error)
        ovsdb_datum_destroy(&datum, pOvsColumn->pcolumn_ovsdb_type);
    }
    error = ldap_default_fill_columns(columns, num_columns);

error:
    ovsdb_error_destroy(ovsdb_error);
    return error;
}

static void attrs_cleanup(LDAPMod *attrs[], size_t num_columns) {
    OvsFreeMemory(attrs[0]->mod_vals.modv_strvals);
    size_t i;
    for (i = 1; i <= num_columns; i++) {
        OvsFreeMemory(attrs[i]->mod_vals.modv_strvals[0]);
        OvsFreeMemory(attrs[i]->mod_vals.modv_strvals);
    }
}

static uint32_t ldap_object_class_helper(
    char *class_name,
    char *ldap_top,
    LDAPMod *pLDAPMod
) {
    uint32_t error = 0;
    char **modv;

    error = OvsAllocateMemory((void **) &modv, 3 * sizeof(char *));
    BAIL_ON_ERROR(error);

    modv[0] = class_name;
    modv[1] = ldap_top;

    pLDAPMod->mod_op = LDAP_MOD_ADD;
    pLDAPMod->mod_type = LDAP_OBJECT_CLASS;
    pLDAPMod->mod_values = modv;

error:
    return error;
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
    VLOG_INFO("nb_north_bound_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod ovsHVSequence = { 0 };
    LDAPMod ovsNBSequence = { 0 };
    LDAPMod ovsSBSequence = { 0 };
    LDAPMod connSequence = { 0 };
    LDAPMod externalIdsSeq = { 0 };
    LDAPMod sslConfigSeq = { 0 };

    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &ovsHVSequence,
        &ovsNBSequence,
        &ovsSBSequence,
        &connSequence,
        &externalIdsSeq,
        &sslConfigSeq,
        NULL
    };

    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_HV_SEQUENCE, OVS_COLUMN_INTEGER, &ovsHVSequence, OVSDB_HV_SEQUENCE, &ovsdb_type_integer},
        {OVS_NB_SEQUENCE, OVS_COLUMN_INTEGER, &ovsNBSequence, OVSDB_NB_SEQUENCE, &ovsdb_type_integer},
        {OVS_SB_SEQUENCE, OVS_COLUMN_INTEGER, &ovsSBSequence, OVSDB_SB_SEQUENCE, &ovsdb_type_integer},
        {OVS_CONNECTION_SET, OVS_COLUMN_SET, &connSequence, OVSDB_CONNECTION_SET, &ovsdb_type_string_set},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
        {OVS_SSL_CONFIG, OVS_COLUMN_STRING, &sslConfigSeq, OVSDB_SSL_CONFIG, &ovsdb_type_string},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_GLOBAL_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_GLOBAL_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)


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
        NB_GLOBAL_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_GLOBAL_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);

    return error;
}

static uint32_t
nb_north_bound_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    VLOG_INFO("nb_connection_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod targetSequence = { 0 };
    LDAPMod isConnectedSequence = { 0 };
    LDAPMod maxBackOffSeq = { 0 };
    LDAPMod inactivitySeq = { 0 };
    LDAPMod statusSeq = { 0 };
    LDAPMod configSetSeq = { 0 };
    LDAPMod externalIdsSeq = { 0 };
    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &targetSequence,
        &isConnectedSequence,
        &maxBackOffSeq,
        &inactivitySeq,
        &statusSeq,
        &configSetSeq,
        &externalIdsSeq,
        NULL
    };

    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_CONNECTION_TARGET, OVS_COLUMN_STRING, &targetSequence, OVSDB_CONNECTION_TARGET, &ovsdb_type_string},
        {OVS_CONN_IS_CONNECTED, OVS_COLUMN_BOOLEAN, &isConnectedSequence, OVSDB_CONN_IS_CONNECTED, &ovsdb_type_boolean},
        {OVS_MAX_BACK_OFF, OVS_COLUMN_INTEGER, &maxBackOffSeq, OVSDB_MAX_BACK_OFF, &ovsdb_type_integer},
        {OVS_INACTIVITY_PROBE, OVS_COLUMN_INTEGER, &inactivitySeq, OVSDB_INACTIVITY_PROBE, &ovsdb_type_integer},
        {OVS_STATUS, OVS_COLUMN_MAP, &statusSeq, OVSDB_STATUS, &ovsdb_type_string_string_map},
        {OVS_CONFIGS, OVS_COLUMN_MAP, &configSetSeq, OVSDB_CONFIGS, &ovsdb_type_string_string_map},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_CONN_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_CONN_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)

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
        NB_CONN_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_CONN_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);

    return error;
}

static uint32_t
nb_connection_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
        nb_ssl_ldap_update
    };
    VLOG_INFO("nb_ssl_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_ssl_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result
) {
    VLOG_INFO("nb_ssl_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod ovsPrivateKey = { 0 };
    LDAPMod ovsCertificate = { 0 };
    LDAPMod ovsCACertificate = { 0 };
    LDAPMod ovsBootstrapCACertificate = { 0 };
    LDAPMod ovsSSLProtocols = { 0 };
    LDAPMod ovsSSLCipers = { 0 };
    LDAPMod ovsExternalIds = { 0 };

    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &ovsPrivateKey,
        &ovsCertificate,
        &ovsCACertificate,
        &ovsBootstrapCACertificate,
        &ovsSSLProtocols,
        &ovsSSLCipers,
        &ovsExternalIds,
        NULL
    };

    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_SSL_PRIVATE_KEY, OVS_COLUMN_STRING, &ovsPrivateKey, OVSDB_SSL_PRIVATE_KEY, &ovsdb_type_string},
        {OVS_SSL_CERT, OVS_COLUMN_STRING, &ovsCertificate, OVSDB_SSL_CERT, &ovsdb_type_string},
        {OVS_SSL_CA_CERT, OVS_COLUMN_STRING, &ovsCACertificate, OVSDB_SSL_CA_CERT, &ovsdb_type_string},
        {OVS_SSL_BOOTSTRAP_CA_CERT, OVS_COLUMN_BOOLEAN, &ovsBootstrapCACertificate, OVSDB_SSL_BOOTSTRAP_CA_CERT, &ovsdb_type_boolean},
        {OVS_SSL_PROTOCOLS, OVS_COLUMN_STRING, &ovsSSLProtocols, OVSDB_SSL_PROTOCOLS, &ovsdb_type_string},
        {OVS_SSL_CIPHERS, OVS_COLUMN_STRING, &ovsSSLCipers, OVSDB_SSL_CIPHERS, &ovsdb_type_string},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &ovsExternalIds, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_SSL_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_SSL_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)

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
        NB_SSL_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_SSL_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);
    VLOG_INFO("logical rt insert returned error: %d\n", error);
    return error;
}

static uint32_t
nb_ssl_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
        nb_address_set_ldap_update
    };
    VLOG_INFO("nb_address_set_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_address_set_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result
) {
    VLOG_INFO("nb_address_set_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod externalIdsSeq = { 0 };
    LDAPMod addressSeq = { 0 };
    LDAPMod nameSeq = { 0 };

    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &externalIdsSeq,
        &addressSeq,
        &nameSeq,
        NULL
    };

    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_ADDRESSES, OVS_COLUMN_SET, &addressSeq, OVSDB_ADDRESSES, &ovsdb_type_string_set},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
        {OVS_NAME, OVS_COLUMN_STRING, &nameSeq, OVSDB_NAME, &ovsdb_type_string}
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_ADDRESS_SET_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_ADDRESS_SET_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)

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
        NB_ADDRESS_SET_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_ADDRESS_SET_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);

    return error;
}

static uint32_t
nb_address_set_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
        nb_logical_router_ldap_update
    };
    VLOG_INFO("nb_logical_router_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_logical_router_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result
) {
    VLOG_INFO("nb_logical_router_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod enabledSeq = { 0 };
    LDAPMod nameSeq = { 0 };
    LDAPMod portSeq = { 0 };
    LDAPMod staticRouteSeq = { 0 };
    LDAPMod natSeq = { 0 };
    LDAPMod lbSeq = { 0 };
    LDAPMod optionsSeq = { 0 };
    LDAPMod externalIdsSeq = { 0 };
    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &enabledSeq,
        &nameSeq,
        &portSeq,
        &staticRouteSeq,
        &natSeq,
        &lbSeq,
        &optionsSeq,
        &externalIdsSeq,
        NULL
    };
    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_IS_ENABLED, OVS_COLUMN_BOOLEAN, &enabledSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_boolean},
        {OVS_NAME, OVS_COLUMN_STRING, &nameSeq, OVSDB_NAME, &ovsdb_type_string},
        {OVS_PORT_SET, OVS_COLUMN_SET, &portSeq, OVSDB_PORT_SET, &ovsdb_type_string_set},
        {OVS_STATIC_ROUTES_SET, OVS_COLUMN_SET, &staticRouteSeq, OVSDB_STATIC_ROUTES_SET, &ovsdb_type_string_set},
        {OVS_NAT, OVS_COLUMN_STRING, &natSeq, OVSDB_NAT, &ovsdb_type_string},
        {OVS_LB_SET, OVS_COLUMN_SET, &lbSeq, OVSDB_LB_SET, &ovsdb_type_string_set},
        {OVS_OPTIONS, OVS_COLUMN_MAP, &optionsSeq, OVSDB_OPTIONS, &ovsdb_type_string_string_map},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_LOGICAL_RT_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_LOGICAL_RT_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)

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
        NB_LOGICAL_RT_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_LOGICAL_RT_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);

    return error;
}

static uint32_t
nb_logical_router_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
) {
    static uint32_t error = 0;
    result->count = 0;
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
    result->count = 0;
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
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result
) {
    VLOG_INFO("nb_logical_router_port_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod nameSeq = { 0 };
    LDAPMod macSeq = { 0 };
    LDAPMod enabledSeq = { 0 };
    LDAPMod externalIdsSeq = { 0 };
    LDAPMod gwChassisSeq = { 0 };
    LDAPMod networkSeq = { 0 };
    LDAPMod optionsSeq = { 0 };
    LDAPMod peerSeq = { 0 };
    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &nameSeq,
        &macSeq,
        &enabledSeq,
        &externalIdsSeq,
        &gwChassisSeq,
        &networkSeq,
        &optionsSeq,
        &peerSeq,
        NULL
    };
    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_NAME, OVS_COLUMN_STRING, &nameSeq, OVSDB_NAME, &ovsdb_type_string},
        {OVS_LR_MAC, OVS_COLUMN_STRING, &macSeq, OVSDB_LR_MAC, &ovsdb_type_string},
        {OVS_IS_ENABLED, OVS_COLUMN_BOOLEAN, &enabledSeq, OVSDB_IS_ENABLED, &ovsdb_type_boolean},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
        {OVS_GW_CHASSIS_SET, OVS_COLUMN_SET, &gwChassisSeq, OVSDB_GW_CHASSIS_SET, &ovsdb_type_string_set},
        {OVS_NETWORKS, OVS_COLUMN_STRING, &networkSeq, OVSDB_NETWORKS, &ovsdb_type_string},
        {OVS_OPTIONS, OVS_COLUMN_MAP, &optionsSeq, OVSDB_OPTIONS, &ovsdb_type_string_set},
        {OVS_LR_PEER, OVS_COLUMN_STRING, &peerSeq, OVSDB_LR_PEER, &ovsdb_type_string},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_LOGICAL_RT_PORT_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_LOGICAL_RT_PORT_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)

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
        NB_LOGICAL_RT_PORT_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_LOGICAL_RT_PORT_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);
    VLOG_INFO("logical rt port insert returned error: %d\n", error);
    return error;
}

static uint32_t
nb_logical_router_port_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
        nb_gateway_chassis_ldap_update
    };
    VLOG_INFO("nb_gateway_chassis_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_gateway_chassis_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result
) {
    VLOG_INFO("nb_gateway_chassis_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod nameSeq = { 0 };
    LDAPMod chassisNameSeq = { 0 };
    LDAPMod prioritySeq = { 0 };
    LDAPMod optionsSeq = { 0 };
    LDAPMod externalIdsSeq = { 0 };
    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &nameSeq,
        &chassisNameSeq,
        &prioritySeq,
        &optionsSeq,
        &externalIdsSeq,
        NULL
    };

    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_NAME, OVS_COLUMN_STRING, &nameSeq, OVSDB_NAME, &ovsdb_type_string},
        {OVS_GW_CHASSIS_OVS_NAME, OVS_COLUMN_STRING, &chassisNameSeq, OVSDB_GW_CHASSIS_OVS_NAME, &ovsdb_type_string},
        {OVS_PRIORITY, OVS_COLUMN_INTEGER, &prioritySeq, OVSDB_PRIORITY, &ovsdb_type_integer},
        {OVS_OPTIONS, OVS_COLUMN_MAP, &optionsSeq, OVSDB_OPTIONS, &ovsdb_type_string_string_map},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_GW_CHASSIS_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_GW_CHASSIS_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)

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
        NB_GW_CHASSIS_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_GW_CHASSIS_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);

    return error;
}

static uint32_t
nb_gateway_chassis_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
        nb_nat_ldap_update
    };
    VLOG_INFO("nb_nat_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_nat_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result
) {
    VLOG_INFO("nb_nat_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod externalIpSeq = { 0 };
    LDAPMod externalMacSeq = { 0 };
    LDAPMod logicalIpSeq = { 0 };
    LDAPMod logicalPortSeq = { 0 };
    LDAPMod typeSeq = { 0 };
    LDAPMod externalIdsSeq = { 0 };

    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &externalIpSeq,
        &externalMacSeq,
        &logicalIpSeq,
        &logicalPortSeq,
        &typeSeq,
        &externalIdsSeq,
        NULL
    };

    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_EXTERNAL_IP, OVS_COLUMN_STRING, &externalIpSeq, OVSDB_EXTERNAL_IP, &ovsdb_type_string},
        {OVS_EXTERNAL_MAC, OVS_COLUMN_STRING, &externalMacSeq, OVSDB_EXTERNAL_MAC, &ovsdb_type_string},
        {OVS_LOGICAL_IP, OVS_COLUMN_STRING, &logicalIpSeq, OVSDB_LOGICAL_IP, &ovsdb_type_string},
        {OVS_LOGICAL_PORT, OVS_COLUMN_STRING, &logicalPortSeq, OVSDB_LOGICAL_PORT, &ovsdb_type_string},
        {OVS_NAT_TYPE, OVS_COLUMN_STRING, &typeSeq, OVSDB_NAT_TYPE, &ovsdb_type_string},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_NAT_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_NAT_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)


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
        NB_NAT_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_NAT_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);

    return error;
}

static uint32_t
nb_nat_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
        nb_logical_router_static_route_ldap_update
    };
    VLOG_INFO("nb_logical_router_static_route_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_logical_router_static_route_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result
) {
    VLOG_INFO("nb_logical_router_static_route_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod policySeq = { 0 };
    LDAPMod nextHopSeq = { 0 };
    LDAPMod ipPrefixSeq = { 0 };
    LDAPMod outputPortSeq = { 0 };
    LDAPMod externalIdsSeq = { 0 };

    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &policySeq,
        &nextHopSeq,
        &ipPrefixSeq,
        &outputPortSeq,
        &externalIdsSeq,
        NULL
    };

    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_POLICY, OVS_COLUMN_STRING, &policySeq, OVSDB_POLICY, &ovsdb_type_string},
        {OVS_NEXT_HOP, OVS_COLUMN_STRING, &nextHopSeq, OVSDB_NEXT_HOP, &ovsdb_type_string},
        {OVS_IP_PREFIX, OVS_COLUMN_STRING, &ipPrefixSeq, OVSDB_IP_PREFIX, &ovsdb_type_string},
        {OVS_OUTPUT_PORT, OVS_COLUMN_STRING, &outputPortSeq, OVSDB_OUTPUT_PORT, &ovsdb_type_string},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_LOGICAL_RT_STATIC_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_LOGICAL_RT_STATIC_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)


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
        NB_LOGICAL_RT_STATIC_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_LOGICAL_RT_STATIC_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);

    return error;
}

static uint32_t
nb_logical_router_static_route_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
        nb_load_balancer_ldap_update
    };
    VLOG_INFO("nb_load_balancer_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_load_balancer_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result
) {
    VLOG_INFO("nb_load_balancer_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod nameSeq = { 0 };
    LDAPMod protocolSeq = { 0 };
    LDAPMod vipSeq = { 0 };
    LDAPMod externalIdsSeq = { 0 };

    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &nameSeq,
        &protocolSeq,
        &vipSeq,
        &externalIdsSeq,
        NULL
    };

    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_NAME, OVS_COLUMN_STRING, &nameSeq, OVSDB_NAME, &ovsdb_type_string},
        {OVS_PROTOCOL, OVS_COLUMN_STRING, &protocolSeq, OVSDB_PROTOCOL, &ovsdb_type_string},
        {OVS_VIPS, OVS_COLUMN_MAP, &vipSeq, OVSDB_VIPS, &ovsdb_type_string_string_map},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_LB_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_LB_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)

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
        NB_LB_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_LB_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);

    return error;
}

static uint32_t
nb_load_balancer_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
        nb_logical_switch_ldap_update
    };
    VLOG_INFO("nb_logical_switch_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_logical_switch_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result
) {
    VLOG_INFO("nb_logical_switch_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod nameSequence = { 0 };
    LDAPMod portSequence = { 0 };
    LDAPMod lbSequence = { 0 };
    LDAPMod aclSequence = { 0 };
    LDAPMod qosSequence = { 0 };
    LDAPMod dnsSequence = { 0 };
    LDAPMod externalIdsSeq = { 0 };
    LDAPMod configSetSeq = { 0 };
    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &nameSequence,
        &portSequence,
        &lbSequence,
        &aclSequence,
        &qosSequence,
        &dnsSequence,
        &configSetSeq,
        &externalIdsSeq,
        NULL
    };
    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_NAME, OVS_COLUMN_STRING, &nameSequence, OVSDB_NAME, &ovsdb_type_string},
        {OVS_PORT_SET, OVS_COLUMN_SET, &portSequence, OVSDB_PORT_SET, &ovsdb_type_string_set},
        {OVS_LB_SET, OVS_COLUMN_SET, &lbSequence, OVSDB_LB_SET, &ovsdb_type_string_set},
        {OVS_ACL_SET, OVS_COLUMN_SET, &aclSequence, OVSDB_ACL_SET, &ovsdb_type_string_set},
        {OVS_QOS_SET, OVS_COLUMN_SET, &qosSequence, OVSDB_QOS_SET, &ovsdb_type_string_set},
        {OVS_DNS_SET, OVS_COLUMN_SET, &dnsSequence, OVSDB_DNS_SET, &ovsdb_type_string_set},
        {OVS_CONFIGS, OVS_COLUMN_MAP, &configSetSeq, OVSDB_CONFIGS, &ovsdb_type_string_string_map},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        return ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_LOGICAL_SWITCH_COL_COUNT);
    BAIL_ON_ERROR(error)

    error = ldap_object_class_helper(
        NB_LOGICAL_SW_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)

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
        NB_LOGICAL_SW_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }
error:
    attrs_cleanup(attrs, NB_LOGICAL_SWITCH_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);
    VLOG_INFO("logical switch insert returned error: %d\n", error);
    return error;
}

static uint32_t
nb_logical_switch_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
        nb_logical_switch_port_ldap_update
    };
    VLOG_INFO("nb_logical_switch_port_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_logical_switch_port_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result
) {
    VLOG_INFO("nb_logical_switch_port_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod nameSeq = { 0 };
    LDAPMod typeSeq = { 0 };
    LDAPMod addressSeq = { 0 };
    LDAPMod portSecuritySeq = { 0 };
    LDAPMod parentNameSeq = { 0 };
    LDAPMod tagRequestSeq = { 0 };
    LDAPMod tagSeq = { 0 };
    LDAPMod isUpSeq = { 0 };
    LDAPMod isEnabledSeq = { 0 };
    LDAPMod dynAddressSeq = { 0 };
    LDAPMod dhcpV4Seq = { 0 };
    LDAPMod dhcpV6Seq = { 0 };
    LDAPMod optionsSeq = { 0 };
    LDAPMod externalIdsSeq = { 0 };

    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &nameSeq,
        &typeSeq,
        &addressSeq,
        &portSecuritySeq,
        &parentNameSeq,
        &tagRequestSeq,
        &tagSeq,
        &isUpSeq,
        &isEnabledSeq,
        &dynAddressSeq,
        &dhcpV4Seq,
        &dhcpV6Seq,
        &optionsSeq,
        &externalIdsSeq,
        NULL
    };

    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_NAME, OVS_COLUMN_STRING, &nameSeq, OVSDB_NAME, &ovsdb_type_string},
        {OVS_LOGICAL_SW_PORT_OVS_TYPE, OVS_COLUMN_STRING, &typeSeq, OVSDB_LOGICAL_SW_PORT_OVS_TYPE, &ovsdb_type_string},
        {OVS_ADDRESSES, OVS_COLUMN_SET, &addressSeq, OVSDB_ADDRESSES, &ovsdb_type_string_set},
        {OVS_LOGICAL_SW_PORT_OVS_SECURITY, OVS_COLUMN_SET, &portSecuritySeq, OVSDB_LOGICAL_SW_PORT_OVS_SECURITY, &ovsdb_type_string_set},
        {OVS_PARENT_NAME, OVS_COLUMN_STRING, &parentNameSeq, OVSDB_PARENT_NAME, &ovsdb_type_string},
        {OVS_TAG_REQUEST, OVS_COLUMN_INTEGER, &tagRequestSeq, OVSDB_TAG_REQUEST, &ovsdb_type_integer},
        {OVS_TAG, OVS_COLUMN_INTEGER, &tagSeq, OVSDB_TAG, &ovsdb_type_integer},
        {OVS_IS_UP, OVS_COLUMN_BOOLEAN, &isUpSeq, OVSDB_IS_UP, &ovsdb_type_boolean},
        {OVS_IS_ENABLED, OVS_COLUMN_BOOLEAN, &isEnabledSeq, OVSDB_IS_ENABLED, &ovsdb_type_boolean},
        {OVS_DYN_ADDRESSES, OVS_COLUMN_STRING, &dynAddressSeq, OVSDB_DYN_ADDRESSES, &ovsdb_type_string},
        {OVS_DHCP_V4, OVS_COLUMN_SET, &dhcpV4Seq, OVSDB_DHCP_V4, &ovsdb_type_string_set},
        {OVS_DHCP_V6, OVS_COLUMN_SET, &dhcpV6Seq, OVSDB_DHCP_V6, &ovsdb_type_string_set},
        {OVS_OPTIONS, OVS_COLUMN_MAP, &optionsSeq, OVSDB_OPTIONS, &ovsdb_type_string_string_map},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_LOGICAL_SW_PORT_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_LOGICAL_SW_PORT_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)

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
        NB_LOGICAL_SW_PORT_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_LOGICAL_SW_PORT_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);

    return error;
}

static uint32_t
nb_logical_switch_port_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
        nb_dhcp_options_ldap_update
    };
    VLOG_INFO("nb_dhcp_options_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_dhcp_options_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result
) {
    VLOG_INFO("nb_dhcp_options_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod cidr = { 0 };
    LDAPMod optionsSeq = { 0 };
    LDAPMod externalIdsSeq = { 0 };

    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &cidr,
        &optionsSeq,
        &externalIdsSeq,
        NULL
    };

    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_CIDR, OVS_COLUMN_STRING, &cidr, OVSDB_CIDR, &ovsdb_type_string},
        {OVS_OPTIONS, OVS_COLUMN_MAP, &optionsSeq, OVSDB_OPTIONS, &ovsdb_type_string_string_map},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_DHCP_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_DHCP_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)

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
        NB_DHCP_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_DHCP_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);

    return error;
}

static uint32_t
nb_dhcp_options_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
        nb_qos_ldap_update
    };
    VLOG_INFO("nb_qos_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_qos_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result
) {
    VLOG_INFO("nb_qos_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod directionSeq = { 0 };
    LDAPMod matchSeq = { 0 };
    LDAPMod prioritySeq = { 0 };
    LDAPMod externalIdsSeq = { 0 };
    LDAPMod dscpActionSeq = { 0 };

    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &directionSeq,
        &matchSeq,
        &prioritySeq,
        &externalIdsSeq,
        &dscpActionSeq,
        NULL
    };

    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_DIRECTION, OVS_COLUMN_STRING, &directionSeq, OVSDB_DIRECTION, &ovsdb_type_string},
        {OVS_MATCH, OVS_COLUMN_STRING, &matchSeq, OVSDB_MATCH, &ovsdb_type_string},
        {OVS_PRIORITY, OVS_COLUMN_INTEGER, &prioritySeq, OVSDB_PRIORITY, &ovsdb_type_integer},
        {OVS_DSCP_ACTION, OVS_COLUMN_MAP, &dscpActionSeq, OVSDB_DSCP_ACTION, &ovsdb_type_string_integer_map},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_QOS_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_QOS_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)

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
        NB_QOS_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_QOS_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);

    return error;
}

static uint32_t
nb_qos_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
        nb_dns_config_ldap_update
    };
    VLOG_INFO("nb_dns_config_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_dns_config_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result
) {
    VLOG_INFO("nb_dns_config_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod externalIdsSeq = { 0 };
    LDAPMod recordsSeq = { 0 };

    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &externalIdsSeq,
        &recordsSeq,
        NULL
    };

    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
        {OVS_DNS_RECORDS, OVS_COLUMN_MAP, &recordsSeq, OVSDB_DNS_RECORDS, &ovsdb_type_string_string_map},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_DNS_RECORDS_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_DNS_RECORDS_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)

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
        NB_DNS_RECORDS_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_DNS_RECORDS_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);

    return error;
}

static uint32_t
nb_dns_config_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
        nb_acl_ldap_update
    };
    VLOG_INFO("nb_acl_init called\n");
    return ldap_fn_table;
}

static uint32_t
nb_acl_ldap_insert(
    PDB_INTERFACE_CONTEXT_T pContext,
    struct ovsdb_parser *parser,
    struct json *result
) {
    VLOG_INFO("nb_acl_ldap_insert called\n");

    static uint32_t error = 0;
    const struct json *row_json;
    struct ovsdb_error *ovsdb_error = NULL;

    LDAPMod nbObjectClass = { 0 };
    LDAPMod cn = { 0 };
    LDAPMod nameSeq = { 0 };
    LDAPMod actionSeq = { 0 };
    LDAPMod directionSeq = { 0 };
    LDAPMod matchSeq = { 0 };
    LDAPMod externalIdsSeq = { 0 };
    LDAPMod logSeq = { 0 };
    LDAPMod prioritySeq = { 0 };
    LDAPMod severitySeq = { 0 };

    LDAPMod * attrs[] = {
        &nbObjectClass,
        &cn,
        &nameSeq,
        &actionSeq,
        &directionSeq,
        &matchSeq,
        &externalIdsSeq,
        &logSeq,
        &prioritySeq,
        &severitySeq,
        NULL
    };

    struct ovs_column columns[] = {
        {LDAP_CN, OVS_COLUMN_UUID, &cn, OVSDB_UUID, &ovsdb_type_uuid},
        {OVS_NAME, OVS_COLUMN_STRING, &nameSeq, OVSDB_NAME, &ovsdb_type_string},
        {OVS_ACL_ACTION, OVS_COLUMN_STRING, &actionSeq, OVSDB_ACL_ACTION, &ovsdb_type_string},
        {OVS_DIRECTION, OVS_COLUMN_STRING, &directionSeq, OVSDB_DIRECTION, &ovsdb_type_string},
        {OVS_MATCH, OVS_COLUMN_STRING, &matchSeq, OVSDB_MATCH, &ovsdb_type_string},
        {OVS_EXTERNAL_IDS, OVS_COLUMN_MAP, &externalIdsSeq, OVSDB_EXTERNAL_IDS, &ovsdb_type_string_string_map},
        {OVS_ACL_LOG, OVS_COLUMN_BOOLEAN, &logSeq, OVSDB_ACL_LOG, &ovsdb_type_boolean},
        {OVS_PRIORITY, OVS_COLUMN_INTEGER, &prioritySeq, OVSDB_PRIORITY, &ovsdb_type_integer},
        {OVS_ACL_SEVERITY, OVS_COLUMN_STRING, &severitySeq, OVSDB_ACL_SEVERITY, &ovsdb_type_string},
    };

    row_json = ovsdb_parser_member(parser, "row", OP_OBJECT);
    ovsdb_error = ovsdb_parser_get_error(parser);
    if (ovsdb_error) {
        error = ovsdb_error->errno_;
        BAIL_ON_ERROR(error)
    }
    error = ldap_parse_row(row_json, columns, NB_ACL_COL_COUNT);
    BAIL_ON_ERROR(error);

    error = ldap_object_class_helper(
        NB_ACL_OBJ_CLASS_NAME,
        LDAP_TOP,
        &nbObjectClass
    );
    BAIL_ON_ERROR(error)

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
        NB_ACL_OBJ_CLASS_NAME,
        cn.mod_vals.modv_strvals[0]
    );
    BAIL_ON_ERROR(error);

    if (!ovsdb_error) {
        json_object_put(
            result,
            "uuid",
            wrap_json(
                "uuid",
                json_string_create_nocopy(
                    cn.mod_vals.modv_strvals[0]
                )
            )
        );
    }

error:
    attrs_cleanup(attrs, NB_ACL_COL_COUNT);
    ovsdb_error_destroy(ovsdb_error);

    return error;
}

static uint32_t
nb_acl_ldap_select(
    PDB_INTERFACE_CONTEXT_T pContext OVS_UNUSED,
    struct ovsdb_parser *parser OVS_UNUSED,
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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
    struct json *result OVS_UNUSED
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

    if (pContext->session != NULL) {
        err = OvsCreateConnection(
            LDAP_SERVER,
            LDAP_USER,
            LDAP_PASSWORD,
            &pContext->ldap_conn
        );
    }
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
                    error = pfn_ldap_operation(pContext, &parser, result);
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
