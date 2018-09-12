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
#include "ovsdb-condition.h"
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

#define OVS_IS_NULL_OR_EMPTY_STRING(pStr) \
        (!(pStr) || !(*(pStr)))

#define BAIL_ON_ERROR(err) \
            if ((err) != 0) { \
                VLOG_INFO( \
                        "(%d) at %s:%d", \
                        err, \
                        __FILE__, \
                        __LINE__ \
                ); \
                goto error; \
            }



#define LDAP_PORT 389
#define LDAP_CN "cn"

#define ERROR_OVS_NOT_ENOUGH_MEMORY   800008
#define ERROR_OVS_INVALID_CONFIG      800009
#define ERROR_OVS_INVALID_PARAMETER   800019
#define ERROR_OVS_VSNPRINTF_FAILED    800048
#define ERROR_OVS_INVALID_COLUMN_TYPE 800100
#define ERROR_OVS_JSON_SYNTAX_ERROR   800101
#define ERROR_OVS_UNKNOWN_OVS_SET_TYPE  800102

#define DEFAULT_NAMING_CONTEXT "defaultNamingContext"

// #define LDAP_SERVER "10.118.100.227"
#define LDAP_SERVER "10.20.153.104"
#define LDAP_USER "administrator@lightwave.local"
#define LDAP_PASSWORD "Admin!23"

#define NB_GLOBAL "NB_Global"
#define CONNECTION "Connection"
#define SSL "SSL"
#define ADDRESS_SET "Address_Set"
#define LOGICAL_ROUTER "Logical_Router"
#define LOGICAL_ROUTER_PORT "Logical_Router_Port"
#define GATEWAY_CHASSIS "Gateway_Chassis"
#define NAT "NAT"
#define LOGICAL_ROUTER_STATIC_ROUTE "Logical_Router_Static_Route"
#define LOAD_BALANCER "Load_Balancer"
#define LOGICAL_SWITCH "Logical_Switch"
#define LOGICAL_SWITCH_PORT "Logical_Switch_Port"
#define DHCP_OPTIONS "DHCP_Options"
#define QOS "QoS"
#define DNS "DNS"
#define ACL "ACL"

#define NB_GLOBAL_COL_COUNT 7
#define NB_GLOBAL_OBJ_CLASS_NAME "ovsNorthBound"

#define NB_SSL_COL_COUNT 8
#define NB_SSL_OBJ_CLASS_NAME "ovsSSLConfig"

#define NB_CONN_COL_COUNT 8
#define NB_CONN_OBJ_CLASS_NAME "ovsConnection"

#define NB_DHCP_COL_COUNT 4
#define NB_DHCP_OBJ_CLASS_NAME "ovsDHCPOptions"

#define NB_QOS_COL_COUNT 6
#define NB_QOS_OBJ_CLASS_NAME "ovsQOSRule"

#define NB_DNS_RECORDS_COL_COUNT 3
#define NB_DNS_RECORDS_OBJ_CLASS_NAME "ovsDNSConfig"

#define NB_ACL_COL_COUNT 9
#define NB_ACL_OBJ_CLASS_NAME "ovsACL"

#define NB_LB_COL_COUNT 5
#define NB_LB_OBJ_CLASS_NAME "ovsLoadBalancer"

#define NB_NAT_COL_COUNT 6
#define NB_NAT_OBJ_CLASS_NAME "ovsNATRule"

#define NB_LOGICAL_SW_PORT_COL_COUNT 15
#define NB_LOGICAL_SW_PORT_OBJ_CLASS_NAME "ovsLogicalSwitchPort"

#define NB_GW_CHASSIS_COL_COUNT 6
#define NB_GW_CHASSIS_OBJ_CLASS_NAME "ovsGatewayChassis"

#define NB_LOGICAL_RT_STATIC_COL_COUNT 6
#define NB_LOGICAL_RT_STATIC_OBJ_CLASS_NAME "ovsLogicalRouterStaticRoute"

#define NB_ADDRESS_SET_COL_COUNT 4
#define NB_ADDRESS_SET_OBJ_CLASS_NAME "ovsAddressSet"

#define NB_GLOBAL_COL_COUNT 7
#define NB_GLOBAL_OBJ_CLASS_NAME "ovsNorthBound"

#define NB_DHCP_COL_COUNT 4
#define NB_DHCP_OBJ_CLASS_NAME "ovsDHCPOptions"

#define NB_LOGICAL_RT_COL_COUNT 9
#define NB_LOGICAL_RT_OBJ_CLASS_NAME "ovsLogicalRouter"

#define NB_LOGICAL_RT_PORT_COL_COUNT 9
#define NB_LOGICAL_RT_PORT_OBJ_CLASS_NAME "ovsLogicalRouterPort"

#define NB_LOGICAL_SWITCH_COL_COUNT 9
#define NB_LOGICAL_SW_OBJ_CLASS_NAME "ovsLogicalSwitch"

#define LDAP_OBJECT_CLASS "objectclass"
#define LDAP_TOP "top"

#define OVS_ACL_ACTION "ovsACLAction"
#define OVS_ACL_LOG "ovsACLLog"
#define OVS_ACL_SET "ovsACLSet"
#define OVS_ACL_SEVERITY "ovsACLSeverity"
#define OVS_ACTION "ovsAction"
#define OVS_ADDRESSES "ovsAddresses"
#define OVS_BANDWIDTH "ovsBandwidth"
#define OVS_CIDR "ovsCidr"
#define OVS_CONFIGS "ovsConfigSet"
#define OVS_CONN_IS_CONNECTED "ovsIsConnected"
#define OVS_CONNECTION_SET "ovsConnectionSet"
#define OVS_CONNECTION_TARGET "ovsConnectionTarget"
#define OVS_DHCP_V4 "ovsDHCPV4Options"
#define OVS_DHCP_V6 "ovsDHCPV6Options"
#define OVS_DIRECTION "ovsDirection"
#define OVS_DNS_RECORDS "ovsDNSRecords"
#define OVS_DNS_SET "ovsDNSConfigSet"
#define OVS_DSCP_ACTION "ovsDSCPAction"
#define OVS_DYN_ADDRESSES "ovsDynamicAddresses"
#define OVS_EXTERNAL_IDS "ovsExternalIds"
#define OVS_EXTERNAL_IP "ovsExternalIp"
#define OVS_EXTERNAL_MAC "ovsExternalMac"
#define OVS_GW_CHASSIS_OVS_NAME "ovsGatewayChassisName"
#define OVS_GW_CHASSIS_SET "ovsGatewayChassisSet"
#define OVS_HV_SEQUENCE "ovsHVSequence"
#define OVS_INACTIVITY_PROBE "ovsInactivityProbe"
#define OVS_IP_PREFIX "ovsIpPrefix"
#define OVS_IS_ENABLED "ovsIsEnabled"
#define OVS_IS_UP "ovsIsUp"
#define OVS_LB_SET "ovsLoadBalancerSet"
#define OVS_LOGICAL_IP "ovsLogicalIp"
#define OVS_LOGICAL_PORT "ovsLogicalPort"
#define OVS_LOGICAL_SW_PORT_OVS_SECURITY "ovsPortSecurity"
#define OVS_LOGICAL_SW_PORT_OVS_TYPE "ovsLogicalSwitchPortType"
#define OVS_LR_MAC "ovsLogicalRouterMac"
#define OVS_LR_PEER "ovsLogicalRouterPeer"
#define OVS_MATCH "ovsMatch"
#define OVS_MAX_BACK_OFF "ovsMaxBackoff"
#define OVS_NAME "name"
#define OVS_NAT "ovsNATSet"
#define OVS_NAT_TYPE "ovsNATType"
#define OVS_NB_SEQUENCE "ovsNBSequence"
#define OVS_NETWORKS "ovsNetworks"
#define OVS_NEXT_HOP "ovsNextHop"
#define OVS_OPTIONS "ovsOptions"
#define OVS_OUTPUT_PORT "ovsOutputPort"
#define OVS_PARENT_NAME "ovsParentName"
#define OVS_POLICY "ovsPolicy"
#define OVS_PORT_SET "ovsPorts"
#define OVS_PRIORITY "ovsPriority"
#define OVS_PROTOCOL "ovsProtocol"
#define OVS_QOS_SET "ovsQOSRuleSet"
#define OVS_SB_SEQUENCE "ovsSBSequence"
#define OVS_SSL_BOOTSTRAP_CA_CERT "ovsBootstrapCACertificate"
#define OVS_SSL_CA_CERT "ovsCACertificate"
#define OVS_SSL_CERT "ovsCertificate"
#define OVS_SSL_CIPHERS "ovsSSLCipers"
#define OVS_SSL_CONFIG "ovsSSLConfigDN"
#define OVS_SSL_PRIVATE_KEY "ovsPrivateKey"
#define OVS_SSL_PROTOCOLS "ovsSSLProtocols"
#define OVS_STATIC_ROUTES_SET "ovsStaticRoutes"
#define OVS_STATUS "status"
#define OVS_TAG "ovsTag"
#define OVS_TAG_REQUEST "ovsTagRequest"
#define OVS_VIPS "ovsVips"

#define OVSDB_ACL_ACTION "action"
#define OVSDB_ACL_LOG "log"
#define OVSDB_ACL_SET "acls"
#define OVSDB_ACL_SEVERITY "severity"
#define OVSDB_ACTION "action"
#define OVSDB_ADDRESSES "addresses"
#define OVSDB_BANDWIDTH "bandwidth"
#define OVSDB_CIDR "cidr"
#define OVSDB_CONFIGS "other_config"
#define OVSDB_CONN_IS_CONNECTED "is_connected"
#define OVSDB_CONNECTION_SET "connections"
#define OVSDB_CONNECTION_TARGET "target"
#define OVSDB_DHCP_V4 "dhcpv4_options"
#define OVSDB_DHCP_V6 "dhcpv6_options"
#define OVSDB_DIRECTION "direction"
#define OVSDB_DNS_RECORDS "records"
#define OVSDB_DNS_SET "dns_records"
#define OVSDB_DSCP_ACTION "action"
#define OVSDB_DYN_ADDRESSES "dynamic_addresses"
#define OVSDB_EXTERNAL_IDS "external_ids"
#define OVSDB_EXTERNAL_IP "external_ip"
#define OVSDB_EXTERNAL_MAC "external_mac"
#define OVSDB_GW_CHASSIS_OVS_NAME "chassis_name"
#define OVSDB_GW_CHASSIS_SET "gateway_chassis"
#define OVSDB_HV_SEQUENCE "hv_cfg"
#define OVSDB_INACTIVITY_PROBE "inactivity_probe"
#define OVSDB_IP_PREFIX "ip_prefix"
#define OVSDB_IS_ENABLED "enabled"
#define OVSDB_IS_UP "is_up"
#define OVSDB_LB_SET "load_balancer"
#define OVSDB_LOGICAL_IP "logical_ip"
#define OVSDB_LOGICAL_PORT "logical_port"
#define OVSDB_LOGICAL_SW_PORT_OVS_SECURITY "port_security"
#define OVSDB_LOGICAL_SW_PORT_OVS_TYPE "port_type"
#define OVSDB_LR_MAC "mac"
#define OVSDB_LR_PEER "peer"
#define OVSDB_MATCH "match"
#define OVSDB_MAX_BACK_OFF "max_backoff"
#define OVSDB_NAME "name"
#define OVSDB_NAT "nat"
#define OVSDB_NAT_TYPE "type"
#define OVSDB_NB_SEQUENCE "nb_cfg"
#define OVSDB_NETWORKS "networks"
#define OVSDB_NEXT_HOP "nexthop"
#define OVSDB_OPTIONS "options"
#define OVSDB_OUTPUT_PORT "output_port"
#define OVSDB_PARENT_NAME "parent_name"
#define OVSDB_POLICY "policy"
#define OVSDB_PORT_SET "ports"
#define OVSDB_PRIORITY "priority"
#define OVSDB_PROTOCOL "protocol"
#define OVSDB_QOS_SET "qos_rules"
#define OVSDB_SB_SEQUENCE "sb_cfg"
#define OVSDB_SSL_BOOTSTRAP_CA_CERT "bootstrap_ca_cert"
#define OVSDB_SSL_CA_CERT "ca_cert"
#define OVSDB_SSL_CERT "certificate"
#define OVSDB_SSL_CIPHERS "ssl_ciphers"
#define OVSDB_SSL_CONFIG "ssl"
#define OVSDB_SSL_PRIVATE_KEY "private_key"
#define OVSDB_SSL_PROTOCOLS "ssl_protocols"
#define OVSDB_STATIC_ROUTES_SET "static_routes"
#define OVSDB_STATUS "status"
#define OVSDB_TAG "tag"
#define OVSDB_TAG_REQUEST "tag_request"
#define OVSDB_UUID "uuid"
#define OVSDB_VIPS "vips"

#define KEY_SEP ':'
#define ENTRY_SEP ' '
#define LDAP_DEFAULT_STRING "null"
#define LDAP_DEFAULT_BOOLEAN false
#define LDAP_DEFAULT_INTEGER 0
#define LDAP_OBJECT_IDENTIFIER "-obj"

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

typedef enum _ovs_set_type_t {
    INTEGER,
    STRING
} set_type_t;

typedef struct _ovs_map_t {
    char *pKey;
    char *pValue;
} ovs_map_t;

typedef struct _ovs_set_t {
    set_type_t type;
    char *pValue;
} ovs_set_t;

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

typedef enum _OVS_COLUMN_TYPE {
    OVS_COLUMN_DEFAULT,
    OVS_COLUMN_UUID,
    OVS_COLUMN_STRING,
    OVS_COLUMN_BOOLEAN,
    OVS_COLUMN_SET,
    OVS_COLUMN_MAP,
    OVS_COLUMN_INTEGER
} OVS_COLUMN_TYPE;


struct ovs_clause {
    const char *ovsdb_column_name;
    enum ovsdb_function function;
    struct ovsdb_datum *value;
    const char *ldap_column_name;
};

struct ovs_condition {
    struct ovs_clause *ovs_clauses;
    size_t n_clauses;
};

struct ovs_column {
    char * ldap_column_name;
    const OVS_COLUMN_TYPE column_type;
    char * ovsdb_column_name;
    const struct ovsdb_type * pcolumn_ovsdb_type;
};

struct ovs_column_set {
    struct ovs_column * ovs_columns;
    size_t n_columns;
};

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
OvsLdapAddImpl(
    ovs_ldap_context_t *pConnection,
    LDAPMod **attrs,
    char *pDn,
    char *bucket,
    char *pUuid
);

uint32_t
OvsLdapSearchImpl(
    ovs_ldap_context_t *pConnection,
    char *pDn,
    char *bucket,
    const struct ovs_column_set *povs_column_set,
    struct ovs_condition *povs_condition,
    struct sset *desired_ovsdb_columns,
    struct json **ppresult_rows
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
    struct json *,
    const struct ovs_column_set *
);

typedef struct ovs_column_set FN_LDAP_GET_OVS_COLUMN_SET (void);

typedef struct __LDAP_FUNCTION_TABLE
{
    FN_LDAP_OPERATION *pfn_ldap_insert;
    FN_LDAP_OPERATION *pfn_ldap_select;
    FN_LDAP_OPERATION *pfn_ldap_delete;
    FN_LDAP_OPERATION *pfn_ldap_update;
    FN_LDAP_GET_OVS_COLUMN_SET *pfn_ldap_get_column_set;
} LDAP_FUNCTION_TABLE;

typedef LDAP_FUNCTION_TABLE LDAP_FUNCTION_TABLE_INIT (void);

#endif /* LDAP_PROVIDER_H */
