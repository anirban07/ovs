/* Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OVSDB_JSONRPC_SERVER_H
#define OVSDB_JSONRPC_SERVER_H 1

#include <stdbool.h>
#include "openvswitch/types.h"
#include "ovsdb-intf.h"
#include "trigger.h"
#include "server.h"

struct ovsdb;
struct shash;
struct simap;
struct uuid;
enum ovsdb_monitor_version;
struct json;
struct json_array;
struct ovsdb_trigger;
struct ovsdb_session;

struct ovsdb_jsonrpc_server *ovsdb_jsonrpc_server_create(bool read_only);
bool ovsdb_jsonrpc_server_add_db(struct ovsdb_jsonrpc_server *,
                                 struct ovsdb *);
void ovsdb_jsonrpc_server_remove_db(struct ovsdb_jsonrpc_server *,
                                    struct ovsdb *, char *comment);
void ovsdb_jsonrpc_server_destroy(struct ovsdb_jsonrpc_server *);

/* JSON-RPC database server. */

struct ovsdb_jsonrpc_server {
    struct ovsdb_server up;
    unsigned int n_sessions;
    bool read_only;            /* This server is does not accept any
                                  transactions that can modify the database. */
    struct shash remotes;      /* Contains "struct ovsdb_jsonrpc_remote *"s. */
};

/* A configured remote.  This is either a passive stream listener plus a list
 * of the currently connected sessions, or a list of exactly one active
 * session. */
struct ovsdb_jsonrpc_remote {
    struct ovsdb_jsonrpc_server *server;
    struct pstream *listener;   /* Listener, if passive. */
    struct ovs_list sessions;   /* List of "struct ovsdb_jsonrpc_session"s. */
    uint8_t dscp;
    bool read_only;
    char *role;
};

/* JSON-RPC database server session. */
struct ovsdb_jsonrpc_session {
    struct ovs_list node;       /* Element in remote's sessions list. */
    struct ovsdb_session up;
    struct ovsdb_jsonrpc_remote *remote;

    /* RFC 7047 does not contemplate how to alert clients to changes to the set
     * of databases, e.g. databases that are added or removed while the
     * database server is running.  Traditionally, ovsdb-server disconnects all
     * of its clients when this happens; a well-written client will reassess
     * what is available from the server upon reconnection.
     *
     * OVS 2.9 introduces a way for clients to monitor changes to the databases
     * being served, through the Database table in the _Server database that
     * OVSDB adds in this version.  ovsdb-server suppresses the connection
     * close for clients that identify themselves as taking advantage of this
     * mechanism.  When this member is true, it indicates that the client
     * requested such suppression. */
    bool db_change_aware;

    /* Triggers. */
    struct hmap triggers;       /* Hmap of "struct ovsdb_jsonrpc_trigger"s. */

    /* Monitors. */
    struct hmap monitors;       /* Hmap of "struct ovsdb_jsonrpc_monitor"s. */

    /* Network connectivity. */
    struct jsonrpc_session *js;  /* JSON-RPC session. */
    unsigned int js_seqno;       /* Last jsonrpc_session_get_seqno() value. */

    /* Read only. */
    bool read_only;             /*  When true, not allow to modify the
                                    database. */
};

/* Options for a remote. */
struct ovsdb_jsonrpc_options {
    int max_backoff;            /* Maximum reconnection backoff, in msec. */
    int probe_interval;         /* Max idle time before probing, in msec. */
    bool read_only;             /* Only read-only transactions are allowed. */
    int dscp;                   /* Dscp value for manager connections */
    char *role;                 /* Role, for role-based access controls */
};
struct ovsdb_jsonrpc_options *
ovsdb_jsonrpc_default_options(const char *target);

void ovsdb_jsonrpc_server_set_remotes(struct ovsdb_jsonrpc_server *,
                                      const struct shash *);

/* JSON-RPC database server triggers.
 *
 * (Every transaction is treated as a trigger even if it doesn't actually have
 * any "wait" operations.) */

struct ovsdb_jsonrpc_trigger {
    struct ovsdb_trigger trigger;
    struct hmap_node hmap_node; /* In session's "triggers" hmap. */
    struct json *id;
};

/* Status of a single remote connection. */
struct ovsdb_jsonrpc_remote_status {
    const char *state;
    int last_error;
    unsigned int sec_since_connect;
    unsigned int sec_since_disconnect;
    bool is_connected;
    char *locks_held;
    char *locks_waiting;
    char *locks_lost;
    int n_connections;
    ovs_be16 bound_port;
};
bool ovsdb_jsonrpc_server_get_remote_status(
    const struct ovsdb_jsonrpc_server *, const char *target,
    struct ovsdb_jsonrpc_remote_status *);
void ovsdb_jsonrpc_server_free_remote_status(
    struct ovsdb_jsonrpc_remote_status *);

void ovsdb_jsonrpc_server_reconnect(struct ovsdb_jsonrpc_server *, bool force,
                                    char *comment);

void ovsdb_jsonrpc_server_run(struct ovsdb_jsonrpc_server *,
                              PDB_INTERFACE_CONTEXT_T pContext,
                              DB_FUNCTION_TABLE *pDbFnTable);
void ovsdb_jsonrpc_server_wait(struct ovsdb_jsonrpc_server *);

void ovsdb_jsonrpc_server_set_read_only(struct ovsdb_jsonrpc_server *,
                                        bool read_only);

void ovsdb_jsonrpc_server_get_memory_usage(const struct ovsdb_jsonrpc_server *,
                                           struct simap *usage);

const struct uuid *ovsdb_jsonrpc_server_get_uuid(
    const struct ovsdb_jsonrpc_server *);

struct ovsdb_jsonrpc_monitor;
void ovsdb_jsonrpc_monitor_destroy(struct ovsdb_jsonrpc_monitor *,
                                   bool notify_cancellation);
void ovsdb_jsonrpc_disable_monitor_cond(void);

struct jsonrpc_msg *ovsdb_jsonrpc_monitor_create(
    struct ovsdb_jsonrpc_session *, struct ovsdb *, struct json *params,
    enum ovsdb_monitor_version, const struct json *request_id);

struct jsonrpc_msg *ovsdb_jsonrpc_monitor_cond_change(
    struct ovsdb_jsonrpc_session *s,
    struct json *params,
    const struct json *request_id);

struct jsonrpc_msg *ovsdb_jsonrpc_monitor_cancel(
    struct ovsdb_jsonrpc_session *,
    struct json_array *params,
    const struct json *request_id);

struct ovsdb *
ovsdb_jsonrpc_lookup_db(const struct ovsdb_jsonrpc_session *s,
                        const struct jsonrpc_msg *request,
                        struct jsonrpc_msg **replyp);
struct ovsdb_jsonrpc_trigger *ovsdb_jsonrpc_trigger_find(
    struct ovsdb_jsonrpc_session *, const struct json *id, size_t hash);
void ovsdb_jsonrpc_session_send(struct ovsdb_jsonrpc_session *,
                                       struct jsonrpc_msg *);
struct jsonrpc_msg *
syntax_error_reply(const struct jsonrpc_msg *request, const char *details);
void ovsdb_jsonrpc_trigger_complete(struct ovsdb_jsonrpc_trigger *);
#endif /* ovsdb/jsonrpc-server.h */
