# APIs:
## nb_ldap_insert_helper
Takes in the same parameters as any `nb_<table_name>_ldap_insert` function, in addition to a table name. It does all the work that needs to be done in a insert request. If inserting into a table that's a child of another table, the dn of the parent is included in the dn to be used. Otherwise, the default root dn is used. The row passed in the json is parsed, and columns that are not mentioned are filled with default values. These default values can be different from those used by OVSDB. The row is inserted into Lightwave, and a json object with the uuid of the row added is added to the `result` json object.
## nb_ldap_select_helper
Takes in the same parameters as any nb\_\<table_name\>\_ldap_select function, in addition to a table name. It does all the work that needs to be done in a select request. All the fields in the request are parsed. An `ovs_condition` struct is created from the "where" clause in the request. If columns are specified in the request, a set is populated with the columns that are to be returned. The OVSDB names of the columns are used. Since the select might be on a child object, all the parent objects must be searched. All the dns where this type of object occurs are collected in a set. One by one all these dns are searched for objects that might pass the condition specified in the "where" clause. `OvsLdapSearchImpl` does this searching. It adds the objects found as json rows in `result_rows`, keeping only the rows specified in "columns". If "columns" was absent in the json request, all columns are returned. The rows returned as json objects are added to the `result` json object.
## nb_ldap_update_helper
Similar to `nb_ldap_select_helper`. Attributes not present in the row json are left `NULL`. The attrs created on parsing the row have their mod_op set to `LDAP_MOD_REPLACE`. Instead of calling `OvsLdapSearchImpl`, `OvsLdapUpdateImpl` is called, which makes changes to the objects that match the given condition. The number of rows updated is added to the `result` json object.
## nb_<table_name>_get_column_set
These functions return an `ovs_column_set` which contains an array of `ovs_column`s. The set represents the attributes of that object. Each `ovs_column` struct contains the OVSDB name of that attribute, its LDAP name, it's OVSDB attribute type, and an OVS (general) type. This function is called in `ldap_execute_compose_intf` before every operation is executed. The `ovs_column_set` is passed in to the operation executor.
## lookup_ldap_operation
Takes an operation name and a function table of operations for a nb table and returns a pointer to the corresponding operator function.
## ldap_string_to_datum
Takes in a string that was read from the LDAP server, the type of datum to be made, and a pointer to the datum to be populated. The LDAP string is modified such that LDAP's default string is not used, instead OVSDB's default (empty string) is used. If it is a map, the key-value separator is replaced with "=" which is what `ovsdb_datum_from_string` expects. The string is then passed to `ovsdb_datum_from_string` which converts it to an `ovsdb_datum` struct.
## ldap_ovs_evaluate_clause
Similar to `ovsdb_clause_evaluate`. Takes in an `ovsdb_datum` struct, an `ovsdb_type` struct and an `ovs_clause` and returns if the datum satisfies the clause or not.
## ldap_get_row_if_match
Takes an `LDAPMessage` struct, which contains an object that was read from LDAP, a set of `ovs_clauses` in the `ovs_condition` struct, and a set of desired attributes in the form of their OVSDB column names. It goes through every attribute of the given obejct, ignoring those that aren't OVS attributes. The attribute's value is checked against all the clauses in the condition passed in. If any attribute doesn't match the condition, the result row is set to `NULL`. Once all conditions are checked, then only the desired columns are added to the result row. The complexity of this fnuction can be improved if the clauses in the `ovs_condition` struct are stored in a hash map from column name to the condition.
## ldap_get_all_dns
If the object passed in does not have a parent object, nothing is added to the set of dns. If the object has a parent, all of the parent objects are searched for buckets of the child object. For every parent object that has a bucket of the child object in question, it's dn is saved in the set `pall_dns`
## OvsLdapSearchImpl
It takes the dn of the parent of the bucket to search in. For every object found in the bucket, `ldap_get_row_if_match` is called, if the object passes the conditions, the corresponding row is added to the `presults_row` json array.
## OvsLdapUpdateImpl
Similar to `OvsLdapSearchImpl`. If the row passes all the clauses in the condition passed in, the object is modified using the `attrs` passed in.
## ldap_ovs_clause_from_json
Similar to `ovsdb_clause_from_json` 
## ldap_ovs_condition_from_json
Loops over the array elements in the "where" clause of the json, and parses them into `ovs_clause` structs. All the '`ovs_clause` structs are collected into an array inside a `ovs_condition` struct.
## ovsdb_datum_to_ovs_set
Takes an `ovsdb_datum`, an `ovsdb_type` and creates `ovs_set_t` structs which are populated in a return parameter. Currently the `ovs_set_t` struct is simply a wrapper for a string with a type. The only type being used is `STRING`. The `ovsdb_datum` is converted to a string atom by atom using OVSDB's helper funciton `ovsdb_atom_to_bare`.
## destroy_ovs_set
Takes a pointer to an `ovs_set_t` array, and number of elements and frees the string in the set and the set struct itself.
## ovsdb_datum_to_ovs_map
Takes an `ovsdb_datum`, an `ovsdb_type` and creates `ovs_map_t` structs which are returned in a return parameter. Currently, the only types of maps supported are string-to-string and string-to-integer maps. These are the only types of maps that occur in the Northbound DB of OVN
## destroy_ovs_map
Takes a pointer to an `ovs_map_t` array and the number of elements. It frees the keys and values and the `ovs_map_t` structs as well.
## LDAPMod_creater
Given an `ovsdb_datum`, `mod_op` and `ovs_column`, it populates the fields of the given `LDAPMod` struct. It calls the helper functions such as `ovs_get_int_sequence`, `ovs_get_bool_sequence`, `ovs_get_set_sequence`, `ovs_get_map_sequence`, and `ovs_get_str_sequence` depending on the type of the `ovs_column` passed in.
## ldap_ovs_parse_row
Parses the row json passed in into an array of LDAPMod structs which is returned in a return parameter. It first loops over all the attributes present in the row json. It uses `LDAPMod_creater` to convert the `ovsdb_datum` made from the json, to a `LDAPMod` struct. If the `fill_default` flag is set, then the attributes not present in the row json are filled with their default values. If `uuid` was not present in the row json, a new uuid is created for this object. If `fill_default` is set, an attribute apart from the columns is added, which is the `LDAP_OBJECT_CLASS` attribute. `fill_default` is set to false when a row json is being read for an update request. The array of `LDAPMod` struct pointers must be null terminated.
## attrs_cleanup
Frees the fields of the `LDAPMod` structs that need to be freed.

# Known bugs/issues
## GetDSERootAttribute fails with error -1
Occasionally the call to `ldap_search_ext_s` in GetDSERootAttribute will fail with error code -1. This seems to happen when the connection has been up for a long time. Though that might not be the cause.
## Objects with multiple parents
The Load Balancer table in NB can have wither Logical Router or Logical Switch as it parent (perhaps both at the same time too). This case needs to be handled since LDAP only supports a single parent for a given object.
## Perfromance benefits from using hash maps
Some structs like the `ovs_column_set`, `ovs_condition` and so on can benefit from using hash maps instead of arrays.