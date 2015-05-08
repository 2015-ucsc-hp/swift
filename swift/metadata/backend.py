# Copyright (c) 2010-2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import time
from string import maketrans
from swift.common.utils import normalize_timestamp
from swift.common.utils import json
import pyorient

# TODO: go over all queries and look into using transactions
# TODO: When server.py is cleaned up this can be removed
BROKER_TIMEOUT = 25

#TODO: merge orientdbbroker into metadata broker
class OrientDBBroker(object):
    """
    Encapsulates working with an OrientDB database.

    server.py creates MetadataBroker(OrientDBBroker) which calls OrientDBBroker.__init__(),
    server.py calls OrientDBBroker.initialize(),
    if the tables do not exist server.py calls MetadataBroker._initialize()
    """

    # TODO: update defn and function calls in server.py to be simpler
    #       and trim out unused portions of sqlite code
    def __init__(self, db_file, timeout=BROKER_TIMEOUT, logger=None,
                 account=None, container=None, pending_timeout=None,
                 stale_reads_ok=False):
        self.conn = None
        self.db_address = "127.0.0.1"
        self.timeout = timeout

    # TODO: cleanup server.py and remove timestamp param
    # TODO: Retrieve IP/user/pw of an orientdb node from configuration file
    def initialize(self, put_timestamp=None):
        """
        Connect to and/or create the DB
        """
        self.conn = pyorient.OrientDB("localhost", 2424)
        self.conn.connect("root","hpgroup")
        if not self.conn.db_exists("metadata", pyorient.STORAGE_TYPE_PLOCAL):
            self.conn.db_create( "metadata", pyorient.DB_TYPE_DOCUMENT, pyorient.STORAGE_TYPE_PLOCAL )
            # TODO: Does this autoconnect? Does it block to create the DB?
            self._initialize(self.conn)
        self.conn.db_open("metadata", "root", "hpgroup")
    

class MetadataBroker(OrientDBBroker):
    """
    initialize the database and four tables.
    Three are for system metadata of account, container and object server.
    custom metadata are stored in key-value pair format in another table.
    """
    # TODO: cleanup the class docstring
    # TODO: cleanup the global variables
    type = 'metadata'
    db_contains_type = 'object'
    db_reclaim_timestamp = 'created_at'
    account_fields = [
        "account_uri",
        "account_name",
        "account_tenant_id",
        "account_first_use_time",
        "account_last_modified_time",
        "account_last_changed_time",
        "account_delete_time",
        "account_last_activity_time",
        "account_container_count",
        "account_object_count",
        "account_bytes_used"
    ]
    container_fields = [
        "container_uri",
        "container_name",
        "container_account_name",
        "container_create_time",
        "container_last_modified_time",
        "container_last_changed_time",
        "container_delete_time",
        "container_last_activity_time",
        "container_read_permissions",
        "container_write_permissions",
        "container_sync_to",
        "container_sync_key",
        "container_versions_location",
        "container_object_count",
        "container_bytes_used",
    ]
    object_fields = [
        "object_uri",
        "object_name",
        "object_account_name",
        "object_container_name",
        "object_location",
        "object_uri_create_time",
        "object_last_modified_time",
        "object_last_changed_time",
        "object_delete_time",
        "object_last_activity_time",
        "object_etag_hash",
        "object_content_type",
        "object_content_length",
        "object_content_encoding",
        "object_content_disposition",
        "object_content_language",
        "object_cache_control",
        "object_delete_at","manifest_type",
        "object_manifest",
        "object_access_control_allow_origin",
        "object_access_control_allow_credentials",
        "object_access_control_expose_headers",
        "object_access_control_max_age",
        "object_allow_methods",
        "object_allow_headers",
        "object_origin",
        "object_access_control_request_method",
        "object_access_control_request_headers"
    ]

    def _initialize(self):
        """ Initialize the tables of the database """
        self.create_md_table()
        self.create_custom_md_table()

    def create_md_table(self):
        """ Issue a batch console command to create the metadata table """
        self.conn.batch("""
            CREATE CLASS Metadata;
            CREATE PROPERTY Metadata.account_uri STRING;
            CREATE PROPERTY Metadata.account_name STRING;
            CREATE PROPERTY Metadata.account_tenant_id STRING;
            CREATE PROPERTY Metadata.account_first_use_time DATETIME;
            CREATE PROPERTY Metadata.account_last_modified_time DATETIME;
            CREATE PROPERTY Metadata.account_last_changed_time DATETIME;
            CREATE PROPERTY Metadata.account_delete_time DATETIME;
            CREATE PROPERTY Metadata.account_last_activity_time DATETIME;
            CREATE PROPERTY Metadata.account_container_count LONG;
            CREATE PROPERTY Metadata.account_object_count LONG;
            CREATE PROPERTY Metadata.account_bytes_used LONG;
            CREATE PROPERTY Metadata.container_uri STRING;
            CREATE PROPERTY Metadata.container_name STRING;
            CREATE PROPERTY Metadata.container_account_name STRING;
            CREATE PROPERTY Metadata.container_create_time DATETIME;
            CREATE PROPERTY Metadata.container_last_modified_time DATETIME;
            CREATE PROPERTY Metadata.container_last_changed_time DATETIME;
            CREATE PROPERTY Metadata.container_delete_time DATETIME;
            CREATE PROPERTY Metadata.container_last_activity_time DATETIME;
            CREATE PROPERTY Metadata.container_read_permissions STRING;
            CREATE PROPERTY Metadata.container_write_permissions STRING;
            CREATE PROPERTY Metadata.container_sync_to STRING;
            CREATE PROPERTY Metadata.container_sync_key STRING;
            CREATE PROPERTY Metadata.container_versions_location STRING;
            CREATE PROPERTY Metadata.container_object_count LONG;
            CREATE PROPERTY Metadata.container_bytes_used LONG;
            CREATE PROPERTY Metadata.object_uri STRING;
            CREATE PROPERTY Metadata.object_name STRING;
            CREATE PROPERTY Metadata.object_account_name STRING;
            CREATE PROPERTY Metadata.object_container_name STRING;
            CREATE PROPERTY Metadata.object_location STRING;
            CREATE PROPERTY Metadata.object_uri_create_time DATETIME;
            CREATE PROPERTY Metadata.object_last_modified_time DATETIME;
            CREATE PROPERTY Metadata.object_last_changed_time DATETIME;
            CREATE PROPERTY Metadata.object_delete_time DATETIME;
            CREATE PROPERTY Metadata.object_last_activity_time DATETIME;
            CREATE PROPERTY Metadata.object_etag_hash STRING;
            CREATE PROPERTY Metadata.object_content_type STRING;
            CREATE PROPERTY Metadata.object_content_length LONG;
            CREATE PROPERTY Metadata.object_content_encoding STRING;
            CREATE PROPERTY Metadata.object_content_disposition STRING;
            CREATE PROPERTY Metadata.object_content_language STRING;
            CREATE PROPERTY Metadata.object_cache_control STRING;
            CREATE PROPERTY Metadata.object_delete_at DATETIME;
            CREATE PROPERTY Metadata.object_manifest_type LONG;
            CREATE PROPERTY Metadata.object_manifest STRING;
            CREATE PROPERTY Metadata.object_access_control_allow_origin STRING;
            CREATE PROPERTY Metadata.object_access_control_allow_credentials STRING;
            CREATE PROPERTY Metadata.object_access_control_expose_headers STRING;
            CREATE PROPERTY Metadata.object_access_control_max_age STRING;
            CREATE PROPERTY Metadata.object_allow_methods STRING;
            CREATE PROPERTY Metadata.object_allow_headers STRING;
            CREATE PROPERTY Metadata.object_origin STRING;
            CREATE PROPERTY Metadata.object_access_control_request_method STRING;
            CREATE PROPERTY Metadata.object_access_control_request_headers STRING;
        """)

    def create_custom_md_table(self):
        """ Issue a batch console command to create the metadata table """
        conn.batch("""
            CREATE CLASS Custom;
            CREATE PROPERTY Custom.uri STRING;
            CREATE INDEX custom_id on Custom (uri, custom_key) UNIQUE;
            CREATE PROPERTY Custom.custom_key STRING;
            CREATE PROPERTY Custom.custom_value STRING;
            CREATE PROPERTY Custom.timestamp DATETIME;
        """)

    def insert_custom_md(self, uri, key, value):
        """Data insertion method for custom metadata table"""
        query = '''
            UPDATE Custom SET
                uri = '%s',
                custom_key = '%s',
                custom_value = '%s',
                timestamp = '%s'
            UPSERT WHERE uri = '%s'"
        '''
        # Build and execute query for each requested insertion
        formatted_query = \
            query % (uri, key, value, normalize_timestamp(time.time()), uri)
        self.conn.command(formatted_query)

    def insert_account_md(self, data):
        """Data insertion method for account metadata"""
        query = '''UPDATE Metadata SET 
                account_uri = "%s",
                account_name = "%s",
                account_tenant_id = "%s", 
                account_first_use_time = %s, 
                account_last_modified_time = %s, 
                account_last_changed_time = %s, 
                account_delete_time = %s, 
                account_last_activity_time = %s, 
                account_container_count = %s, 
                account_object_count = %s, 
                account_bytes_used = %s 
            UPSERT WHERE 
                account_uri = "%s"
        '''

        for row in data:
            formatted_query = query % (
                row['account_uri'],
                row['account_name'],
                row['account_tenant_id'],
                row['account_first_use_time'],
                row['account_last_modified_time'],
                row['account_last_changed_time'],
                row['account_delete_time'],
                row['account_last_activity_time'],
                row['account_container_count'],
                row['account_object_count'],
                row['account_bytes_used'],
                row['account_uri']
            )            
            self.conn.command(formatted_query)

    def insert_container_md(self, data):
        """Data insertion method for container metadata"""
        query = '''UPDATE Metadata SET 
                account_uri = "%s",
                account_name = "%s",
                account_tenant_id = "%s", 
                account_first_use_time = "%s", 
                account_last_modified_time = "%s", 
                account_last_changed_time = "%s", 
                account_delete_time = "%s", 
                account_last_activity_time = "%s", 
                account_container_count = %s, 
                account_object_count = %s, 
                account_bytes_used = %s, 
                container_uri = "%s",
                container_name = "%s",
                container_account_name = "%s",
                container_create_time = %s,
                container_last_modified_time = %s,
                container_last_changed_time = %s,
                container_delete_time = %s,
                container_last_activity_time = %s,
                container_read_permissions = "%s",
                container_write_permissions = "%s",
                container_sync_to = "%s",
                container_sync_key = "%s",
                container_versions_location = "%s",
                container_object_count = %s,
                container_bytes_used = %s 
            UPSERT WHERE 
                container_uri = "%s"
        '''

        for row in data:
            # Query for account details for denormalized insertion
            acc_query = '''SELECT 
                    account_uri, 
                    account_name, 
                    account_tenant_id, 
                    account_first_use_time, 
                    account_last_modified_time, 
                    account_last_changed_time, 
                    account_delete_time, 
                    account_last_activity_time, 
                    account_container_count, 
                    account_object_count, 
                    account_bytes_used 
                FROM Metadata 
                WHERE 
                    account_name = "%s"
            ''' % (
                row['container_account_name']
            )
            queryList = self.conn.query(acc_query)
            # TODO: check for keyError
            acc_data = queryList[0].oRecordData
            
            formatted_query = query % (
                acc_data['account_uri'],
                acc_data['account_name'],
                acc_data['account_tenant_id'],
                acc_data['account_first_use_time'],
                acc_data['account_last_modified_time'],
                acc_data['account_last_changed_time'],
                acc_data['account_delete_time'],
                acc_data['account_last_activity_time'],
                acc_data['account_container_count'],
                acc_data['account_object_count'],
                acc_data['account_bytes_used'],
                row['container_uri'],
                row['container_name'],
                row['container_account_name'],
                row['container_create_time'],
                row['container_last_modified_time'],
                row['container_last_changed_time'],
                row['container_delete_time'],
                row['container_last_activity_time'],
                row['container_read_permissions'],
                row['container_write_permissions'],
                row['container_sync_to'],
                row['container_sync_key'],
                row['container_versions_location'],
                row['container_object_count'],
                row['container_bytes_used'],
                row['container_uri']
            )
            target = open("/home/hp/debug2", 'a')                                                                                                        
            target.write(formatted_query) 
            self.conn.command(formatted_query)

    def insert_object_md(self, data):
        """Data insertion method for object metadata"""
        query = '''UPDATE Metadata SET
                account_uri = "%s",
                account_name = "%s",
                account_tenant_id = "%s", 
                account_first_use_time = "%s", 
                account_last_modified_time = "%s", 
                account_last_changed_time = "%s", 
                account_delete_time = "%s", 
                account_last_activity_time = "%s", 
                account_container_count = %s, 
                account_object_count = %s, 
                account_bytes_used = %s, 
                container_uri = "%s",
                container_name = "%s",
                container_account_name = "%s",
                container_create_time = "%s",
                container_last_modified_time = "%s",
                container_last_changed_time = "%s",
                container_delete_time = "%s",
                container_last_activity_time = "%s",
                container_read_permissions = "%s",
                container_write_permissions = "%s",
                container_sync_to = "%s",
                container_sync_key = "%s",
                container_versions_location = "%s",
                container_object_count = %s,
                container_bytes_used = %s,
                object_uri = "%s",
                object_name = "%s",
                object_account_name = "%s",
                object_container_name = "%s",
                object_location = "%s",
                object_uri_create_time = %s,
                object_last_modified_time = %s,
                object_last_changed_time = %s,
                object_delete_time = %s,
                object_last_activity_time = %s,
                object_etag_hash = "%s",
                object_content_type = "%s",
                object_content_length = %s,
                object_content_encoding = "%s",
                object_content_disposition = "%s",
                object_content_language = "%s",
                object_cache_control = "%s",
                object_delete_at = %s,
                object_manifest_type = %s,
                object_manifest = "%s",
                object_access_control_allow_origin = "%s",
                object_access_control_allow_credentials = "%s",
                object_access_control_expose_headers = "%s",
                object_access_control_max_age = "%s",
                object_allow_methods = "%s",
                object_allow_headers = "%s",
                object_origin = "%s",
                object_access_control_request_method = "%s",
                object_access_control_request_headers = "%s"
            UPSERT WHERE 
                object_uri = "%s"
        '''

        for row in data:
            # Query for account details for denormalized insertion
            acc_cont_query = '''SELECT 
                    account_uri, 
                    account_name, 
                    account_tenant_id, 
                    account_first_use_time, 
                    account_last_modified_time, 
                    account_last_changed_time, 
                    account_delete_time, 
                    account_last_activity_time, 
                    account_container_count, 
                    account_object_count, 
                    account_bytes_used
                    container_uri,
                    container_name,
                    container_account_name,
                    container_create_time,
                    container_last_modified_time,
                    container_last_changed_time,
                    container_delete_time,
                    container_last_activity_time,
                    container_read_permissions,
                    container_write_permissions,
                    container_sync_to,
                    container_sync_key,
                    container_versions_location,
                    container_object_count,
                    container_bytes_used
                FROM Metadata 
                WHERE 
                    account_name = "%s"
                AND
                    container_name = "%s"
            ''' % (
                row['object_account_name'],
                row['object_container_name']
            )
            queryList = self.conn.query(acc_cont_query)
            # TODO: check for keyError
            acc_cont_data = queryList[0].oRecordData
            
            formatted_query = query % (
                acc_cont_data['account_uri'],
                acc_cont_data['account_name'],
                acc_cont_data['account_tenant_id'],
                acc_cont_data['account_first_use_time'],
                acc_cont_data['account_last_modified_time'],
                acc_cont_data['account_last_changed_time'],
                acc_cont_data['account_delete_time'],
                acc_cont_data['account_last_activity_time'],
                acc_cont_data['account_container_count'],
                acc_cont_data['account_object_count'],
                acc_cont_data['account_bytes_used'],
                acc_cont_data['container_uri'],
                acc_cont_data['container_name'],
                acc_cont_data['container_account_name'],
                acc_cont_data['container_create_time'],
                acc_cont_data['container_last_modified_time'],
                acc_cont_data['container_last_changed_time'],
                acc_cont_data['container_delete_time'],
                acc_cont_data['container_last_activity_time'],
                acc_cont_data['container_read_permissions'],
                acc_cont_data['container_write_permissions'],
                acc_cont_data['container_sync_to'],
                acc_cont_data['container_sync_key'],
                acc_cont_data['container_versions_location'],
                acc_cont_data['container_object_count'],
                acc_cont_data['container_bytes_used'],
                row['object_uri'],
                row['object_name'],
                row['object_account_name'],
                row['object_container_name'],
                row['object_location'],
                row['object_uri_create_time'],
                row['object_last_modified_time'],
                row['object_last_changed_time'],
                row['object_delete_time'],
                row['object_last_activity_time'],
                row['object_etag_hash'],
                row['object_content_type'],
                row['object_content_length'],
                row['object_content_encoding'],
                row['object_content_disposition'],
                row['object_content_language'],
                row['object_cache_control'],
                row['object_delete_at'],
                row['object_manifest_type'],
                row['object_manifest'],
                row['object_access_control_allow_origin'],
                row['object_access_control_allow_credentials'],
                row['object_access_control_expose_headers'],
                row['object_access_control_max_age'],
                row['object_access_control_allow_methods'],
                row['object_access_control_allow_headers'],
                row['object_origin'],
                row['object_access_control_request_method'],
                row['object_access_control_request_headers'],
                row['object_uri']
            )
            self.conn.command(formatted_query)

    def overwrite_custom_md(self, conn, uri, data):
        """Data overwrite method for custom metadata table,
        deletes all rows that are not updated"""
        # Remove all custom metadata that is not listed in data
        query = "DELETE FROM Custom WHERE uri = '" + str(uri)
        inserted_fields = []
        for field, value in data.items():
            inserted_fields.append(str(field) + " <> '" + str(value) + "'")
        query += " and ".join(inserted_fields)
        conn.command(query)

        # Update all custom metadata listed in data
        for field, value in data.items():
            insert_custom_md(self, conn, uri, field, value)

    # TODO: analyze, accounts/containers cannot be deleted unless empty
    #       so overwrite does not need to affect lower level hierarchies
    #       but should lower level deletes affect higher levels?
    def overwrite_account_md(self, data):
        """Data overwrite method for account data in metadata table,
        nulls all fields that are not updated"""
        query = "UPDATE Metadata SET "
        inserted_fields = []
        for field in account_fields:
            if field in data:
                inserted_fields.append(str(field) + " = '" + str(data[field]) + "'")
            else:
                inserted_fields.append(str(field) + " = null")
        query += " and " + " ,".join(inserted_fields)
        query += " UPSERT WHERE account_uri = '" + str(data['account_uri']) + "'"
        self.conn.command(query)

    # TODO: analyze, accounts/containers cannot be deleted unless empty
    #       so overwrite does not need to affect lower level hierarchies
    #       but should lower level deletes affect higher levels?
    def overwrite_container_md(self, data):
        """Data overwrite method for container data in metadata table,
        nulls all fields that are not updated"""
        query = "UPDATE Metadata SET "
        inserted_fields = []
        for field in container_fields:
            if field in data:
                inserted_fields.append(str(field) + " = '" + str(data[field]) + "'")
            else:
                inserted_fields.append(str(field) + " = null")
        query += " and " + " ,".join(inserted_fields)
        query += " UPSERT WHERE container_uri = '" + str(data['container_uri']) + "'"
        self.conn.command(query)

    # TODO: analyze, accounts/containers cannot be deleted unless empty
    #       so overwrite does not need to affect lower level hierarchies
    #       but should lower level deletes affect higher levels?
    def overwrite_object_md(self, data):
        """Data insertion methods for object data in metadata table,
        nulls all fields that are not updated"""
        query = "UPDATE Metadata SET "
        inserted_fields = []
        for field in object_fields:
            if field in data:
                inserted_fields.append(str(field) + " = '" + str(data[field]) + "'")
            else:
                inserted_fields.append(str(field) + " = null")
        query += " and " + " ,".join(inserted_fields)
        query += " WHERE object_uri = '" + str(data['object_uri']) + "'"
        self.conn.command(query)

    def getAll(self):
        """
        Dump everything, used for debugging
        """
        obj_data = [record.oRecordData for record in self.conn.query("SELECT FROM Metadata")]

        return ''.join([
            json.dumps(obj_data), "\n\n", json.dumps(con_data), "\n\n",
            json.dumps(acc_data)
        ])

    def get_attributes_query(self, acc, con, obj, attrs):
        """
        This query starts off the query STRING by adding the Attributes
        to be returned in the SELECT statement.
        Also handles scoping by passing in the scope info:

            If we are in object scope, the only things visible
            are this object, the parent container, and the parent
            account.

            If in container scope. All objects in the container are
            visible, this container, and the parent account.

            If in account scope, All objects and containers in the scope
            are visible, as well as this account.
        """
        # Catch bad query
        if attrsStartWith(attrs) == "BAD":
            return "BAD"

        # Object Scope
        if obj != "" and obj is not None:
            Ouri = "'/" + acc + "/" + con + "/" + obj + "'"
            Curi = "'/" + acc + "/" + con + "'"
            Auri = "'/" + acc + "'"
            domain = attrsStartWith(attrs)
            if domain == 'object':
                uri = Ouri
            elif domain == 'container':
                uri = Curi
            else:
                uri = Auri
            return """SELECT %s,%s_uri
                FROM Metadata
                WHERE %s_uri=%s
            """ % (attrs, domain, domain, domain, uri)

        # Container Scope
        elif con != "" and con is not None:
            uri = "'/" + acc + "/" + con + "'"
            Auri = "'/" + acc + "'"
            if attrsStartWith(attrs) == 'object':
                return ("SELECT %s,object_uri "
                    "FROM Metadata "
                    "WHERE object_container_name=%s"
                ) % (attrs, "'" + con + "'")

            elif attrsStartWith(attrs) == 'container':
                return ("SELECT %s,container_uri "
                    "FROM Metadata "
                    "WHERE container_uri=%s"
                ) % (attrs, uri)

            elif attrsStartWith(attrs) == 'account':
                return ("SELECT %s,account_uri "
                    "FROM Metadata "
                    "WHERE account_uri=%s"
                ) % (attrs, Auri)

        # Account scope
        elif acc != "" and acc is not None:
            uri = "'/" + acc + "'"
            if attrsStartWith(attrs) == 'object':
                return ("SELECT %s,object_uri "
                    "FROM Metadata "
                    "WHERE object_account_name='%s'"
                ) % (attrs, acc)

            elif attrsStartWith(attrs) == 'container':
                return ("SELECT %s,container_uri "
                    "FROM Metadata "
                    "WHERE container_account_name='%s'"
                ) % (attrs, acc)

            elif attrsStartWith(attrs) == 'account':
                return ("SELECT %s,account_uri "
                    "FROM Metadata "
                    "WHERE account_uri=%s"
                ) % (attrs, uri)

    def get_uri_query(self, sql, queries):
        '''
        URI Query parser
        Takes the output of get_attributes_query() as input (sql), and adds
        additional query information based on ?query=<> from the URI
        If Query refrences custom attribute, replace condition with EXECPT
        Subquery on custom_metadata table with condition inside where clause.
        Also preforms sanitation preventing SQL injection.
        '''
        queries = queries.replace("%20", " ")
        queries = queries.translate(None,';%[]&')
        query = ""
        querysplit = queries.split(" ")
        count = 1
        for i in querysplit:
            if (i.startswith("object_meta")
                        or i.startswith("container_meta")
                        or i.startswith("account_meta")):
                first = i.split("_")[0]
                key = "_".join(i.translate(maketrans("<>!=","____")).split("_")[:3])
                # Append a new subquery variable after FROM section
                sql = sql.replace("FROM Metadata","FROM Metadata let $temp" + count + "=(SELECT FROM Custom WHERE custom_key=" + first + " AND uri=" + key + " AND custom_value" + i[len(key):] + ") ")
                # Add WHERE condition that subquery returns results
                i = "$temp" + count + ".size() > 0"
                count += 1
            # TODO: must add spaces around '<' and '>' or orientDB has
            # formatting errors
            query += " " + i

        return sql + " AND" + query

    def custom_attributes_query(self, customAttrs, sysMetaList,
                                all_obj_meta, all_con_meta, all_acc_meta):
        """
        This function executes a query to get custom Attributes
        and merge them into the list of dictionaries which is created
        before this function is called. Only merges attributes in the
        customAttrs list passed in.
        """
        for x in sysMetaList:
            uri = x.keys()[0]
            query = """SELECT custom_key, custom_value
            FROM Custom
            WHERE uri='%s'
            """ % uri
            l = self.conn.query(query)
            for d in l:
                if (d['custom_key'] in customAttrs.split(',')) or \
                    (all_obj_meta and
                        d['custom_key'].startswith("object_meta")) or \
                    (all_con_meta and
                        d['custom_key'].startswith("container_meta")) or \
                    (all_acc_meta and
                        d['custom_key'].startswith("account_meta")):
                            x[uri][d['custom_key']] = d['custom_value']
        return sysMetaList

    # TODO: handling duplicate and null data
    def execute_query(self, query, acc, con, obj, includeURI):
        """
        Execute the main query.
        Executes a query which has been built
        up before this call in server.py
        The row_factory makes dictionaries of
        {column : entry} per row returned.
        We add the URI of the `thing` found in the query
        as a key in a new dictionary,
        with the value the previous dictionary
        Each 'row' is now a dictionary in a list
        This list of dictonaries is returned
        """
        queryList = self.conn.query(query)
        retList = []
        for rowData in queryList:
            row = rowData.oRecordData
            if not includeURI:
                try:
                    uri = row['object_uri']
                    retList.append({uri: row})
                    del row['object_uri']
                except KeyError:
                    pass
                try:
                    uri = row['container_uri']
                    retList.append({uri: row})
                    del row['container_uri']
                except KeyError:
                    pass
                try:
                    uri = row['account_uri']
                    retList.append({uri: row})
                    del row['account_uri']
                except KeyError:
                    pass
            else:
                try:
                    retList.append({row['object_uri']: row})
                except KeyError:
                    pass
                try:
                    retList.append({row['container_uri']: row})
                except KeyError:
                    pass
                try:
                    retList.append({row['account_uri']: row})
                except KeyError:
                    pass
        return retList

    # TODO: Correct this to be match mariadb/server.py
    def is_initialized(self):
        row = self.conn.query("select from (select expand(classes) from metadata:schema) where name = 'Metadata'")
        return len(row) != 0

    def empty(self):
        row = self.conn.query("select from (select expand(classes) from metadata:schema) where name = 'Metadata'")
        return len(row) == 0


def dict_factory(cursor, row):
    """Converts query return into a dictionary"""
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d



def attachURI(metaDict, acc, con, obj):
    """Add URI to dict as `label`"""
    if obj != "" and obj is not None:
        uri = '/'.join(['', acc, con, obj])
    elif con != "" and con is not None:
        uri = '/'.join(['', acc, con])
    else:
        uri = '/' + acc
    return {uri: metaDict}



def attrsStartWith(attrs):
    """
    checks if every attribute in the list starts with the correct.
    returns the thing it begins with (object/container/account)
    or "BAD" if error
    """
    objs = 0
    cons = 0
    accs = 0
    for attr in attrs.split(','):
        if attr.startswith('object'):
            objs += 1
        elif attr.startswith('container'):
            cons += 1
        elif attr.startswith('account'):
            accs += 1

    if objs > 0 and cons == 0 and accs == 0:
        return 'object'
    elif cons > 0 and objs == 0 and accs == 0:
        return 'container'
    elif accs > 0 and objs == 0 and cons == 0:
        return 'account'
    else:
        return "BAD"
