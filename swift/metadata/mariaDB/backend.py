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
import MySQLdb as mdb
from MySQLdb.constants import ER as errorcode

class MariaDBBroker(object):
    """
    Encapsulates working with an MariaDB database.
    
    server.py creates MetadataBroker(MariaDBBroker) which calls MariaDBBroker.__init__(),
    server.py calls MariaDBBroker.initialize(),
    if the tables do not exist server.py calls MetadataBroker._initialize()
    """
    # TODO: Retrieve IP/user/pw of load balancer from configuration file
    def __init__(self,db_ip,db_port,db_user,db_pw):
        self.conn = None
        self.db_ip = db_ip
        self.db_port = db_port
        self.db_user = db_user
        self.db_pw = db_pw
        
    # TODO: Check failure for db not exist and
    # prevent begin creation
    def initialize(self):
        """
        Create and connect to the DB
        """
        try:
            self.conn = mdb.connect(self.db_ip, self.db_user, self.db_pw, 'metadata', port=self.db_port)
        except mdb.Error as e:
            if e.args[0] == errorcode.BAD_DB_ERROR:
                self.conn = mdb.connect(self.db_ip, self.db_user, self.db_pw, port=self.db_port)
                cursor = self.conn.cursor()
                cursor.execute('CREATE DATABASE metadata')
                cursor.execute('USE metadata')
        finally:
            if not self.is_initialized():
                self._initialize()

class MetadataBroker(MariaDBBroker):

    def _initialize(self):
          """
        Initialize the database and four tables.
        Three are for system metadata of account, container and object server.
        Custom metadata are stored in key-value pair format in another table.
        """
        cur = self.conn.cursor()
        self.create_account_md_table(cur)
        self.create_container_md_table(cur)
        self.create_object_md_table(cur)
        self.create_custom_md_table(cur)
        self.conn.commit()
        
    def create_account_md_table(self, cur):
        cur.execute("""
            CREATE TABLE account_metadata (
                PRIMARY KEY(account_uri(255)),
                account_uri TEXT,
                account_name TEXT,
                account_tenant_id TEXT,
                account_first_use_time DATETIME,
                account_last_modified_time DATETIME,
                account_last_changed_time DATETIME,
                account_delete_time DATETIME,
                account_last_activity_time DATETIME,
                account_container_count INT,
                account_object_count INT,
                account_bytes_used INT
            );
        """)

    def create_container_md_table(self, cur):
        cur.execute("""
            CREATE TABLE container_metadata (
                PRIMARY KEY(container_uri(255)),
                container_uri TEXT,
                container_name TEXT,
                container_account_name TEXT,
                container_create_time DATETIME,
                container_last_modified_time DATETIME,
                container_last_changed_time DATETIME,
                container_delete_time DATETIME,
                container_last_activity_time DATETIME,
                container_read_permissions TEXT,
                container_write_permissions TEXT,
                container_sync_to TEXT,
                container_sync_key TEXT,
                container_versions_location TEXT,
                container_object_count INT,
                container_bytes_used INT
            );
        """)

    def create_object_md_table(self, cur):
        cur.execute("""
            CREATE TABLE object_metadata (
                PRIMARY KEY(object_uri(255)),
                object_uri TEXT,
                object_name TEXT,
                object_account_name TEXT,
                object_container_name TEXT,
                object_location TEXT,
                object_uri_create_time DATETIME,
                object_last_modified_time DATETIME,
                object_last_changed_time DATETIME,
                object_delete_time DATETIME,
                object_last_activity_time DATETIME,
                object_etag_hash TEXT,
                object_content_type TEXT,
                object_content_length INT,
                object_content_encoding TEXT,
                object_content_disposition TEXT,
                object_content_language TEXT,
                object_cache_control TEXT,
                object_delete_at DATETIME,
                object_manifest_type INT,
                object_manifest TEXT,
                object_access_control_allow_origin TEXT,
                object_access_control_allow_credentials TEXT,
                object_access_control_expose_headers TEXT,
                object_access_control_max_age TEXT,
                object_access_control_allow_methods TEXT,
                object_access_control_allow_headers TEXT,
                object_origin TEXT,
                object_access_control_request_method TEXT,
                object_access_control_request_headers TEXT
            );
        """)

    def create_custom_md_table(self, cur):
        cur.execute("""
            CREATE TABLE custom_metadata (
                uri TEXT NOT NULL,
                custom_key TEXT NOT NULL,
                custom_value TEXT,
                timestamp DATETIME,
                PRIMARY KEY (uri(255), custom_key(255))
            );
        """)

    def insert_custom_md(self, uri, key, value):
        query = '''
            INSERT INTO custom_metadata (
                uri,
                custom_key,
                custom_value,
                timestamp
            )
            VALUES ("%s","%s","%s","%s")
            ON DUPLICATE KEY UPDATE
                uri = "%s",
                custom_key = "%s",
                custom_value = "%s",
                timestamp = "%s"
            ;
        '''

        # Build and execute query for each requested insertion
        formatted_query = \
            query % (uri, key, value, normalize_timestamp(time.time()),uri, key, value, normalize_timestamp(time.time()))
        cur = conn.cursor()
        cur.execute(formatted_query)

    def insert_account_md(self, data):
        """Data insertion methods for account metadata table"""
        query = '''
            INSERT INTO account_metadata (
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
            )
            VALUES ("%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s")
            ON DUPLICATE KEY UPDATE
                account_uri = "%s",
                account_name = "%s",
                account_tenant_id = "%s",
                account_first_use_time = "%s",
                account_last_modified_time = "%s",
                account_last_changed_time = "%s",
                account_delete_time = "%s",
                account_last_activity_time = "%s",
                account_container_count = "%s",
                account_object_count = "%s",
                account_bytes_used = "%s"
            ;
        '''
        # Build and execute query for each requested insertion
        for item in data:
            formatted_query = query % (
                item['account_uri'],
                item['account_name'],
                item['account_tenant_id'],
                item['account_first_use_time'],
                item['account_last_modified_time'],
                item['account_last_changed_time'],
                item['account_delete_time'],
                item['account_last_activity_time'],
                item['account_container_count'],
                item['account_object_count'],
                item['account_bytes_used'],
                item['account_uri'],
                item['account_name'],
                item['account_tenant_id'],
                item['account_first_use_time'],
                item['account_last_modified_time'],
                item['account_last_changed_time'],
                item['account_delete_time'],
                item['account_last_activity_time'],
                item['account_container_count'],
                item['account_object_count'],
                item['account_bytes_used']
            )
            for custom in item:
                if(custom.startswith("account_meta")):
                    self.insert_custom_md(
                        self.conn, item['account_uri'], custom, item[custom])
            cur = self.conn.cursor()
            cur.execute(formatted_query)
            self.conn.commit()

    def insert_container_md(self, data):
        """Data insertion methods for container metadata table"""
        query = '''
            INSERT INTO container_metadata (
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
            )
            VALUES (
                "%s", "%s", "%s", "%s",
                "%s", "%s", "%s", "%s",
                "%s", "%s", "%s", "%s",
                "%s", "%s", "%s"
            )
            ON DUPLICATE KEY UPDATE
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
                container_object_count = "%s",
                container_bytes_used = "%s"
            ;
        '''
        for item in data:
            formatted_query = query % (
                item['container_uri'],
                item['container_name'],
                item['container_account_name'],
                item['container_create_time'],
                item['container_last_modified_time'],
                item['container_last_changed_time'],
                item['container_delete_time'],
                item['container_last_activity_time'],
                item['container_read_permissions'],
                item['container_write_permissions'],
                item['container_sync_to'],
                item['container_sync_key'],
                item['container_versions_location'],
                item['container_object_count'],
                item['container_bytes_used'],
                item['container_uri'],
                item['container_name'],
                item['container_account_name'],
                item['container_create_time'],
                item['container_last_modified_time'],
                item['container_last_changed_time'],
                item['container_delete_time'],
                item['container_last_activity_time'],
                item['container_read_permissions'],
                item['container_write_permissions'],
                item['container_sync_to'],
                item['container_sync_key'],
                item['container_versions_location'],
                item['container_object_count'],
                item['container_bytes_used']
            )
            for custom in item:
                if(custom.startswith("container_meta")):
                    self.insert_custom_md(
                        self.conn, item['container_uri'], custom, item[custom])
            cur = self.conn.cursor()
            cur.execute(formatted_query)
            self.conn.commit()

    def insert_object_md(self, data):
        """Data insertion methods for object metadata table"""
        query = '''
            INSERT INTO object_metadata (
                object_uri,
                object_name,
                object_account_name,
                object_container_name,
                object_location,
                object_uri_create_time,
                object_last_modified_time,
                object_last_changed_time,
                object_delete_time,
                object_last_activity_time,
                object_etag_hash,
                object_content_type,
                object_content_length,
                object_content_encoding,
                object_content_disposition,
                object_content_language,
                object_cache_control,
                object_delete_at,
                object_manifest_type,
                object_manifest,
                object_access_control_allow_origin,
                object_access_control_allow_credentials,
                object_access_control_expose_headers,
                object_access_control_max_age,
                object_access_control_allow_methods,
                object_access_control_allow_headers,
                object_origin,
                object_access_control_request_method,
                object_access_control_request_headers
            ) VALUES (
                "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s",
                "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s",
                "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"
            )
            ON DUPLICATE KEY UPDATE
                object_uri = "%s",
                object_name = "%s",
                object_account_name = "%s",
                object_container_name = "%s",
                object_location = "%s",
                object_uri_create_time = "%s",
                object_last_modified_time = "%s",
                object_last_changed_time = "%s",
                object_delete_time = "%s",
                object_last_activity_time = "%s",
                object_etag_hash = "%s",
                object_content_type = "%s",
                object_content_length = "%s",
                object_content_encoding = "%s",
                object_content_disposition = "%s",
                object_content_language = "%s",
                object_cache_control = "%s",
                object_delete_at = "%s",
                object_manifest_type = "%s",
                object_manifest = "%s",
                object_access_control_allow_origin = "%s",
                object_access_control_allow_credentials = "%s",
                object_access_control_expose_headers = "%s",
                object_access_control_max_age = "%s",
                object_access_control_allow_methods = "%s",
                object_access_control_allow_headers = "%s",
                object_origin = "%s",
                object_access_control_request_method = "%s",
                object_access_control_request_headers = "%s"
            ;
        '''
        for item in data:
            formatted_query = query % (
                item['object_uri'],
                item['object_name'],
                item['object_account_name'],
                item['object_container_name'],
                item['object_location'],
                item['object_uri_create_time'],
                item['object_last_modified_time'],
                item['object_last_changed_time'],
                item['object_delete_time'],
                item['object_last_activity_time'],
                item['object_etag_hash'],
                item['object_content_type'],
                item['object_content_length'],
                item['object_content_encoding'],
                item['object_content_disposition'],
                item['object_content_language'],
                item['object_cache_control'],
                item['object_delete_at'],
                item['object_manifest_type'],
                item['object_manifest'],
                item['object_access_control_allow_origin'],
                item['object_access_control_allow_credentials'],
                item['object_access_control_expose_headers'],
                item['object_access_control_max_age'],
                item['object_access_control_allow_methods'],
                item['object_access_control_allow_headers'],
                item['object_origin'],
                item['object_access_control_request_method'],
                item['object_access_control_request_headers'],
                item['object_uri'],
                item['object_name'],
                item['object_account_name'],
                item['object_container_name'],
                item['object_location'],
                item['object_uri_create_time'],
                item['object_last_modified_time'],
                item['object_last_changed_time'],
                item['object_delete_time'],
                item['object_last_activity_time'],
                item['object_etag_hash'],
                item['object_content_type'],
                item['object_content_length'],
                item['object_content_encoding'],
                item['object_content_disposition'],
                item['object_content_language'],
                item['object_cache_control'],
                item['object_delete_at'],
                item['object_manifest_type'],
                item['object_manifest'],
                item['object_access_control_allow_origin'],
                item['object_access_control_allow_credentials'],
                item['object_access_control_expose_headers'],
                item['object_access_control_max_age'],
                item['object_access_control_allow_methods'],
                item['object_access_control_allow_headers'],
                item['object_origin'],
                item['object_access_control_request_method'],
                item['object_access_control_request_headers']
            )
            for custom in item:
                if(custom.startswith("object_meta")):
                    self.insert_custom_md(
                        self.conn, item['object_uri'], custom, item[custom])
            cur = self.conn.cursor()
            cur.execute(formatted_query)
            self.conn.commit()

    def delete_account_md(self, uri, timestamp):
        """Nullifies fields other than last_activity/delete_time and uri"""
        query = '''
            UPDATE account_metadata SET 
                account_tenant_id = NULL,
                account_first_use_time = NULL,
                account_last_modified_time = NULL,
                account_last_changed_time = NULL,
                account_delete_time = "%s",
                account_last_activity_time = "%s",
                account_container_count = NULL,
                account_object_count = NULL,
                account_bytes_used = NULL
            WHERE
                account_uri = "%s"
            ;
        '''
        # Build and execute query for each requested insertion
        formatted_query = query % (
                timestamp,
                timestamp,
                uri
        )
        self.delete_custom_md(uri)
        cur = self.conn.cursor()
        cur.execute(formatted_query)
        self.conn.commit()
     
    def delete_container_md(self, uri, timestamp):
        """Nullifies fields other than last_activity/delete_time and uri"""
        query = '''
            UPDATE container_metadata SET
                container_name = NULL,
                container_account_name = NULL,
                container_create_time = NULL,
                container_last_modified_time = NULL,
                container_last_changed_time = NULL,
                container_delete_time = "%s",
                container_last_activity_time = "%s",
                container_read_permissions = NULL,
                container_write_permissions = NULL,
                container_sync_to = NULL,
                container_sync_key = NULL,
                container_versions_location = NULL,
                container_object_count = NULL,
                container_bytes_used = NULL
            WHERE
                container_uri = "%s"
            ;
        '''
        self.conn.commit()
        formatted_query = query % (
                timestamp,
                timestamp,
                uri
        )
        self.delete_custom_md(uri)
        cur = self.conn.cursor()
        cur.execute(formatted_query)
        self.conn.commit()

    def delete_object_md(self, uri, timestamp):
        """Nullifies fields other than last_activity/delete_time and uri"""
        query = '''
            UPDATE object_metadata SET
                object_name = NULL,
                object_account_name = NULL,
                object_container_name = NULL,
                object_location = NULL,
                object_uri_create_time = NULL,
                object_last_modified_time = NULL,
                object_last_changed_time = NULL,
                object_delete_time = "%s",
                object_last_activity_time = "%s",
                object_etag_hash = NULL,
                object_content_type = NULL,
                object_content_length = NULL,
                object_content_encoding = NULL,
                object_content_disposition = NULL,
                object_content_language = NULL,
                object_cache_control = NULL,
                object_delete_at = NULL,
                object_manifest_type = NULL,
                object_manifest = NULL,
                object_access_control_allow_origin = NULL,
                object_access_control_allow_credentials = NULL,
                object_access_control_expose_headers = NULL,
                object_access_control_max_age = NULL,
                object_access_control_allow_methods = NULL,
                object_access_control_allow_headers = NULL,
                object_origin = NULL,
                object_access_control_request_method = NULL,
                object_access_control_request_headers = NULL
            WHERE
                object_uri = "%s"
            ;
        '''
        formatted_query = query % (
                timestamp,
                timestamp,
                uri
        )
        self.delete_custom_md(uri)
        cur = self.conn.cursor()
        cur.execute(formatted_query)
        self.conn.commit()

    def delete_custom_md(self, uri):
        """Removes all custom fields assigned to uri"""
        """Nullifies fields other than last_activity/delete_time and uri"""
        query = '''
            DELETE FROM object_metadata
            WHERE
                object_uri = "%s"
            ;
        '''
        formatted_query = query % (
                uri
        )
        self.delete_custom_md(uri)
        cur = self.conn.cursor()
        cur.execute(formatted_query)
        self.conn.commit()
        
    def overwrite_account_md(self, data):
        query = "UPDATE account_metadata SET "
        inserted_fields = []
        for field in account_fields:
            if field in data:
                inserted_fields.append(str(field) + " = '" + str(data[field]) + "'")
        query += " WHERE account_uri = '" + str(data['account_uri']) + "';"
        
        cur = self.conn.cursor()
        cur.execute(formatted_query)
        self.conn.commit()

    def overwrite_container_md(self, data):
        query = "UPDATE container_metadata SET "
        inserted_fields = []
        for field in container_fields:
            if field in data:
                inserted_fields.append(str(field) + " = '" + str(data[field]) + "'")
        query += " WHERE container_uri = '" + str(data['container_uri']) + "';"
        
        cur = self.conn.cursor()
        cur.execute(formatted_query)
        self.conn.commit()
        
    def overwrite_object_md(self, data):
        query = "UPDATE object_metadata SET "
        inserted_fields = []
        for field in object_fields:
            if field in data:
                inserted_fields.append(str(field) + " = '" + str(data[field]) + "'")
        query += " WHERE object_uri = '" + str(data['object_uri']) + "';"
        
        cur = self.conn.cursor()
        cur.execute(formatted_query)
        self.conn.commit()
        
    def overwrite_custom_md(self, uri, key, value):
        query = "UPDATE custom_metadata SET"
        for field in data:
                inserted_fields.append(" custom_value = '" + str(value) + "'")
        query += " WHERE object_uri = '" + str(data['object_uri']) + "' and custom_key = '" + str(key) + "';"
        cur = self.conn.cursor()
        cur.execute(formatted_query)
        self.conn.commit()
        
    def getAll(self):
        """
        Dump everything
        """
        self.conn.row_factory = dict_factory
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM object_metadata")
        obj_data = cur.fetchall()
        cur.execute("SELECT * FROM container_metadata")
        con_data = cur.fetchall()
        cur.execute("SELECT * FROM account_metadata")
        acc_data = cur.fetchall()

        return ''.join([
            json.dumps(obj_data), "\n\n", json.dumps(con_data), "\n\n",
            json.dumps(acc_data)
        ])

    
    def get_attributes_query(self, acc, con, obj, attrs):
        """
        This query starts off the query string by adding the Attributes
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

        # JOIN all our tables together so the API can do queries
        # across tables.
        fromStr = """account_metadata
            INNER JOIN container_metadata
            ON account_name=container_account_name
            INNER JOIN object_metadata
            ON account_name=object_account_name
            AND container_name=object_container_name"""

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
            return """
                SELECT distinct %s,%s_uri
                FROM %s
                WHERE %s_uri=%s
            """ % (attrs, domain, fromStr, domain, uri)

        # Container Scope
        elif con != "" and con is not None:
            uri = "'/" + acc + "/" + con + "'"
            Auri = "'/" + acc + "'"
            if attrsStartWith(attrs) == 'object':
                return """
                    SELECT distinct %s,object_uri
                    FROM object_metadata
                    WHERE object_container_name=%s
                """ % (attrs, "'" + con + "'")

            elif attrsStartWith(attrs) == 'container':
                return """
                    SELECT distinct %s,container_uri
                    FROM %s
                    WHERE container_uri=%s
                """ % (attrs, fromStr, uri)

            elif attrsStartWith(attrs) == 'account':
                return """
                    SELECT distinct %s,account_uri
                    FROM %s
                    WHERE account_uri=%s
                """ % (attrs, fromStr, Auri)

        # Account scope
        elif acc != "" and acc is not None:
            uri = "'/" + acc + "'"
            if attrsStartWith(attrs) == 'object':
                return """
                    SELECT distinct %s,object_uri
                    FROM %s
                    WHERE object_account_name='%s'
                """ % (attrs, fromStr, acc)

            elif attrsStartWith(attrs) == 'container':
                return """
                    SELECT distinct %s,container_uri
                    FROM %s
                    WHERE container_account_name='%s'
                """ % (attrs, fromStr, acc)

            elif attrsStartWith(attrs) == 'account':
                return """
                    SELECT distinct %s,account_uri
                    FROM %s
                    WHERE account_uri=%s
                """ % (attrs, fromStr, uri)

    
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
        for i in querysplit:
            if (i.startswith("object_meta")
                        or i.startswith("container_meta")
                        or i.startswith("account_meta")):
                first = i.split("_")[0]
                key = "_".join(i.translate(maketrans("<>!=","____")).split("_")[:3])
                i = """EXISTS (SELECT * FROM custom_metadata
                        where uri == %s_uri AND custom_key='%s'
                        AND custom_value%s)""" %\
                        (first,key,i[len(key):])
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
            FROM custom_metadata
            WHERE uri='%s'
            """ % uri
            cur = self.conn.cursor()
            cur.execute(query)
            l = cur.fetchall()
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
        self.conn.row_factory = dict_factory
        cur = self.conn.cursor(mdb.cursors.DictCursor)
        cur.execute(query)
        queryList = cur.fetchall()
        retList = []
        for row in queryList:
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

    def is_initialized(self):
        """Returns true if the database has tables and is ready for use."""
        cur = self.conn.cursor()
        cur.execute("SHOW TABLES LIKE 'account_metadata'")
        row = cur.fetchone()
        return (row != None)

# TODO: Remove, possibly replaced by 
#       self.conn.cursor(mdb.cursors.DictCursor)
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
