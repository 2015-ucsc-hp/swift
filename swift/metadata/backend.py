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
from swift.common.db import DatabaseBroker
from swift.common.utils import json


class MetadataBroker(DatabaseBroker):
    """ 
    initialize the database and four tables.
    Three are for system metadata of account, container and object server. 
    custom metadata are stored in key-value pair format in another table.
    """
    type = 'metadata'
    db_contains_type = 'object'
    db_reclaim_timestamp = 'created_at'

    
    def _initialize(self, conn, timestamp):
        self.create_account_md_table(conn)
        self.create_container_md_table(conn)
        self.create_object_md_table(conn)
        self.create_custom_md_table(conn)

    def create_account_md_table(self, conn):
        conn.executescript("""
            CREATE TABLE account_metadata (
                account_uri TEXT PRIMARY KEY,
                account_name TEXT,
                account_tenant_id TEXT,
                account_first_use_time TEXT DEFAULT '0',
                account_last_modified_time TEXT DEFAULT '0',
                account_last_changed_time TEXT DEFAULT '0',
                account_delete_time TEXT DEFAULT '0',
                account_last_activity_time TEXT DEFAULT '0',
                account_container_count INTEGER,
                account_object_count INTEGER,
                account_bytes_used INTEGER
            );
        """)

    def create_container_md_table(self, conn):
        conn.executescript("""
            CREATE TABLE container_metadata (
                container_uri TEXT PRIMARY KEY,
                container_name TEXT,
                container_account_name TEXT,
                container_create_time TEXT DEFAULT '0',
                container_last_modified_time TEXT DEFAULT '0',
                container_last_changed_time TEXT DEFAULT '0',
                container_delete_time TEXT DEFAULT '0',
                container_last_activity_time TEXT DEFAULT '0',
                container_read_permissions TEXT,
                container_write_permissions TEXT,
                container_sync_to TEXT,
                container_sync_key TEXT,
                container_versions_location TEXT,
                container_object_count INTEGER,
                container_bytes_used INTEGER
            );
        """)

    def create_object_md_table(self, conn):
        conn.executescript("""
            CREATE TABLE object_metadata (
                object_uri TEXT PRIMARY KEY,
                object_name TEXT,
                object_account_name TEXT,
                object_container_name TEXT,
                object_location TEXT,
                object_uri_create_time TEXT DEFAULT '0',
                object_last_modified_time TEXT DEFAULT '0',
                object_last_changed_time TEXT DEFAULT '0',
                object_delete_time TEXT DEFAULT '0',
                object_last_activity_time TEXT DEFAULT '0',
                object_etag_hash TEXT,
                object_content_type TEXT,
                object_content_length INTEGER,
                object_content_encoding TEXT,
                object_content_disposition TEXT,
                object_content_language TEXT,
                object_cache_control TEXT,
                object_delete_at TEXT DEFAULT '0',
                object_manifest_type INTEGER,
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

    def create_custom_md_table(self, conn):
        conn.executescript("""
            CREATE TABLE custom_metadata (
                uri TEXT NOT NULL,
                custom_key TEXT NOT NULL,
                custom_value TEXT,
                timestamp TEXT,
                PRIMARY KEY (uri, custom_key)
            );
        """)

    def insert_custom_md(self, conn, uri, key, value):
        query = '''
            INSERT OR REPLACE INTO custom_metadata (
                uri,
                custom_key,
                custom_value,
                timestamp
            )
            VALUES ("%s","%s","%s","%s")
            ;
        '''

        # Build and execute query for each requested insertion
        formatted_query = \
            query % (uri, key, value, normalize_timestamp(time.time()))
        conn.execute(formatted_query)


    def insert_account_md(self, data):
        """Data insertion methods for account metadata table"""
        with self.get() as conn:
            query = '''
                INSERT OR REPLACE INTO account_metadata (
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
                ;
            '''
            # Build and execute query for each requested insertion
            conn.commit()
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
                    item['account_bytes_used']
                )
                for custom in item:
                    if(custom.startswith("account_meta")):
                        self.insert_custom_md(
                            conn, item['account_uri'], custom, item[custom])
                conn.execute(formatted_query)
            conn.commit()

    def insert_container_md(self, data):
        """Data insertion methods for container metadata table"""
        with self.get() as conn:
            query = '''
                INSERT OR REPLACE INTO container_metadata (
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
                ;
            '''
            conn.commit()
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
                    item['container_bytes_used']
                )
                for custom in item:
                    if(custom.startswith("container_meta")):
                        self.insert_custom_md(
                            conn, item['container_uri'], custom, item[custom])
                conn.execute(formatted_query)
            conn.commit()

    def insert_object_md(self, data):
        """Data insertion methods for object metadata table"""
        with self.get() as conn:
            query = '''
                INSERT OR REPLACE INTO object_metadata (
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
                ;
            '''
            conn.commit()
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
                    item['object_access_control_request_headers']
                )
                for custom in item:
                    if(custom.startswith("object_meta")):
                        self.insert_custom_md(
                            conn, item['object_uri'], custom, item[custom])
                conn.execute(formatted_query)
            conn.commit()

    def getAll(self):
        """
        Dump everything
        """
        with self.get() as conn:
            conn.row_factory = dict_factory
            cur = conn.cursor()
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
        with self.get() as conn:
            for x in sysMetaList:
                uri = x.keys()[0]
                query = """SELECT custom_key, custom_value
                FROM custom_metadata
                WHERE uri='%s'
                """ % uri
                cur = conn.cursor()
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
        with self.get() as conn:
            conn.row_factory = dict_factory
            cur = conn.cursor()
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

    def is_deleted(self, mdtable, timestamp=None):
        '''
        Determine whether a DB is considered deleted
        :param mdtable: a string representing the relevant object type
            (account, container, object)
        :returns: True if the DB is considered deleted, False otherwise
        '''
        if self.db_file != ':memory:' and not os.path.exists(self.db_file):
            return True
        self._commit_puts_stale_ok()
        return False

    def empty(self):
        """
        Check if the Metadata DB is empty.
        :returns: True if the database has no metadata.
        """
        self._commit_puts_stale_ok()
        with self.get() as conn:
            row = conn.execute(
                'SELECT account_container_count from account_metadata'). \
                fetchone()
            return (row[0] == 0)



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
