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
import sys
import time
import traceback
from swift import gettext_ as _

from eventlet import Timeout
import swift.common.db

from swift.metadata.backend import MetadataBroker
from swift.common.db import DatabaseAlreadyExists

from swift.common.utils import get_logger, public, \
    config_true_value, json, timing_stats, \
    split_path, Timestamp

from swift.common.constraints import check_utf8

from swift.common.db_replicator import ReplicatorRpc

from swift.common.swob import HTTPBadRequest, HTTPConflict, \
    HTTPInternalServerError, HTTPNoContent, \
    HTTPPreconditionFailed, HTTPMethodNotAllowed, Request, Response, \
    HTTPException

from swift.metadata.utils import output_plain, output_json, output_xml, Sort_metadata, \
    format_obj_metadata, format_con_metadata, format_acc_metadata

from swift.common.constraints import valid_timestamp

from swift.common.exceptions import DiskFileQuarantined, DiskFileNotExist, \
    DiskFileCollision, DiskFileNoSpace, DiskFileDeviceUnavailable, \
    DiskFileDeleted, DiskFileError, DiskFileNotOpen, PathNotDir, \
    ReplicationLockTimeout, DiskFileExpired, DiskFileXattrNotSupported

from swift.proxy.controllers.base import get_container_info
from swift.obj.diskfile import DiskFileManager, DiskFileNotExist, get_ondisk_files
from swift.common.storage_policy import POLICIES

#container related imports
import swift.container.backend
from swift.container.server import ContainerController
from swift.common.utils import hash_path, storage_directory
from swift.common.db import DatabaseConnectionError
from swift.common.request_helpers import is_sys_or_user_meta

#account related imports
import swift.account.backend
from swift.account.server import AccountController


#delete imports
from swift.common.constraints import valid_timestamp

#MD broker
#from swift.metadata.backend import MetadataBroker

DATADIR = 'metadata'

"""
List of system attributes supported from OSMS API
"""
ACCOUNT_SYS_ATTRS = [
    'account_uri',
    'account_name',
    'account_tenant_id',
    'account_first_use_time',
    'account_last_modified_time',
    'account_last_changed_time',
    'account_delete_time',
    'account_last_activity_time',
    'account_container_count',
    'account_object_count',
    'account_bytes_used']

CONTAINER_SYS_ATTRS = [
    'container_uri',
    'container_name',
    'container_account_name',
    'container_create_time',
    'container_last_modified_time',
    'container_last_changed_time',
    'container_delete_time',
    'container_last_activity_time',
    'container_read_permissions',
    'container_write_permissions',
    'container_sync_to',
    'container_sync_key',
    'container_versions_location',
    'container_object_count',
    'container_bytes_used']

OBJECT_SYS_ATTRS = [
    'object_uri',
    'object_name',
    'object_account_name',
    'object_container_name',
    'object_location',
    'object_uri_create_time',
    'object_last_modified_time',
    'object_last_changed_time',
    'object_delete_time',
    'object_last_activity_time',
    'object_etag_hash',
    'object_content_type',
    'object_content_length',
    'object_content_encoding',
    'object_content_disposition',
    'object_content_language',
    'object_cache_control',
    'object_delete_at',
    'object_manifest_type',
    'object_manifest',
    'object_access_control_allow_origin',
    'object_access_control_allow_credentials',
    'object_access_control_expose_headers',
    'object_access_control_max_age',
    'object_access_control_allow_methods',
    'object_access_control_allow_headers',
    'object_origin',
    'object_access_control_request_method',
    'object_access_control_request_headers']


class MetadataController(object):
    """"
    WSGI Controller for metadata server
    """
    save_headers = [
        'x-metadata-read',
        'x-metadata-write',
        'x-metadata-sync-key',
        'x-metadata-sync-to'
    ]

    def __init__(self, conf, logger=None):
        # location/directory of the metadata database (meta.db)
        self.location = conf.get('location', '/srv/node/sdb1/metadata/')
        # path the the actual file
        #self.db_file = os.path.join(self.location, 'meta.db')
        self.logger = logger or get_logger(conf, log_route='metadata-server')
        self.root = conf.get('devices', '/srv/node')
        #workaround for device listings
        self.node_count = conf.get('nodecount','8')
        self.devicelist = []
        for x in range(0,int(self.node_count)):
            self.devicelist.append(conf.get('device'+str(x),''))
        self.mount_check = config_true_value(conf.get('mount_check', 'true'))
        self.node_timeout = int(conf.get('node_timeout', 3))
        self.conn_timeout = float(conf.get('node_timeout', 3))
        replication_server = conf.get('replication_server', None)
        if replication_server is not None:
            replication_server = config_true_value(replication_server)
        self.replication_server = replication_server
        self.allowed_sync_hosts = [
            h.strip()
            for h in conf.get('allowed_sync_hosts', '127.0.0.1').split(',')
            if h.strip()
        ]
        self.replicator_rpc = ReplicatorRpc(
            self.root,
            DATADIR,
            MetadataBroker,
            self.mount_check,
            logger=self.logger
        )
        
        self.diskfile_mgr = DiskFileManager(conf,self.logger)

        self.db_ip = conf.get('db_ip', '127.0.0.1')
        self.db_port = int(conf.get('db_port', 2424))
        self.db_user = conf.get('db_user', 'root')
        self.db_pw = conf.get('db_pw', 'root')

        if config_true_value(conf.get('allow_versions', 'f')):
            self.save_headers.append('x-versions-location')

        swift.common.db.DB_PREALLOCATION = config_true_value(
            conf.get('db_preallocation', 'f'))

    def _get_metadata_broker(self, **kwargs):
        """
        Returns an instance of the DB abstraction layer object (broker)
        """
        return MetadataBroker(self.db_ip,self.db_port,self.db_user,self.db_pw)

    def check_attrs(self, attrs, acc, con, obj):
        """
        Verify that attributes are valid
        Checks the attr list against a list of system attributes
        Allows for custom metadata.

        returns: boolean wether the attrs are valid
        """
        for attr in attrs.split(','):
            if attr.startswith('object_meta') or \
                    attr.startswith('container_meta') or \
                    attr.startswith('account_meta'):
                pass
            elif attr not in [
                    'object_uri',
                    'object_name',
                    'object_account_name',
                    'object_container_name',
                    'object_location',
                    'object_uri_create_time',
                    'object_last_modified_time',
                    'object_last_changed_time',
                    'object_delete_time',
                    'object_last_activity_time',
                    'object_etag_hash',
                    'object_content_type',
                    'object_content_length',
                    'object_content_encoding',
                    'object_content_disposition',
                    'object_content_language',
                    'object_cache_control',
                    'object_delete_at',
                    'object_manifest_type',
                    'object_manifest',
                    'object_access_control_allow_origin',
                    'object_access_control_allow_credentials',
                    'object_access_control_expose_headers',
                    'object_access_control_max_age',
                    'object_access_control_allow_methods',
                    'object_access_control_allow_headers',
                    'object_origin',
                    'object_access_control_request_method',
                    'object_access_control_request_headers',
                    'object_meta',
                    'container_uri',
                    'container_name',
                    'container_account_name',
                    'container_create_time',
                    'container_last_modified_time',
                    'container_last_changed_time',
                    'container_delete_time',
                    'container_last_activity_time',
                    'container_read_permissions',
                    'container_write_permissions',
                    'container_sync_to',
                    'container_sync_key',
                    'container_versions_location',
                    'container_object_count',
                    'container_bytes_used',
                    'container_meta',
                    'account_uri',
                    'account_name',
                    'account_tenant_id',
                    'account_first_use_time',
                    'account_last_modified_time',
                    'account_last_changed_time',
                    'account_delete_time',
                    'account_last_activity_time',
                    'account_container_count',
                    'account_object_count',
                    'account_bytes_used',
                    'account_meta',
                    'all_attrs',
                    'all_system_attrs',
                    'all_meta_attrs',
                    'all_account_attrs'
                    'all_account_system_attrs',
                    'all_account_meta_attrs',
                    'all_container_attrs',
                    'all_container_system_attrs'
                    'all_container_meta_attrs',
                    'all_object_attrs',
                    'all_object_system_attrs'
                    'all_object_meta_attrs']:
                return False
        return True

    @public
    @timing_stats()
    def GET(self, req):
        """
        Handle HTTP GET requests
        Build SQL queries piece by piece and then execute
        Custom attributes need to be handled specially, since they exist
        in a seperate table
        """
        broker = self._get_metadata_broker()

        base_version, acc, con, obj = split_path(req.path, 1, 4, True)
        if 'sorted' in req.headers:
            sort_value_list = req.headers['sorted']
            if sort_value_list == '':
                sort_value_list = 'uri'
            toSort = True
        else:
            toSort = False
        if 'attributes' in req.headers:
            attrs = req.headers['attributes']
        # if there is no attributes lists, include everything in scope
        # since no attributes passed in, there can be
        #  things from multiple levels of scope
        else:
            attrs = "object_uri,container_uri,account_uri"

        attrs, all_obj_meta, all_con_meta, all_acc_meta = \
            eval_superset(attrs.split(","))
        format = "text/plain"
        if self.check_attrs(attrs, acc, con, obj) or attrs == '':
            accAttrs, conAttrs, objAttrs, superAttrs, customAttrs = \
                split_attrs_by_scope(attrs)

            """
            If we have a thing from which we don't request any sys attrs
            Then we need to add its uri so that it appears in the list
            returned from the query. After we query for custom attrs,
            we need to delete any thing that is empty.
            """
            if all_obj_meta and objAttrs == "":
                objAttrs = "object_uri"
            if all_con_meta and conAttrs == "":
                conAttrs = "container_uri"
            if all_acc_meta and accAttrs == "":
                accAttrs = "account_uri"

            # Builds initial query containing the
            # split attributes for each item type
            accQuery = broker.get_attributes_query(acc, con, obj, accAttrs)
            conQuery = broker.get_attributes_query(acc, con, obj, conAttrs)
            objQuery = broker.get_attributes_query(acc, con, obj, objAttrs)

            # If there is a query in the request add it to the end
            # of the WHERE clause of the SQL
            if 'query' in req.headers:
                query = req.headers['query']
                accQuery = broker.get_uri_query(accQuery, query)
                conQuery = broker.get_uri_query(conQuery, query)
                objQuery = broker.get_uri_query(objQuery, query)

            # if successful query add the results to the end of the
            # accumulator list
            ret = []
            if not accQuery.startswith("BAD"):
                ret.extend(broker.execute_query(
                    accQuery, acc, con, obj,
                    'account_uri' in attrs.split(',')))
            if not conQuery.startswith("BAD"):
                ret.extend(broker.execute_query(
                    conQuery, acc, con, obj,
                    'container_uri' in attrs.split(',')))
            if not objQuery.startswith("BAD"):
                ret.extend(broker.execute_query(
                    objQuery, acc, con, obj,
                    'object_uri' in attrs.split(',')))

            # query the custom table
            ret = broker.custom_attributes_query(
                customAttrs, ret, all_obj_meta, all_con_meta, all_acc_meta)

            """
            Do the deletion thing mentioned above
            """
            ret = [x for x in ret if x[x.keys()[0]] != {}]

            if toSort:
                sorter = Sort_metadata()
                ret = sorter.sort_data(ret, sort_value_list.split(","))

            # default format is plain text
            # can choose between json/xml as well
            # no error handling done right now
            # just default everything to plain if spelling error
            if "format" in req.headers:
                if req.headers['format'] == "json":
                    format = "application/json"
                    out = output_json(ret)
                elif req.headers['format'] == "xml":
                    format = "application/xml"
                    out = output_xml(ret)
                else:
                    out = output_plain(ret)
            else:
                out = output_plain(ret)
            status = 200

        else:
            out = "One or more attributes not supported"
            status = 400
            format = "text/plain"

        # Returns the HTTP Response object with the result of the API request
        return Response(
            request=req, body=out + "\n", content_type=format, status=status)

    @public
    #@timing_stats()
    #TODO: reorganize code to generalize repeated calls
    #TODO: abstract data/object type names for generic calls
    def PUT(self, req):
        version, acc, con, obj = split_path(req.path, 1, 4, True)
        stor_policy = req.headers['storage_policy']
        ring = POLICIES.get_object_ring(stor_policy, '/etc/swift')
        #Handle Container PUT
        if not obj:
            hsh = hash_path(acc, con)
            part = ring.get_part(acc, con)
            db_dir = storage_directory(swift.container.backend.DATADIR, part, hsh)
            nodes = ring.get_part_nodes(part)
            for node in nodes:
                for item in self.devicelist:
                    if node['device'] in item:
                        try:
                            path = os.path.join(self.root + item, db_dir, hsh + '.db')
                            #TODO: move kwargs
                            kwargs = {'account':acc, 'container':con, 'logger':self.logger}
                            broker = swift.container.backend.ContainerBroker(path, **kwargs)
                            md = broker.get_info()
                            md.update(
                                (key, value)
                                for key, (value, timestamp) in broker.metadata.iteritems()
                                if value != '' and is_sys_or_user_meta('container', key))
                            sys_md = format_container_metadata(md)
                            user_md = format_custom_metadata(md)
                            if 'X-Container-Read' in req.headers:
                                sys_md['container_read_permissions'] = req.headers['X-Container-Read']
                            if 'X-Container-Write' in req.headers:
                                sys_md['container_write_permissions'] = req.headers['X-Container-Write']
                            #TODO: insert container_last_activity_time
                            #TODO: split meta user/sys
                            #TODO: insert meta
                            insert_container_md(sys_md)
                            return
                        except DatabaseConnectionError as e:
                            self.logger.warn("DatabaseConnectionError: " + e.path + "\n")
                            pass
                        except:
                            self.logger.warn("%s: %s\n"%(str(sys.exc_info()[0]),str(sys.exc_info()[1])))
                            pass
        #handle object PUT
        else:
            part = ring.get_part(acc, con, obj)
            nodes = ring.get_part_nodes(part)
            for node in nodes:
                for item in self.devicelist:
                    if node['device'] in item:
                        try:
                            df = self.diskfile_mgr.get_diskfile(item, part, acc, con, obj, stor_policy)
                            md = df.read_metadata()
                            sys_md = format_obj_metadata(md)
                            #df._data_file is a direct path to the objects data
                            sys_md['object_location'] = df._data_file
                            user_md = format_custom_metadata(md)
                            #TODO: insert user meta and sys meta
                        except:
                            self.logger.warn("%s: %s\n"%(str(sys.exc_info()[0]),str(sys.exc_info()[1])))
                            pass
        return

    @public
    @timing_stats()
    def DELETE(self, req):
        version, acc, con, obj = split_path(req.path, 1, 4, True)
        timestamp = Timestamp(time.time()).isoformat()
        data_type = ''
        if not con and not obj:
            #do nothing. accounts cannot be deleted
            return
        elif not obj:
            md = build_con_metadata(md)
            md['container_delete_time'] = timestamp
            md['container_last_activity_time'] = timestamp
            data_type = 'container'
            for item in \
                (data_type + '_uri', data_type + '_name'):
                if item in md:
                    del md[item]
            #TODO: overwrite container metadata
            #TODO: delete container custom metadata
        else:
            md = build_obj_metadata(md)
            md['object_delete_time'] = timestamp
            md['object_last_activity_time'] = timestamp
            data_type = 'object'
            for item in \
                (data_type + '_uri', data_type + '_name'):
                if item in md:
                    del md[item]
            #TODO: overwrite object metadata
            #TODO: delete object user meta
        return
        
            
            
    #TODO: generalize strings used for repeat calls
    @public
    #@timing_stats()
    def POST(self, req):
        version, acc, con, obj = split_path(req.path, 1, 4, True)
        stor_policy = req.headers['storage_policy']
        ring = POLICIES.get_object_ring(stor_policy, '/etc/swift')
        if not con and not obj:
            meta_type = 'account'
            kwargs = {'account':acc, 'logger':self.logger}
            data_dir = swift.account.backend.DATADIR
            hsh = hash_path(acc)
            part = ring.get_part(acc)
            db_dir = storage_directory(data_dir, part, hsh)
            nodes = ring.get_part_nodes(part)
            for node in nodes:
                for item in self.devicelist:
                    if node['device'] in item:
                        try:
                            path = os.path.join(self.root + item, db_dir, hsh + '.db')
                            broker = swift.account.backend.AccountBroker(path, **kwargs)
                            md = broker.get_info()
                            md.update(
                                (key, value)
                                for key, (value, timestamp) in broker.metadata.iteritems()
                                if value != '' and is_sys_or_user_meta(meta_type, key))
                            sys_md = format_acc_metadata(md)
                            user_md = format_custom_metadata(md)
                            #TODO: call overwrite_account_metadata
                            #TODO: call overwrite_custom_metadata
                            return
                        except:
                            self.logger.warn("%s: %s\n"%(str(sys.exc_info()[0]),str(sys.exc_info()[1])))
                            pass
        #Handle Container POST
        elif not obj:
            meta_type = 'container'
            kwargs = {'account':acc, 'container':con, 'logger':self.logger}
            data_dir = swift.container.backend.DATADIR
            try:
                hsh = hash_path(acc, con)
                part = ring.get_part(acc, con)
                db_dir = storage_directory(data_dir, part, hsh)
                nodes = ring.get_part_nodes(part)
                for node in nodes:
                    for item in self.devicelist:
                        if node['device'] in item:
                            try:
                                path = os.path.join(self.root + item, db_dir, hsh + '.db')
                                broker = swift.container.backend.ContainerBroker(path, **kwargs)
                                md = broker.get_info()
                                md.update(
                                    (key, value)
                                    for key, (value, timestamp) in broker.metadata.iteritems()
                                    if value != '' and is_sys_or_user_meta('container', key))
                                sys_md = format_con_metadata(md)
                                user_md = format_custom_metadata(md)
                                if 'X-Container-Read' in req.headers:
                                    sys_md['container_read_permissions'] = req.headers['X-Container-Read']
                                    if 'X-Container-Write' in req.headers:
                                        sys_md['container_write_permissions'] = req.headers['X-Container-Write']
                            #TODO: call overwrite_container_metadata
                            #TODO: call overwrite_custom_metadata
                                        return
                            except DatabaseConnectionError as e:
                                self.logger.warn("DatabaseConnectionError: " + e.path + "\n")
                                pass
            except:
                self.logger.warn("%s: %s\n"%(str(sys.exc_info()[0]),str(sys.exc_info()[1])))
                pass
        else:
            part = ring.get_part(acc, con, obj)
            nodes = ring.get_part_nodes(part)
            for node in nodes:
                for item in self.devicelist:
                    if node['device'] in item:
                        try:
                            df = self.diskfile_mgr.get_diskfile(item, part, acc, con, obj, stor_policy)
                            md = df.read_metadata()
                            sys_md = format_obj_metadata(md)
                            user_md = format_custom_metadata(md)
                            #TODO: call overwrite_object_metadata
                            #TODO: call overwrite_custom_metadata
                        except:
                            self.logger.warn("%s: %s\n"%(str(sys.exc_info()[0]),str(sys.exc_info()[1])))
                            pass
        return


    @public
    @timing_stats()
    def COPY(self, req):
        version, acc, con, obj = split_path(req.path, 1, 4, True)
        


    def __call__(self, env, start_response):
        """
        Boilerplate code for how the server's code gets called
        upon receiving a request.
        Taken directly from other servers.
        """
        # start_time = time.time()
        req = Request(env)
        self.logger.txn_id = req.headers.get('x-trans-id', None)
        if not check_utf8(req.path_info):
            res = HTTPPreconditionFailed(body='Invalid UTF8 or contains NULL')
        else:
            try:
                # disallow methods which have not been marked 'public'
                try:
                    method = getattr(self, req.method)
                    getattr(method, 'publicly_accessible')
                    replication_method = getattr(method, 'replication', False)
                    if (self.replication_server is not None and
                            self.replication_server != replication_method):
                        raise AttributeError('Not allowed method.')
                except AttributeError:
                    res = HTTPMethodNotAllowed()
                else:
                    res = method(req)
            except HTTPException as error_response:
                res = error_response
            except (Exception, Timeout):
                self.logger.exception(_(
                    'ERROR __call__ error with %(method)s %(path)s '),
                    {'method': req.method, 'path': req.path})
                res = HTTPInternalServerError(body=traceback.format_exc())
        # trans_time = '%.4f' % (time.time() - start_time)
        # if self.log_requests:
        #     log_message = '%s - - [%s] "%s %s" %s %s "%s" "%s" "%s" %s' % (
        #         req.remote_addr,
        #         time.strftime('%d/%b/%Y:%H:%M:%S +0000',
        #                       time.gmtime()),
        #         req.method, req.path,
        #         res.status.split()[0], res.content_length or '-',
        #         req.headers.get('x-trans-id', '-'),
        #         req.referer or '-', req.user_agent or '-',
        #         trans_time)
        #     if req.method.upper() == 'REPLICATE':
        #         self.logger.debug(log_message)
        #     else:
        #         self.logger.info(log_message)
        return res(env, start_response)


def split_attrs_by_scope(attrs):
    """
    Take the list of attributes and split them by object,container,account,
    superset, and custom.
    Reuturns a tuple of attribute strings.
    """
    acc_star = []
    con_star = []
    obj_star = []
    all_star = []
    custom_star = []
    for attr in attrs.split(','):
        if attr != "" or attr is not None:
            if attr.startswith('object_meta') or \
                    attr.startswith('container_meta') or \
                    attr.startswith('account_meta'):
                custom_star.append(attr)
            elif attr.startswith('object'):
                obj_star.append(attr)
            elif attr.startswith('container'):
                con_star.append(attr)
            elif attr.startswith('account'):
                acc_star.append(attr)
            elif attr.startswith('all'):
                all_star.append(attr)
    return (",".join(acc_star), ",".join(con_star), ",".join(obj_star),
            ",".join(all_star), ",".join(custom_star))


def app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating WSGI container server apps"""
    conf = global_conf.copy()
    conf.update(local_conf)
    return MetadataController(conf)


def eval_superset(attrs):
    """
    Take in the list of attrs and iterate through
    the list and if there is a superset attrs
    replace it with the set of attrs represented
    through by the superset attr

    If custom metadata superset attr is included,
    also return a boolean for wether or not
    to include all metadata for obj/con/acc
    since it is not possible to add these
    to the attr list. These flags will
    be used later in the query to the
    custom table

    Returns the expanded attrs as a string, along with the bool vals.
    """
    expanded = set()
    cust_obj = False
    cust_con = False
    cust_acc = False
    for attr in attrs:
        if attr == "all_attrs":
            expanded = expanded.union(set(ACCOUNT_SYS_ATTRS))
            expanded = expanded.union(set(CONTAINER_SYS_ATTRS))
            expanded = expanded.union(set(OBJECT_SYS_ATTRS))
            cust_acc = True
            cust_con = True
            cust_obj = True
        elif attr == "all_system_attrs":
            expanded = expanded.union(set(ACCOUNT_SYS_ATTRS))
            expanded = expanded.union(set(CONTAINER_SYS_ATTRS))
            expanded = expanded.union(set(OBJECT_SYS_ATTRS))
        elif attr == "all_meta_attrs":
            cust_acc = True
            cust_con = True
            cust_obj = True

        elif attr == "all_account_attrs":
            expanded = expanded.union(set(ACCOUNT_SYS_ATTRS))
            cust_acc = True
        elif attr == "all_account_system_attrs":
            expanded = expanded.union(set(ACCOUNT_SYS_ATTRS))
        elif attr == "all_account_meta_attrs":
            cust_acc = True

        elif attr == "all_container_attrs":
            expanded = expanded.union(set(CONTAINER_SYS_ATTRS))
            cust_con = True
        elif attr == "all_container_system_attrs":
            expanded = expanded.union(set(CONTAINER_SYS_ATTRS))
        elif attr == "all_container_meta_attrs":
            cust_con = True

        elif attr == "all_object_attrs":
            expanded = expanded.union(set(OBJECT_SYS_ATTRS))
            cust_obj = True
        elif attr == "all_object_system_attrs":
            expanded = expanded.union(set(OBJECT_SYS_ATTRS))
        elif attr == "all_object_meta_attrs":
            cust_obj = True
        else:
            expanded.add(attr)
    return (",".join(list(expanded)), cust_obj, cust_con, cust_acc)
