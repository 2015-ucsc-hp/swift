# Copyright (c) 2010-2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from swift.common.swob import Request, Response
from swift.common.utils import json
from swift.proxy.controllers.base import get_container_info, get_account_info
from eventlet.green.httplib import HTTPConnection

from swift.common.utils import split_path

from swift.common.storage_policy import POLICIES

from swift.obj.diskfile import DiskFileManager, DiskFileNotExist

from swift.common.utils import get_logger

class MetaDataMiddleware(object):
    """
    Middleware for metadata queries. See OSMS API

    """

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.mds_ip = conf.get('md-server-ip', '127.0.0.1')
        self.mds_port = conf.get('md-server-port', '6090')
        self.version = 'v1'
        self.logger = get_logger(conf, log_route='object-updater')


    def __call__(self, env, start_response):
        req = Request(env)
        try:
            requestMethod = env['REQUEST_METHOD']

            if requestMethod == 'DELETE':
                def delete_start_response(status, headers):
                    if '204' in status:
                        self.DELETE(env)
                    return start_response(status, headers)
                return self.app(env, delete_start_response)

            if requestMethod == 'POST':
                def post_start_response(status, headers):
                    if '204' in status:
                        self.POST(env)
                    return start_response(status, headers)
                return self.app(env, post_start_response)

            if requestMethod == 'COPY':
                def copy_start_response(status, headers):
                    if '201' in status:
                        self.COPY(env)
                    return start_response(status, headers)
                return self.app(env, copy_start_response)

            if requestMethod == 'PUT':                    
                def put_start_response(status, headers):
                    if ('201' in status) or ('202' in status):
                        self.PUT(env)
                    return start_response(status, headers)
                return self.app(env, put_start_response)

            if 'metadata' in req.params:
                if self.versioncheck(req.params['metadata']):
                    handler = self.GET
                    return handler(req)(env, start_response)
                elif req.params['metadata'] == 'services':
                    handler = self.SERVICES
                    return handler(req)(env, start_response)
                else:
                    handler = self.BAD
                    return handler(req)(env, start_response)
        except UnicodeError:
            pass
        return self.app(env, start_response)


    def GET(self, req):
        """Handle the query request."""
        conn = HTTPConnection('%s:%s' % (self.mds_ip, self.mds_port))
        headers = req.params
        conn.request('GET', req.path, headers=headers)
        resp = conn.getresponse()
        return Response(request=req, body=resp.read(), content_type=resp.getheader('Content-Type'))

    def PUT(self, env):
        """Handle PUT requests related to metadata"""
        req = Request(env)
        conn = HTTPConnection('%s:%s' % (self.mds_ip, self.mds_port))
        headers = req.params
        try:
            info = get_container_info(env, self.app)
            if info:
                stor_policy = info['storage_policy']
                headers['storage_policy'] = stor_policy
        except:
            pass
        conn.request('PUT', req.path, headers=headers)
        resp = conn.getresponse()
        return self.app

    def DELETE(self, req):
        """Eliminate metadata for deleted objects"""
        conn = HTTPConnection('%s:%s' % (self.mds_ip, self.mds_port))
        headers = req.params
        conn.request('DELETE', req.path, headers=headers)
        resp = conn.getresponse()
        #confirm response then pass along the request
        return self.app

    def COPY(self, req):
        """Eliminate metadata for deleted objects"""
        conn = HTTPConnection('%s:%s' % (self.mds_ip, self.mds_port))
        headers = req.params
        conn.request('COPY', req.path, headers=headers)
        resp = conn.getresponse()
        #confirm response then pass along the request
        return self.app

    def POST(self, req):
        """Handle posts dealing with metadata alteration"""
        conn = HTTPConnection('%s:%s' % (self.mds_ip, self.mds_port))
        headers = req.params
        conn.request('POST', req.path, headers=headers)
        resp = conn.getresponse()
        #confirm response then pass along the request
        return self.app

    def BAD(self, req):
        """Returns a 400 for bad request"""
        return Response(request=req, status=400,
                        body="Metadata version bad\n",
                        content_type="text/plain")


#Supported version of the OSMS API Spec can be included here.
    def versioncheck(self, req_version):
        if(req_version == "v1"):
            return True
        return False

#Handler for version API call that returns supported features of API
    def SERVICES(self, req):
        body = {}
        attr_list = []

        body['min_base_api_version']   = "v1"
        body['max_base_api_version']   = "v1"
        body['search_provider']        = "HP(UCSC)"
        body['search_enabled']         = "true"
        body['min_search_api_version'] = "v1"
        body['max_search_api_version'] = self.version
        body['freshness_complete']     = "false"
        body['freshness_partial']      = "false"
        body['complex_boolean_expr']   = "true"
        body['attr_list'] = attr_list

#Account Attributes
        attr_list.append({
                "attr_name" : "account_uri",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "account_name",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "account_tenant_id",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "account_first_use_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "account_last_modified_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "account_last_changed_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "account_delete_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "account_last_activity_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "account_container_count",
                "data_type" : "numeric",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "account_object_count",
                "data_type" : "numeric",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "account_bytes_used",
                "data_type" : "numeric",
                "sortable"  : "true"})

#Container Attrobutes
        attr_list.append({
                "attr_name" : "container_uri",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "container_name",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "container_account_name",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "container_create_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "container_last_modified_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "container_last_changed_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "container_delete_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "container_last_activity_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "container_read_permissions",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "container_write_permissions",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "container_sync_to",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "container_sync_key",
                "data_type" : "string",
                "sortable"  : "true"})
#        attr_list.append({
#                "attr_name" : "container_versions_location",
#                "data_type" : "string",
#                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "container_object_count",
                "data_type" : "numeric",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "container_bytes_used",
                "data_type" : "numeric",
                "sortable"  : "true"})

#Object Attributes
        attr_list.append({
                "attr_name" : "object_uri",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_name",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_account_name",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_container_name",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_location",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_uri_create_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_last_modified_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_last_changed_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_delete_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_last_activity_time",
                "data_type" : "date",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_etag_hash",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_content_type",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_content_length",
                "data_type" : "numeric",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_content_encoding",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_content_disposition",
                "data_type" : "string",
                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_content_language",
                "data_type" : "string",
                "sortable"  : "true"})
#        attr_list.append({
#                "attr_name" : "object_cache_control",
#                "data_type" : "string",
#                "sortable"  : "true"})
        attr_list.append({
                "attr_name" : "object_delete_at",
                "data_type" : "date",
                "sortable"  : "true"})
#        attr_list.append({
#                "attr_name" : "object_manifest_type",
#                "data_type" : "numeric",
#                "sortable"  : "true"})
#        attr_list.append({
#                "attr_name" : "object_manifest",
#                "data_type" : "string",
#                "sortable"  : "true"})

#Object CORS Attributes
#        attr_list.append({
#                "attr_name" : "object_access_control_allow_origin",
#                "data_type" : "string",
#                "sortable"  : "true"})
#        attr_list.append({
#                "attr_name" : "object_access_control_allow_credentials",
#                "data_type" : "string",
#                "sortable"  : "true"})
#        attr_list.append({
#                "attr_name" : "object_access_control_expose_headers",
#                "data_type" : "string",
#                "sortable"  : "true"})
#        attr_list.append({
#                "attr_name" : "object_access_control_max_age",
#                "data_type" : "string",
#                "sortable"  : "true"})
#        attr_list.append({
#                "attr_name" : "object_access_control_allow_methods",
#                "data_type" : "string",
#                "sortable"  : "true"})
#        attr_list.append({
#                "attr_name" : "object_access_control_allow_headers",
#                "data_type" : "string",
#                "sortable"  : "true"})
#        attr_list.append({
#                "attr_name" : "object_origin",
#                "data_type" : "string",
#                "sortable"  : "true"})
#        attr_list.append({
#                "attr_name" : "object_access_control_request_method",
#                "data_type" : "string",
#                "sortable"  : "true"})
#        attr_list.append({
#                "attr_name" : "object_access_control_request_headers",
#                "data_type" : "string",
#                "sortable"  : "true"})

        body = json.dumps(body, indent=4, separators=(',', ' : '))
        return Response(request=req, body=body, content_type="json")


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def metadata_filter(app):
        return MetaDataMiddleware(app, conf)
    return metadata_filter
