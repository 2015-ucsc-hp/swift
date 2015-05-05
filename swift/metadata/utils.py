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

from swift.common.exceptions import ConnectionTimeout
from swift.common.http import HTTP_INTERNAL_SERVER_ERROR
from swift.common.utils import json
from eventlet import Timeout
from eventlet.green.httplib import HTTPConnection
from collections import OrderedDict
import operator


class Sender():

    def __init__(self, conf):

        self.conn_timeout = float(conf.get('conn_timeout', 3))

    def sendData(self, metaList, data_type, server_ip, server_port):
        ip = server_ip
        port = server_port
        updatedData = json.dumps(metaList)
        headers = {'user-agent': data_type}
        with ConnectionTimeout(self.conn_timeout):
            try:
                conn = HTTPConnection('%s:%s' % (ip, port))
                conn.request('PUT', '/', headers=headers, body=updatedData)
                resp = conn.getresponse()
                return resp
            except (Exception, Timeout):
                return HTTP_INTERNAL_SERVER_ERROR

def format_obj_metadata(data):
        metadata = {}
        uri = data['name'].split("/")
        metadata['object_uri'] = data['name']
        metadata['object_name'] = ("/".join(uri[3:]))
        metadata['object_account_name'] = uri[1]
        metadata['object_container_name'] = uri[2]
        #Attribute added post-format in the PUT handler of the server
        metadata['object_location'] = 'NULL'
        metadata['object_uri_create_time'] = \
            data.setdefault('X-Timestamp', 'NULL')

        metadata['object_last_modified_time'] = \
            data.setdefault('X-Timestamp', 'NULL')

        metadata['object_last_changed_time'] = 'NULL'

        metadata['object_delete_time'] = 'NULL'

        metadata['object_last_activity_time'] = \
            data.setdefault('X-Timestamp', 'NULL')

        metadata['object_etag_hash'] = \
            data.setdefault('ETag', 'NULL')

        metadata['object_content_type'] = \
            data.setdefault('Content-Type', 'NULL')

        metadata['object_content_length'] = \
            data.setdefault('Content-Length', 'NULL')

        metadata['object_content_encoding'] = \
            data.setdefault('Content-Encoding', 'NULL')

        metadata['object_content_disposition'] = \
            data.setdefault('Content-Disposition', 'NULL')

        metadata['object_content_language'] = \
            data.setdefault('Content-Langauge', 'NULL')

        metadata['object_cache_control'] = 'NULL' 

        metadata['object_delete_at'] = \
            data.setdefault('X-Delete-At', 'NULL')

        metadata['object_manifest_type'] = 'NULL'
        metadata['object_manifest'] = 'NULL'
        metadata['object_access_control_allow_origin'] = 'NULL'
        metadata['object_access_control_allow_credentials'] = 'NULL'
        metadata['object_access_control_expose_headers'] = 'NULL'
        metadata['object_access_control_max_age'] = 'NULL'
        metadata['object_access_control_allow_methods'] = 'NULL'
        metadata['object_access_control_allow_headers'] = 'NULL'
        metadata['object_origin'] = 'NULL'
        metadata['object_access_control_request_method'] = 'NULL'
        metadata['object_access_control_request_headers'] = 'NULL'

        #Insert all Object custom metadata
        for custom in data:
            if(custom.startswith("X-Object-Meta")):
                sanitized_custom = custom[2:13].lower() + custom[13:]
                sanitized_custom = sanitized_custom.replace('-', '_')
                metadata[sanitized_custom] = data[custom]

        return metadata

def format_con_metadata(data):
    metadata = {}
    uri = "/" + data['account'] + "/" + data['container']
    metadata['container_uri'] = uri
    metadata['container_name'] = data['container']
    metadata['container_account_name'] = data['account']
    metadata['container_create_time'] = data.setdefault('created_at', 'NULL')
    metadata['container_last_modified_time'] = \
        data.setdefault('put_timestamp', 'NULL')

    metadata['container_last_changed_time'] = \
        data.setdefault('put_timestamp', 'NULL')

    metadata['container_delete_time'] = \
        data.setdefault('delete_timestamp', 'NULL')

    metadata['container_last_activity_time'] = \
        data.setdefault('put_timestamp', 'NULL')

        #last_activity_time needs to be updated on meta server
    metadata['container_read_permissions'] = 'NULL'  # Not Implemented yet
    metadata['container_write_permissions'] = 'NULL'
    metadata['container_sync_to'] = \
        data.setdefault('x_container_sync_point1', 'NULL')

    metadata['container_sync_key'] = \
        data.setdefault('x_container_sync_point2', 'NULL')

    metadata['container_versions_location'] = 'NULL'
    metadata['container_object_count'] = \
        data.setdefault('object_count', 'NULL')

    metadata['container_bytes_used'] = \
        data.setdefault('bytes_used', 'NULL')

    metadata['container_delete_at'] = \
        data.setdefault('delete_timestamp', 'NULL')

    #Insert all Container custom metadata
    for custom in data:
        if(custom.startswith("X-Container-Meta")):
            sanitized_custom = custom[2:16].lower() + custom[16:]
            sanitized_custom = sanitized_custom.replace('-', '_')
            metadata[sanitized_custom] = data[custom]
    return metadata

def format_acc_metadata(data):
    metadata = {}
    uri = "/" + data['account']
    metadata['account_uri'] = uri
    metadata['account_name'] = data['account']
    metadata['account_tenant_id'] = data.setdefault('id', 'NULL')
    metadata['account_first_use_time'] = data.setdefault('created_at', 'NULL')
    metadata['account_last_modified_time'] = \
        data.setdefault('put_timestamp', 'NULL')

    metadata['account_last_changed_time'] =  \
        data.setdefault('put_timestamp', 'NULL')

    metadata['account_delete_time'] = \
        data.setdefault('delete_timestamp', 'NULL')

    metadata['account_last_activity_time'] = \
        data.setdefault('put_timestamp', 'NULL')

    metadata['account_container_count'] = \
        data.setdefault('container_count', 'NULL')

    metadata['account_object_count'] = \
        data.setdefault('object_count', 'NULL')

    metadata['account_bytes_used'] = data.setdefault('bytes_used', 'NULL')

    #Insert all Account custom metadata
    for custom in data:
        if(custom.lower().startswith("x-account-meta")):
            sanitized_custom = custom[2:14].lower() + custom[14:]
            sanitized_custom = sanitized_custom.replace('-', '_')
            metadata[sanitized_custom] = data[custom]
    return metadata

def output_xml(metaList):
    """
    Converts the list of dicts into XML format
    """
    out = '<?xml version="1.0" encoding="UTF-8"?>\n\n'
    out += "<metadata>" +'\n'

    for d in metaList:
        uri = d.keys()[0]
        c = len(uri.split('/'))
        if c == 2:
            level = "account"
        elif c == 3:
            level = "container"
        elif c >= 4:
            level = "object"
            
        out += "<" + level + ' uri="' + uri + '">\n'
        
        for k in d[uri].keys():
            val = d[uri][k]
            out += "    <" + k + ">" + str(val) + "</" + k + ">\n"
        
        out += "</" + level + ">\n"
    out += "</metadata>" + '\n'
    return out

def output_plain(metaList):
    """
    Converts the list of dicts into a plain text format
    """
    out = ""
    for d in metaList:
        uri = d.keys()[0]
        out += uri + '\n'
        for k in d[uri].keys():
            val = d[uri][k]
            out += "    " + k + ":" + str(val) + '\n'
    return out 

def output_json(metaList):
    """
    Converts the list of dicts into a JSON format 
    """
    return json.dumps(metaList, indent=4, separators=(',', ' : '))

class Sort_metadata():
    def sort_data_helper(self, attr_list, sort_value):
        """
        Unitary function to help main function to sort one value at a time
        param attr_list:The list of unsorted dictionaries of custom metadata
        param sort_value: the sorting attribute set by user
        returns: The list of sorted dictionaries
        """
        dict1 = {}
        dict2 = {}
        dict3 = {}
        index_list = []
        return_list = []
        j=0
        h=0

        """Default: if no set sort_value then sort by uri"""
        if sort_value == "uri":
            for i in range(len(attr_list)):
                dict1 = attr_list[i]
                """parsed list of dictionaries into a new dictionary"""
                for d in dict1:
                    dict2[i] = d
            sorted_dict = sorted(dict2.iteritems(), key=operator.itemgetter(1))
            for k in range(len(sorted_dict)):
                index_list.append(sorted_dict[k][0])
                return_list.append(attr_list[index_list[k]])
            return return_list

        """sort_value defined: sort by attribute"""
        for i in range(len(attr_list)):
            """parsed list of dictionaries into a new dictionary """
            dict1 = attr_list[i]
            for d in dict1:
                dict2 = dict1[d]
                for d in dict2:
                    """Extract by only sort_value parameter (key)"""
                    if d == sort_value:
                        dict3[i]= dict2[d]
                        """store values from dictionaries as key in new dictionary to pass for sorting"""
        sorted_dict = sorted(dict3.iteritems(), key=operator.itemgetter(1))

        """Get indexes of the targetted entry for sorted attributes from the original list """
        for k in range(len(sorted_dict)):
            index_list.append(sorted_dict[k][0])
            return_list.append(attr_list[index_list[k]])

        """Appending the sorted attributes into original dictionary into the right indexes"""
        for h in range(len(attr_list)):
            if not(h in index_list):
                return_list.append(attr_list[h])

        return return_list

#
    def sort_data (self,attr_list,sort_value_list):
        """
        Sorts custom metadata by more than one sorting attributes given by user
        Param attr_list: The list of unsorted dictionaries of custom metadata
        Param sort_value_list: List of more than one sorting attribute given by user
        Returns: The list of sorted dictionaries by more than one sorting attribute
        """

        return_list = []
        if sort_value_list == ['']:
            return_list=self.sort_data_helper (attr_list,"uri")
        #
        if len(sort_value_list)>0:
            unsorted_list = []
            dup_value_dict = {}
            dict1 = {}
            dict2 = {}
            dict3 = {}
            k = 0;
            for i in range(len(sort_value_list)):
                if i==0:
                    return_list=self.sort_data_helper(attr_list,sort_value_list[i])
                else:
                    dup_value_list=[]
                    dup_index_list = []
                    sort_value=sort_value_list[i]
                    for j in range(len(return_list)):
                        dict1 = return_list[j]
                        for d in dict1:
                            dict2 = dict1[d]
                            if dict2.has_key(sort_value_list[i-1]):
                                if dict2[sort_value_list[i-1]] in dup_value_dict:
                                    dup_value_dict[dict2[sort_value_list[i-1]]].append(j)
                                else:
                                    dup_value_dict[(dict2[sort_value_list[i-1]])]= [j]
                    #sort only duplicate attributes extracted from sort_data_helper based on multiple sorting parameters
                    for key in dup_value_dict:
                        if len(dup_value_dict[key])>1:
                            ind_list = dup_value_dict[key]
                            unsort_value_list = []
                            for k in range(len(ind_list)):
                                unsort_value_list.append(return_list[ind_list[k]])
                                sorted_value_list = self.sort_data_helper(unsort_value_list,sort_value_list[i])
                            #Add the sorted list back to original dictionary based on indexes
                            for h in range(len(sorted_value_list)):
                                return_list[ind_list[h]]=sorted_value_list[h]
        return return_list
