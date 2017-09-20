import httplib
import json

from tornado import httpclient
from tornado.gen import coroutine, Return
from tornado.httpclient import HTTPError

from pywebhdfs import errors, operations


class PyWebHdfsClient(object):
    """
    PyWebHdfsClient is a Python wrapper for the Hadoop WebHDFS REST API

    To use this Tornado client:

    >>> from pywebhdfs.tornado.webhdfs import PyWebHdfsClient
    """

    def __init__(
            self, host='localhost', port='50070', user_name=None,
            krb_instance=None, base_uri_pattern='http://{host}:{port}/webhdfs/v1/',
            ca_trust_bundle='/etc/ssl/certs/ca-certificates.crt', **kwargs):
        """
        Create a new client for interacting with WebHDFS

        :param host: the ip address or hostname of the HDFS namenode
        :param port: the port number for WebHDFS on the namenode
        :param user_name: WebHDFS user.name used for authentication
        :param base_uri_pattern: format string for base webhdfs URI
        :param cert_store: bundle of trusted certificates to use when making https
        requests to WebHDFS. This bundle must include the namenode and datanode certs if
        SSL is enabled for HDFS

        >>> hdfs = PyWebHdfsClient(host='host',port='50070', user_name='hdfs')
        """

        self.host = host
        self.port = port
        self.user_name = user_name
        self.krb_instance = krb_instance
        self.krb_primary = kwargs.pop('krb_primary', 'HTTP')
        self.request_options = self._pop_request_options(kwargs)
        self.request_options['ca_certs'] = ca_trust_bundle

        # create base uri to be used in request operations
        self.base_uri = base_uri_pattern.format(host=self.host, port=self.port)

        # create our asynchronous client
        self.http_client = httpclient.AsyncHTTPClient()

    @staticmethod
    def _pop_request_options(kwargs):
        return dict(
            connect_timeout=kwargs.pop('connect_timeout', None),
            request_timeout=kwargs.pop('request_timeout', None)
        )

    @coroutine
    def create_file(self, path, file_data, **kwargs):
        """
        Creates a new file on HDFS

        :param path: the HDFS file path without a leading '/'
        :param file_data: the initial data to write to the new file

        The function wraps the WebHDFS REST call:

        PUT http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=CREATE

        [&overwrite=<true|false>][&blocksize=<LONG>][&replication=<SHORT>]
        [&permission=<OCTAL>][&buffersize=<INT>]

        The function accepts all WebHDFS optional arguments shown above

        Example:

        >>> hdfs = PyWebHdfsClient(host='host',port='50070', user_name='hdfs')
        >>> my_data = '01010101010101010101010101010101'
        >>> my_file = 'user/hdfs/data/myfile.txt'
        >>> hdfs.create_file(my_file, my_data)

        Example with optional args:

        >>> hdfs.create_file(my_file, my_data, overwrite=True, blocksize=64)

        Or for sending data from file like objects:

        >>> with open('file.data') as file_data:
        >>>     hdfs.create_file(hdfs_path, data=file_data)


        Note: The create_file function does not follow automatic redirects but
        instead uses a two step call to the API as required in the
        WebHDFS documentation
        """

        headers = dict()
        if self.krb_instance:
            headers['Authorization'] = self.krb_instance.acquire_kerberos_ticket(self.krb_primary, self.host)

        # make the initial CREATE call to the HDFS namenode
        optional_args = kwargs
        uri = self._create_uri(path, operations.CREATE, **optional_args)
        request = httpclient.HTTPRequest(
            uri, method='PUT', follow_redirects=False, body='', headers=headers, **self.request_options)
        # we are expecting a temporary redirect exception
        try:
            init_response = yield self.http_client.fetch(request)
        except HTTPError as e:
            init_response = e.response

        if not init_response.code == httplib.TEMPORARY_REDIRECT:
            _raise_pywebhdfs_exception(
                init_response.code, init_response.body)

        # Get the address provided in the location header of the
        # initial response from the namenode and make the CREATE request
        # to the datanode
        uri = init_response.headers['location']
        headers['Content-Type'] = 'application/octet-stream'
        # NOTE! We need to acquire a new ticket otherwise Kerberos will suspect a replay
        # and reject our next request
        if self.krb_instance:
            headers['Authorization'] = self.krb_instance.acquire_kerberos_ticket(self.krb_primary, self.host)
        request = httpclient.HTTPRequest(uri, method='PUT', body=file_data, headers=headers, **self.request_options)
        response = yield self.http_client.fetch(request)

        if not response.code == httplib.CREATED:
            _raise_pywebhdfs_exception(response.code, response.body)

        raise Return(True)

    @coroutine
    def append_file(self, path, file_data, **kwargs):
        """
        Appends to an existing file on HDFS

        :param path: the HDFS file path without a leading '/'
        :param file_data: data to append to existing file

        The function wraps the WebHDFS REST call:

        POST http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=APPEND

        [&buffersize=<INT>]

        The function accepts all WebHDFS optional arguments shown above

        Example:

        >>> hdfs = PyWebHdfsClient(host='host',port='50070', user_name='hdfs')
        >>> my_data = '01010101010101010101010101010101'
        >>> my_file = 'user/hdfs/data/myfile.txt'
        >>> hdfs.append_file(my_file, my_data)

        Example with optional args:

        >>> hdfs.append_file(my_file, my_data, overwrite=True, buffersize=4096)

        Note: The append_file function does not follow automatic redirects but
        instead uses a two step call to the API as required in the
        WebHDFS documentation

        Append is not supported in Hadoop 1.x
        """

        headers = dict()
        if self.krb_instance:
            headers['Authorization'] = self.krb_instance.acquire_kerberos_ticket(self.krb_primary, self.host)

        # make the initial APPEND call to the HDFS namenode
        optional_args = kwargs
        uri = self._create_uri(path, operations.APPEND, **optional_args)
        request = httpclient.HTTPRequest(
            uri, method='POST', follow_redirects=False, body='', headers=headers, **self.request_options)
        # we are expecting a temporary redirect here
        try:
            init_response = yield self.http_client.fetch(request)
        except HTTPError as e:
            init_response = e.response

        if not init_response.code == httplib.TEMPORARY_REDIRECT:
            _raise_pywebhdfs_exception(
                init_response.code, init_response.body)

        # Get the address provided in the location header of the
        # initial response from the namenode and make the APPEND request
        # to the datanode
        uri = init_response.headers['location']
        headers['Content-Type'] = 'application/octet-stream'
        # NOTE! We need to acquire a new ticket otherwise Kerberos will suspect a replay
        # and reject our next request
        if self.krb_instance:
            headers['Authorization'] = self.krb_instance.acquire_kerberos_ticket(self.krb_primary, self.host)
        request = httpclient.HTTPRequest(uri, method='POST', body=file_data, headers=headers, **self.request_options)
        response = yield self.http_client.fetch(request)

        if not response.code == httplib.OK:
            _raise_pywebhdfs_exception(response.code, response.body)

        raise Return(True)

    @coroutine
    def read_file(self, path, **kwargs):
        """
        Reads from a file on HDFS  and returns the content

        :param path: the HDFS file path without a leading '/'

        The function wraps the WebHDFS REST call:

        GET http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=OPEN

        [&offset=<LONG>][&length=<LONG>][&buffersize=<INT>]

        Note: this function follows automatic redirects

        Example:

        >>> hdfs = PyWebHdfsClient(host='host',port='50070', user_name='hdfs')
        >>> my_file = 'user/hdfs/data/myfile.txt'
        >>> hdfs.read_file(my_file)
        01010101010101010101010101010101
        01010101010101010101010101010101
        01010101010101010101010101010101
        01010101010101010101010101010101
        """

        headers = dict()
        if self.krb_instance:
            headers['Authorization'] = self.krb_instance.acquire_kerberos_ticket(self.krb_primary, self.host)

        optional_args = kwargs
        uri = self._create_uri(path, operations.OPEN, **optional_args)
        request = httpclient.HTTPRequest(uri, follow_redirects=True, headers=headers, **self.request_options)
        response = yield self.http_client.fetch(request)

        if not response.code == httplib.OK:
            _raise_pywebhdfs_exception(response.code, response.body)

        raise Return(response.body)

    @coroutine
    def make_dir(self, path, **kwargs):
        """
        Create a new directory on HDFS

        :param path: the HDFS file path without a leading '/'

        The function wraps the WebHDFS REST call:

        PUT http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=MKDIRS

        [&permission=<OCTAL>]

        Example:

        >>> hdfs = PyWebHdfsClient(host='host',port='50070', user_name='hdfs')
        >>> my_dir = 'user/hdfs/data/new_dir'
        >>> hdfs.make_dir(my_dir)

        Example with optional args:

        >>> hdfs.make_dir(my_dir, permission=755)
        """

        headers = dict()
        if self.krb_instance:
            headers['Authorization'] = self.krb_instance.acquire_kerberos_ticket(self.krb_primary, self.host)

        optional_args = kwargs
        uri = self._create_uri(path, operations.MKDIRS, **optional_args)

        request = httpclient.HTTPRequest(
            uri, method='PUT', follow_redirects=True, body='', headers=headers, **self.request_options)
        response = yield self.http_client.fetch(request)

        if not response.code == httplib.OK:
            _raise_pywebhdfs_exception(response.code, response.body)

        raise Return(True)

    @coroutine
    def rename_file_dir(self, path, destination_path, **kwargs):
        """
        Rename an existing directory or file on HDFS

        :param path: the HDFS file path without a leading '/'
        :param destination_path: the new file path name

        The function wraps the WebHDFS REST call:

        PUT <HOST>:<PORT>/webhdfs/v1/<PATH>?op=RENAME&destination=<PATH>

        Example:

        >>> hdfs = PyWebHdfsClient(host='host',port='50070', user_name='hdfs')
        >>> current_dir = 'user/hdfs/data/my_dir'
        >>> destination_dir = 'user/hdfs/data/renamed_dir'
        >>> hdfs.rename_file_dir(current_dir, destination_dir)
        """

        headers = dict()
        if self.krb_instance:
            headers['Authorization'] = self.krb_instance.acquire_kerberos_ticket(self.krb_primary, self.host)

        optional_args = kwargs
        uri = self._create_uri(path, operations.RENAME,
                               destination=destination_path,
                               **optional_args)

        request = httpclient.HTTPRequest(
            uri, method='PUT', follow_redirects=True, body='', headers=headers, **self.request_options)
        response = yield self.http_client.fetch(request)

        if not response.code == httplib.OK:
            _raise_pywebhdfs_exception(response.code, response.body)

        raise Return(True)


    @coroutine
    def delete_file_dir(self, path, recursive=False, **kwargs):
        """
        Delete an existing file or directory from HDFS

        :param path: the HDFS file path without a leading '/'

        The function wraps the WebHDFS REST call:

        DELETE "http://<host>:<port>/webhdfs/v1/<path>?op=DELETE

        [&recursive=<true|false>]

        Example for deleting a file:

        >>> hdfs = PyWebHdfsClient(host='host',port='50070', user_name='hdfs')
        >>> my_file = 'user/hdfs/data/myfile.txt'
        >>> hdfs.delete_file_dir(my_file)

        Example for deleting a directory:

        >>> hdfs.delete_file_dir(my_file, recursive=True)
        """

        headers = dict()
        if self.krb_instance:
            headers['Authorization'] = self.krb_instance.acquire_kerberos_ticket(self.krb_primary, self.host)

        optional_args = kwargs
        uri = self._create_uri(path, operations.DELETE, recursive=recursive, **optional_args)
        request = httpclient.HTTPRequest(
            uri, method='DELETE', follow_redirects=True, headers=headers, **self.request_options)
        response = yield self.http_client.fetch(request)

        if not response.code == httplib.OK:
            _raise_pywebhdfs_exception(response.code, response.body)

        raise Return(True)

    @coroutine
    def get_file_dir_status(self, path, **kwargs):
        """
        Get the file_status of a single file or directory on HDFS

        :param path: the HDFS file path without a leading '/'

        The function wraps the WebHDFS REST call:

        GET http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=GETFILESTATUS

        Example for getting file status:

        >>> hdfs = PyWebHdfsClient(host='host',port='50070', user_name='hdfs')
        >>> my_file = 'user/hdfs/data/myfile.txt'
        >>> hdfs.get_file_dir_status(my_file)
        {
            "FileStatus":{
                "accessTime":1371737704282,
                "blockSize":134217728,
                "group":"hdfs",
                "length":90,
                "modificationTime":1371737704595,
                "owner":"hdfs",
                "pathSuffix":"",
                "permission":"755",
                "replication":3,
                "type":"FILE"
            }
        }

        Example for getting directory status:

        >>> my_dir = 'user/hdfs/data/'
        >>> hdfs.get_file_dir_status(my_file)
        {
            "FileStatus":{
                "accessTime":0,
                "blockSize":0,
                "group":"hdfs",
                "length":0,
                "modificationTime":1371737704208,
                "owner":"hdfs",
                "pathSuffix":"",
                "permission":"755",
                "replication":0,
                "type":"DIRECTORY"
            }
        }
        """

        headers = dict()
        if self.krb_instance:
            headers['Authorization'] = self.krb_instance.acquire_kerberos_ticket(self.krb_primary, self.host)

        optional_args = kwargs
        uri = self._create_uri(path, operations.GETFILESTATUS, **optional_args)

        request = httpclient.HTTPRequest(uri, follow_redirects=True, headers=headers, **self.request_options)
        response = yield self.http_client.fetch(request)

        if not response.code == httplib.OK:
            _raise_pywebhdfs_exception(response.code, response.body)

        raise Return(json.loads(response.body))

    @coroutine
    def list_dir(self, path, **kwargs):
        """
        Get a list of file_status for all files and directories
        inside an HDFS directory

        :param path: the HDFS file path without a leading '/'

        The function wraps the WebHDFS REST call:

        GET http://<HOST>:<PORT>/webhdfs/v1/<PATH>?op=LISTSTATUS

        Example for listing a directory:

        >>> hdfs = PyWebHdfsClient(host='host',port='50070', user_name='hdfs')
        >>> my_dir = 'user/hdfs'
        >>> hdfs.list_dir(my_dir)
        {
            "FileStatuses":{
                "FileStatus":[
                    {
                        "accessTime":1371737704282,
                        "blockSize":134217728,
                        "group":"hdfs",
                        "length":90,
                        "modificationTime":1371737704595,
                        "owner":"hdfs",
                        "pathSuffix":"example3.txt",
                        "permission":"755",
                        "replication":3,
                        "type":"FILE"
                    },
                    {
                        "accessTime":1371678467205,
                        "blockSize":134217728,
                        "group":"hdfs","length":1057,
                        "modificationTime":1371678467394,
                        "owner":"hdfs",
                        "pathSuffix":"example2.txt",
                        "permission":"700",
                        "replication":3,
                        "type":"FILE"
                    }
                ]
            }
        }

        """

        headers = dict()
        if self.krb_instance:
            headers['Authorization'] = self.krb_instance.acquire_kerberos_ticket(self.krb_primary, self.host)

        optional_args = kwargs
        uri = self._create_uri(path, operations.LISTSTATUS, **optional_args)
        request = httpclient.HTTPRequest(uri, follow_redirects=True, headers=headers, **self.request_options)
        response = yield self.http_client.fetch(request)

        if not response.code == httplib.OK:
            _raise_pywebhdfs_exception(response.code, response.body)

        raise Return(json.loads(response.body))

    @coroutine
    def set_owner(self, path, owner, group, **kwargs):
        """
        Set the owner and group on a path

        :param path: the HDFS file path without a leading '/'
        :param owner: owner name
        :param group: group name
        :return: JSON response

        """

        headers = dict()
        if self.krb_instance:
            headers['Authorization'] = self.krb_instance.acquire_kerberos_ticket(self.krb_primary, self.host)

        optional_args = kwargs
        optional_args['owner'] = owner
        optional_args['group'] = group
        uri = self._create_uri(path, operations.SETOWNER, **optional_args)
        request = httpclient.HTTPRequest(uri, method='PUT', follow_redirects=True, headers=headers,
                                         **self.request_options)
        response = yield self.http_client.fetch(request)

        if not response.status_code == httplib.OK:
            _raise_pywebhdfs_exception(response.status_code, response.content)

        raise Return(True)

    @coroutine
    def get_acl_status(self, path, **kwargs):
        headers = dict()
        if self.krb_instance:
            headers['Authorization'] = self.krb_instance.acquire_kerberos_ticket(self.krb_primary, self.host)

        optional_args = kwargs
        uri = self._create_uri(path, operations.GETACLSTATUS, **optional_args)        
        request = httpclient.HTTPRequest(uri, follow_redirects=True, headers=headers, **self.request_options)
        response = yield self.http_client.fetch(request)

        if not response.code == httplib.OK:
            _raise_pywebhdfs_exception(response.code, response.body)

        raise Return(json.loads(response.body))

    def _create_uri(self, path, operation, **kwargs):
        """
        internal function used to construct the WebHDFS request uri based on
        the <PATH>, <OPERATION>, and any provided optional arguments
        """

        path_param = path

        # setup the parameter represent the WebHDFS operation
        operation_param = '?op={operation}'.format(operation=operation)

        # configure authorization based on provided credentials
        auth_param = str()
        if self.user_name:
            auth_param = '&user.name={user_name}'.format(
                user_name=self.user_name)

        # setup any optional parameters
        keyword_params = str()
        for key in kwargs:
            keyword_params = '{params}&{key}={value}'.format(
                params=keyword_params, key=key, value=str(kwargs[key]).lower())

        # build the complete uri from the base uri and all configured params
        uri = '{base_uri}{path}{operation}{keyword_args}{auth}'.format(
            base_uri=self.base_uri, path=path_param,
            operation=operation_param, keyword_args=keyword_params,
            auth=auth_param)

        return uri


def _raise_pywebhdfs_exception(resp_code, message=None):

    if resp_code == httplib.BAD_REQUEST:
        raise errors.BadRequest(msg=message)
    elif resp_code == httplib.UNAUTHORIZED:
        raise errors.Unauthorized(msg=message)
    elif resp_code == httplib.NOT_FOUND:
        raise errors.FileNotFound(msg=message)
    elif resp_code == httplib.METHOD_NOT_ALLOWED:
        raise errors.MethodNotAllowed(msg=message)
    else:
        raise errors.PyWebHdfsException(msg=message)
