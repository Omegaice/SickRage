# Copyright (c) 2013 Chris Lucas, <chris@chrisjlucas.com>
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
import urllib
import os.path
import time
import xmlrpclib

from rtorrent.common import (find_torrent,  # @UnresolvedImport
                             is_valid_port,  # @UnresolvedImport
                             convert_version_tuple_to_str)  # @UnresolvedImport
from rtorrent.lib.torrentparser import TorrentParser  # @UnresolvedImport
from rtorrent.lib.xmlrpc.http import HTTPServerProxy  # @UnresolvedImport
from rtorrent.lib.xmlrpc.scgi import SCGIServerProxy  # @UnresolvedImport
from rtorrent.rpc import Method  # @UnresolvedImport
from rtorrent.lib.xmlrpc.requests_transport import RequestsTransport  # @UnresolvedImport @IgnorePep8
from rtorrent.torrent import Torrent  # @UnresolvedImport
from rtorrent.group import Group  # @UnresolvedImport
import rtorrent.rpc  # @UnresolvedImport

__version__ = "0.2.9"
__author__ = "Chris Lucas"
__contact__ = "chris@chrisjlucas.com"
__license__ = "MIT"

MIN_RTORRENT_VERSION = (0, 8, 1)
MIN_RTORRENT_VERSION_STR = convert_version_tuple_to_str(MIN_RTORRENT_VERSION)
MAX_RETRIES = 5


class RTorrent:

    """ Create a new rTorrent connection """
    rpc_prefix = None

    def __init__(self, uri, username=None, password=None,
                 verify=False, sp=None, sp_kwargs=None, tp_kwargs=None):
        self.uri = uri  # : From X{__init__(self, url)}

        self.username = username
        self.password = password

        self.schema = urllib.splittype(uri)[0]

        if sp:
            self.sp = sp
        elif self.schema in ['http', 'https']:
            self.sp = HTTPServerProxy
            if self.schema == 'https':
                self.isHttps = True
            else:
                self.isHttps = False
        elif self.schema == 'scgi':
            self.sp = SCGIServerProxy
        else:
            raise NotImplementedError()

        self.sp_kwargs = sp_kwargs or {}

        self.tp_kwargs = tp_kwargs or {}

        self.torrents = []  # : List of L{Torrent} instances
        self._rpc_methods = []  # : List of rTorrent RPC methods
        self._torrent_cache = []
        self._client_version_tuple = ()

        if verify is True:
            self._verify_conn()

    def _get_conn(self):
        """Get ServerProxy instance"""
        if self.username is not None and self.password is not None:
            if self.schema == 'scgi':
                raise NotImplementedError()

            if 'authtype' not in self.tp_kwargs:
                authtype = None
            else:
                authtype = self.tp_kwargs['authtype']

            if 'check_ssl_cert' not in self.tp_kwargs:
                check_ssl_cert = True
            else:
                check_ssl_cert = self.tp_kwargs['check_ssl_cert']

            if 'proxies' not in self.tp_kwargs:
                proxies = None
            else:
                proxies = self.tp_kwargs['proxies']

            return self.sp(
                self.uri,
                transport=RequestsTransport(
                    use_https=self.isHttps,
                    authtype=authtype,
                    username=self.username,
                    password=self.password,
                    check_ssl_cert=check_ssl_cert,
                    proxies=proxies),
                **self.sp_kwargs
            )

        return self.sp(self.uri, **self.sp_kwargs)

    def _verify_conn(self):
        # check for rpc methods that should be available
        assert "system.client_version" in self._get_rpc_methods(
        ), "Required RPC method not available."
        assert "system.library_version" in self._get_rpc_methods(
        ), "Required RPC method not available."

        # minimum rTorrent version check
        assert self._meets_version_requirement() is True,\
            "Error: Minimum rTorrent version required is {0}".format(
            MIN_RTORRENT_VERSION_STR)

    def _meets_version_requirement(self):
        return self._get_client_version_tuple() >= MIN_RTORRENT_VERSION

    def _get_client_version_tuple(self):
        conn = self._get_conn()

        if not self._client_version_tuple:
            if not hasattr(self, "client_version"):
                setattr(self, "client_version",
                        conn.system.client_version())

            rtver = getattr(self, "client_version")
            self._client_version_tuple = tuple([int(i) for i in
                                                rtver.split(".")])

        return self._client_version_tuple

    def _update_rpc_methods(self):
        self._rpc_methods = self._get_conn().system.listMethods()

        return self._rpc_methods

    def _get_rpc_methods(self):
        """ Get list of raw RPC commands

        @return: raw RPC commands
        @rtype: list
        """

        return(self._rpc_methods or self._update_rpc_methods())

    def get_torrents(self, view="main"):
        """Get list of all torrents in specified view

        @return: list of L{Torrent} instances

        @rtype: list

        @todo: add validity check for specified view
        """
        self.torrents = []
        methods = rtorrent.torrent.methods
        retriever_methods = [m for m in methods
                             if m.is_retriever() and m.is_available(self)]

        m = rtorrent.rpc.Multicall(self)
        m.add("d.multicall2", '', view, "d.hash=",
              *[method.rpc_call + "=" for method in retriever_methods])

        results = m.call()[0]  # only sent one call, only need first result

        for result in results:
            results_dict = {}
            # build results_dict
            # result[0] is the info_hash
            for m, r in zip(retriever_methods, result[1:]):
                results_dict[m.varname] = rtorrent.rpc.process_result(m, r)

            self.torrents.append(
                Torrent(self, info_hash=result[0], **results_dict)
            )

        self._manage_torrent_cache()
        return(self.torrents)

    def _manage_torrent_cache(self):
        """Carry tracker/peer/file lists over to new torrent list"""
        for torrent in self._torrent_cache:
            new_torrent = rtorrent.common.find_torrent(torrent.info_hash,
                                                       self.torrents)
            if new_torrent is not None:
                new_torrent.files = torrent.files
                new_torrent.peers = torrent.peers
                new_torrent.trackers = torrent.trackers

        self._torrent_cache = self.torrents

    def _get_load_function(self, file_type, start, verbose):
        """Determine correct "load torrent" RPC method"""
        func_name = None
        if file_type == "url":
            # url strings can be input directly
            if start and verbose:
                func_name = "load.start_verbose"
            elif start:
                func_name = "load.start"
            elif verbose:
                func_name = "load.verbose"
            else:
                func_name = "load.normal"
        elif file_type in ["file", "raw"]:
            if start and verbose:
                func_name = "load_raw_start_verbose"
            elif start:
                func_name = "load.raw_start"
            elif verbose:
                func_name = "load.raw_verbose"
            else:
                func_name = "load.raw"

        return(func_name)

    def load_magnet(self, magneturl, info_hash, start=False, verbose=False, verify_load=True):  # @IgnorePep8

        p = self._get_conn()

        info_hash = info_hash.upper()

        func_name = self._get_load_function("url", start, verbose)

        # load magnet
        getattr(p, func_name)('', magneturl)

        if verify_load:
            new_torrent = None

            # Make sure the torrent was added
            for i in range(MAX_RETRIES):
                time.sleep(2)
                new_torrent = self.find_torrent(info_hash)
                if new_torrent:
                    break

            # Make sure torrent was added in time
            assert new_torrent, "Adding torrent was unsuccessful after {0} seconds (load_magnet).".format(MAX_RETRIES * 2)

            # Resolve magnet to torrent, it will stop once has resolution has completed
            new_torrent.start()

            # Set new_torrent back to None for checks below
            new_torrent = None

            # Make sure the resolution has finished
            for i in range(MAX_RETRIES):
                time.sleep(2)
                new_torrent = self.find_torrent(info_hash)
                if new_torrent and str(info_hash) not in str(new_torrent.name):
                    break

            assert new_torrent and str(info_hash) not in str(new_torrent.name),\
                "Magnet failed to resolve after {0} seconds (load_magnet).".format(MAX_RETRIES * 2)

            # Skip the find_torrent (slow) below when verify_load
            return new_torrent

        return self.find_torrent(info_hash)

    def load_torrent(self, new_torrent, start=False, verbose=False, verify_load=True):  # @IgnorePep8
        """
        Loads torrent into rTorrent (with various enhancements)

        @param new_torrent: can be a url, a path to a local file, or the raw data
        of a torrent file
        @type new_torrent: str

        @param start: start torrent when loaded
        @type start: bool

        @param verbose: print error messages to rTorrent log
        @type verbose: bool

        @param verify_load: verify that torrent was added to rTorrent successfully
        @type verify_load: bool

        @return: Depends on verify_load:
                 - if verify_load is True, (and the torrent was
                 loaded successfully), it'll return a L{Torrent} instance
                 - if verify_load is False, it'll return None

        @rtype: L{Torrent} instance or None

        @raise AssertionError: If the torrent wasn't successfully added to rTorrent
                               - Check L{TorrentParser} for the AssertionError's
                               it raises


        @note: Because this function includes url verification (if a url was input)
        as well as verification as to whether the torrent was successfully added,
        this function doesn't execute instantaneously. If that's what you're
        looking for, use load_torrent_simple() instead.
        """
        p = self._get_conn()
        tp = TorrentParser(new_torrent)
        new_torrent = xmlrpclib.Binary(tp._raw_torrent)
        info_hash = tp.info_hash

        func_name = self._get_load_function("raw", start, verbose)

        # load torrent
        getattr(p, func_name)('', new_torrent)

        if verify_load:
            new_torrent = None
            for i in range(MAX_RETRIES):
                time.sleep(2)
                new_torrent = self.find_torrent(info_hash)
                if new_torrent:
                    break

            assert new_torrent, "Adding torrent was unsuccessful after {0} seconds. (load_torrent)".format(MAX_RETRIES * 2)

            # Skip the find_torrent (slow) below when verify_load
            return new_torrent

        return self.find_torrent(info_hash)

    def load_torrent_simple(self, new_torrent, file_type,
                            start=False, verbose=False):
        """Loads torrent into rTorrent

        @param new_torrent: can be a url, a path to a local file, or the raw data
        of a torrent file
        @type new_torrent: str

        @param file_type: valid options: "url", "file", or "raw"
        @type file_type: str

        @param start: start torrent when loaded
        @type start: bool

        @param verbose: print error messages to rTorrent log
        @type verbose: bool

        @return: None

        @raise AssertionError: if incorrect file_type is specified

        @note: This function was written for speed, it includes no enhancements.
        If you input a url, it won't check if it's valid. You also can't get
        verification that the torrent was successfully added to rTorrent.
        Use load_torrent() if you would like these features.
        """
        p = self._get_conn()

        assert file_type in ["raw", "file", "url"], \
            "Invalid file_type, options are: 'url', 'file', 'raw'."
        func_name = self._get_load_function(file_type, start, verbose)

        if file_type == "file":
            # since we have to assume we're connected to a remote rTorrent
            # client, we have to read the file and send it to rT as raw
            assert os.path.isfile(new_torrent), \
                "Invalid path: \"{0}\"".format(new_torrent)
            new_torrent = open(new_torrent, "rb").read()

        if file_type in ["raw", "file"]:
            finput = xmlrpclib.Binary(new_torrent)
        elif file_type == "url":
            finput = new_torrent

        getattr(p, func_name)('', finput)

    def get_views(self):
        p = self._get_conn()
        return p.view_list()

    def create_group(self, name, persistent=True, view=None):
        p = self._get_conn()

        if persistent is True:
            p.group.insert_persistent_view('', name)
        else:
            assert view is not None, "view parameter required on non-persistent groups"  # @IgnorePep8
            p.group.insert('', name, view)

        self._update_rpc_methods()

    def get_group(self, name):
        assert name is not None, "group name required"

        group = Group(self, name)
        group.update()
        return group

    def set_dht_port(self, port):
        """Set DHT port

        @param port: port
        @type port: int

        @raise AssertionError: if invalid port is given
        """
        assert is_valid_port(port), "Valid port range is 0-65535"
        self.dht_port = self._p.set_dht_port(port)

    def enable_check_hash(self):
        """Alias for set_check_hash(True)"""
        self.set_check_hash(True)

    def disable_check_hash(self):
        """Alias for set_check_hash(False)"""
        self.set_check_hash(False)

    def find_torrent(self, info_hash):
        """Frontend for rtorrent.common.find_torrent"""
        return(rtorrent.common.find_torrent(info_hash, self.get_torrents()))

    def poll(self):
        """ poll rTorrent to get latest torrent/peer/tracker/file information

        @note: This essentially refreshes every aspect of the rTorrent
        connection, so it can be very slow if working with a remote
        connection that has a lot of torrents loaded.

        @return: None
        """
        self.update()
        torrents = self.get_torrents()
        for t in torrents:
            t.poll()

    def update(self):
        """Refresh rTorrent client info

        @note: All fields are stored as attributes to self.

        @return: None
        """
        multicall = rtorrent.rpc.Multicall(self)
        retriever_methods = [m for m in methods
                             if m.is_retriever() and m.is_available(self)]
        for method in retriever_methods:
            multicall.add(method)

        multicall.call()


def _build_class_methods(class_obj):
    # multicall add class
    caller = lambda self, multicall, method, *args:\
        multicall.add(method, self.rpc_id, *args)

    caller.__doc__ = """Same as Multicall.add(), but with automatic inclusion
                        of the rpc_id

                        @param multicall: A L{Multicall} instance
                        @type: multicall: Multicall

                        @param method: L{Method} instance or raw rpc method
                        @type: Method or str

                        @param args: optional arguments to pass
                        """
    setattr(class_obj, "multicall_add", caller)


def __compare_rpc_methods(rt_new, rt_old):
    from pprint import pprint
    rt_new_methods = set(rt_new._get_rpc_methods())
    rt_old_methods = set(rt_old._get_rpc_methods())
    print("New Methods:")
    pprint(rt_new_methods - rt_old_methods)
    print("Methods not in new rTorrent:")
    pprint(rt_old_methods - rt_new_methods)


def __check_supported_methods(rt):
    from pprint import pprint
    supported_methods = set([m.rpc_call for m in
                             methods +
                             rtorrent.file.methods +
                             rtorrent.torrent.methods +
                             rtorrent.tracker.methods +
                             rtorrent.peer.methods])
    all_methods = set(rt._get_rpc_methods())

    print("Methods NOT in supported methods")
    pprint(all_methods - supported_methods)
    print("Supported methods NOT in all methods")
    pprint(supported_methods - all_methods)

methods = [
    # RETRIEVERS
    Method(RTorrent, 'network.xmlrpc.size_limit', 'network.xmlrpc.size_limit'),
    Method(RTorrent, 'network.proxy_address', 'network.proxy_address'),
    Method(RTorrent, 'system.file.split_suffix', 'system.file.split_suffix'),
    Method(RTorrent, 'get_up_limit', 'throttle.global_up.max_rate'),
    Method(RTorrent, 'pieces.memory.max', 'pieces.memory.max'),
    Method(RTorrent, 'network.max_open_files', 'network.max_open_files'),
    Method(RTorrent, 'throttle.min_peers.seed', 'throttle.min_peers.seed'),
    Method(RTorrent, 'trackers.use_udp', 'trackers.use_udp'),
    Method(RTorrent, 'pieces.preload.min_size', 'pieces.preload.min_size'),
    Method(RTorrent, 'throttle.max_uploads', 'throttle.max_uploads'),
    Method(RTorrent, 'throttle.max_peers.normal', 'throttle.max_peers.normal'),
    Method(RTorrent, 'pieces.sync.timeout', 'pieces.sync.timeout'),
    Method(RTorrent, 'network.receive_buffer.size', 'network.receive_buffer.size'),
    Method(RTorrent, 'system.file.split_size', 'system.file.split_size'),
    Method(RTorrent, 'dht.throttle.name', 'dht.throttle.name'),
    Method(RTorrent, 'throttle.max_peers.seed', 'throttle.max_peers.seed'),
    Method(RTorrent, 'throttle.min_peers.normal', 'throttle.min_peers.normal'),
    Method(RTorrent, 'trackers.numwant', 'trackers.numwant'),
    Method(RTorrent, 'network.max_open_sockets', 'network.max_open_sockets'),
    Method(RTorrent, 'session.path', 'session.path'),
    Method(RTorrent, 'network.local_address', 'network.local_address'),
    Method(RTorrent, 'network.scgi.dont_route', 'network.scgi.dont_route'),
    Method(RTorrent, 'get_hash_read_ahead', 'get_hash_read_ahead'),
    Method(RTorrent, 'network.http.cacert', 'network.http.cacert'),
    Method(RTorrent, 'dht.port', 'dht.port'),
    Method(RTorrent, 'get_handshake_log', 'get_handshake_log'),
    Method(RTorrent, 'pieces.preload.type', 'pieces.preload.type'),
    Method(RTorrent, 'network.http.max_open', 'network.http.max_open'),
    Method(RTorrent, 'network.http.capath', 'network.http.capath'),
    Method(RTorrent, 'throttle.max_downloads.global', 'throttle.max_downloads.global'),
    Method(RTorrent, 'session.name', 'session.name'),
    Method(RTorrent, 'session.on_completion', 'session.on_completion'),
    Method(RTorrent, 'get_down_limit', 'throttle.global_down.max_rate'),
    Method(RTorrent, 'throttle.global_down.total', 'throttle.global_down.total'),
    Method(RTorrent, 'throttle.global_up.rate', 'throttle.global_up.rate'),
    Method(RTorrent, 'get_hash_max_tries', 'get_hash_max_tries'),
    Method(RTorrent, 'protocol.pex', 'protocol.pex'),
    Method(RTorrent, 'throttle.global_down.rate', 'throttle.global_down.rate'),
    Method(RTorrent, 'protocol.connection.seed', 'protocol.connection.seed'),
    Method(RTorrent, 'network.http.proxy_address', 'network.http.proxy_address'),
    Method(RTorrent, 'pieces.stats_preloaded', 'pieces.stats_preloaded'),
    Method(RTorrent, 'pieces.sync.timeout_safe', 'pieces.sync.timeout_safe'),
    Method(RTorrent, 'get_hash_interval', 'get_hash_interval'),
    Method(RTorrent, 'network.port_random', 'network.port_random'),
    Method(RTorrent, 'directory.default', 'directory.default'),
    Method(RTorrent, 'network.port_open', 'network.port_open'),
    Method(RTorrent, 'system.file.max_size', 'system.file.max_size'),
    Method(RTorrent, 'pieces.stats_not_preloaded', 'pieces.stats_not_preloaded'),
    Method(RTorrent, 'pieces.memory.current', 'pieces.memory.current'),
    Method(RTorrent, 'protocol.connection.leech', 'protocol.connection.leech'),
    Method(RTorrent, 'pieces.hash.on_completion', 'pieces.hash.on_completion',
           boolean=True,
           ),
    Method(RTorrent, 'session.use_lock', 'session.use_lock'),
    Method(RTorrent, 'pieces.preload.min_rate', 'pieces.preload.min_rate'),
    Method(RTorrent, 'throttle.max_uploads.global', 'throttle.max_uploads.global'),
    Method(RTorrent, 'network.send_buffer.size', 'network.send_buffer.size'),
    Method(RTorrent, 'network.port_range', 'network.port_range'),
    Method(RTorrent, 'throttle.max_downloads.div', 'throttle.max_downloads.div'),
    Method(RTorrent, 'throttle.max_uploads.div', 'throttle.max_uploads.div'),
    Method(RTorrent, 'pieces.sync.always_safe', 'pieces.sync.always_safe'),
    Method(RTorrent, 'network.bind_address', 'network.bind_address'),
    Method(RTorrent, 'throttle.global_up.total', 'throttle.global_up.total'),
    Method(RTorrent, 'get_client_version', 'system.client_version'),
    Method(RTorrent, 'get_library_version', 'system.library_version'),
    Method(RTorrent, 'get_api_version', 'system.api_version',
           min_version=(0, 9, 1)
           ),
    Method(RTorrent, "get_system_time", "system.time",
           docstring="""Get the current time of the system rTorrent is running on

           @return: time (posix)
           @rtype: int""",
           ),

    # MODIFIERS
    Method(RTorrent, 'network.http.proxy_address.set', 'network.http.proxy_address.set'),
    Method(RTorrent, 'pieces.memory.max.set', 'pieces.memory.max.set'),
    Method(RTorrent, 'system.file.max_size.set', 'system.file.max_size.set'),
    Method(RTorrent, 'network.bind_address.set', 'network.bind_address.set',
           docstring="""Set address bind

           @param arg: ip address
           @type arg: str
           """,
           ),
    Method(RTorrent, 'set_up_limit', 'throttle.global_up.max_rate.set',
           docstring="""Set global upload limit (in bytes)

           @param arg: speed limit
           @type arg: int
           """,
           ),
    Method(RTorrent, 'network.port_random.set', 'network.port_random.set'),
    Method(RTorrent, 'protocol.connection.leech.set', 'protocol.connection.leech.set'),
    Method(RTorrent, 'trackers.numwant.set', 'trackers.numwant.set'),
    Method(RTorrent, 'throttle.max_peers.normal.set', 'throttle.max_peers.normal.set'),
    Method(RTorrent, 'throttle.min_peers.normal.set', 'throttle.min_peers.normal.set'),
    Method(RTorrent, 'throttle.max_uploads.div.set', 'throttle.max_uploads.div.set'),
    Method(RTorrent, 'network.max_open_files.set', 'network.max_open_files.set'),
    Method(RTorrent, 'throttle.max_downloads.global.set', 'throttle.max_downloads.global.set'),
    Method(RTorrent, 'session.use_lock.set', 'session.use_lock.set'),
    Method(RTorrent, 'session.path.set', 'session.path.set'),
    Method(RTorrent, 'system.file.split_suffix.set', 'system.file.split_suffix.set'),
    Method(RTorrent, 'set_hash_interval', 'set_hash_interval'),
    Method(RTorrent, 'set_handshake_log', 'set_handshake_log'),
    Method(RTorrent, 'network.port_range.set', 'network.port_range.set'),
    Method(RTorrent, 'throttle.min_peers.seed.set', 'throttle.min_peers.seed.set'),
    Method(RTorrent, 'network.scgi.dont_route.set', 'network.scgi.dont_route.set'),
    Method(RTorrent, 'pieces.preload.min_size.set', 'pieces.preload.min_size.set'),
    Method(RTorrent, 'set_log.tracker', 'set_log.tracker'),
    Method(RTorrent, 'throttle.max_uploads.global.set', 'throttle.max_uploads.global.set'),
    Method(RTorrent, 'set_down_limit', 'throttle.global_down.max_rate.set',
           docstring="""Set global download limit (in bytes)

           @param arg: speed limit
           @type arg: int
           """,
           ),
    Method(RTorrent, 'pieces.preload.min_rate.set', 'pieces.preload.min_rate.set'),
    Method(RTorrent, 'set_hash_read_ahead', 'set_hash_read_ahead'),
    Method(RTorrent, 'throttle.max_peers.seed.set', 'throttle.max_peers.seed.set'),
    Method(RTorrent, 'throttle.max_uploads.set', 'throttle.max_uploads.set'),
    Method(RTorrent, 'session.on_completion.set', 'session.on_completion.set'),
    Method(RTorrent, 'network.http.max_open.set', 'network.http.max_open.set'),
    Method(RTorrent, 'directory.default.set', 'directory.default.set'),
    Method(RTorrent, 'network.http.cacert.set', 'network.http.cacert.set'),
    Method(RTorrent, 'dht.throttle.name.set', 'dht.throttle.name.set'),
    Method(RTorrent, 'set_hash_max_tries', 'set_hash_max_tries'),
    Method(RTorrent, 'network.proxy_address.set', 'network.proxy_address.set'),
    Method(RTorrent, 'system.file.split_size.set', 'system.file.split_size.set'),
    Method(RTorrent, 'network.receive_buffer.size.set', 'network.receive_buffer.size.set'),
    Method(RTorrent, 'trackers.use_udp.set', 'trackers.use_udp.set'),
    Method(RTorrent, 'protocol.connection.seed.set', 'protocol.connection.seed.set'),
    Method(RTorrent, 'network.xmlrpc.size_limit.set', 'network.xmlrpc.size_limit.set'),
    Method(RTorrent, 'network.xmlrpc.dialect.set', 'network.xmlrpc.dialect.set'),
    Method(RTorrent, 'pieces.sync.always_safe.set', 'pieces.sync.always_safe.set'),
    Method(RTorrent, 'network.http.capath.set', 'network.http.capath.set'),
    Method(RTorrent, 'network.send_buffer.size.set', 'network.send_buffer.size.set'),
    Method(RTorrent, 'throttle.max_downloads.div.set', 'throttle.max_downloads.div.set'),
    Method(RTorrent, 'session.name.set', 'session.name.set'),
    Method(RTorrent, 'network.port_open.set', 'network.port_open.set'),
    Method(RTorrent, 'pieces.sync.timeout.set', 'pieces.sync.timeout.set'),
    Method(RTorrent, 'protocol.pex.set', 'protocol.pex.set'),
    Method(RTorrent, 'network.local_address.set', 'network.local_address.set',
           docstring="""Set IP

           @param arg: ip address
           @type arg: str
           """,
           ),
    Method(RTorrent, 'pieces.sync.timeout_safe.set', 'pieces.sync.timeout_safe.set'),
    Method(RTorrent, 'pieces.preload.type.set', 'pieces.preload.type.set'),
    Method(RTorrent, 'pieces.hash.on_completion.set', 'pieces.hash.on_completion.set',
           docstring="""Enable/Disable hash checking on finished torrents

            @param arg: True to enable, False to disable
            @type arg: bool
            """,
           boolean=True,
           ),
]

_all_methods_list = [methods,
                     rtorrent.file.methods,
                     rtorrent.torrent.methods,
                     rtorrent.tracker.methods,
                     rtorrent.peer.methods,
                     ]

class_methods_pair = {
    RTorrent: methods,
    rtorrent.file.File: rtorrent.file.methods,
    rtorrent.torrent.Torrent: rtorrent.torrent.methods,
    rtorrent.tracker.Tracker: rtorrent.tracker.methods,
    rtorrent.peer.Peer: rtorrent.peer.methods,
}
for c in class_methods_pair.keys():
    rtorrent.rpc._build_rpc_methods(c, class_methods_pair[c])
    _build_class_methods(c)
