#!/usr/bin/env python3
# vim modeline (put ":set modeline" into your ~/.vimrc)
# vim:set expandtab ts=4 sw=4 ai ft=python:
#
# Cryptex manages secure documents for you, stored centrally, and versioned
# It is used differently depending upon what you desire to do:
#
# Copyright (C) 2015 Brandon Gillespie
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import io
import os
import os.path
import stat # chmod
import sys
import argparse
import json
import re
import traceback
import pprint # for DEBUG
import time
import base64
import platform # for node/hostname
import getpass # for local username
#import StringIO
import tempfile
import signal
import subprocess
from subprocess import Popen, PIPE
import atexit # shutdown hooks
import shutil # rm -rf (rmtree)
import uuid
import nacl.secret
import nacl.utils
import boto
from boto.s3.key import Key as botoKey

################################################################
class Core():
    """Core class"""
    debug = {}
    timestamp = False

    ############################################################
    def TSTAMP(self):
        """Create a uniform timestamp"""
        return time.strftime('%Y%m%d%H%M%S')

    ############################################################
    def NOTICE(self, msg):
        """Internal print wrapper, so it can be easily overloaded--Notice is for human readable"""
        if self.timestamp:
            sys.stderr.write(self.TSTAMP() + " " +  msg + "\n")
        else:
            sys.stderr.write(msg + "\n")

    ############################################################
    def OUTPUT(self, msg):
        """Internal print wrapper, so it can be easily overloaded--OUTPUT is for machine readable"""
        if self.timestamp:
            sys.stdout.write(self.TSTAMP() + " " +  msg + "\n")
        else:
            sys.stdout.write(msg + "\n")

    ############################################################
    def DEBUG(self, msg, module="", data=None, err=None):
        """Debugging of output, supporting levels and modules"""
        debug = self.debug or {"*":False}
        if not module:
            module = str(self.__class__.__name__)
        if debug.get("*", None) or module in debug.keys():
            if err:
                msg = msg + ": " + str(err)
            self.NOTICE("DEBUG: " + module + "." + msg)
            if data:
                sys.stderr.write(pprint.pformat(data, indent=1, width=80, depth=None))

    ############################################################
    def ABORT(self, msg, err=None):
        """standardized failure"""
        if err:
            self.DEBUG("Error", err=err)
        self.NOTICE("ABORT: " + msg)
        if err and err.strerror:
            self.NOTICE(str(err))

        sys.exit(1)

################################################################################
# pylint: disable=too-few-public-methods
class NaclKey(object):
    """
    Key wrapper

    >>> NaclKey("MmRnFLmmF4iqXxKAhjkrkC/+pdABVQipeKSv2EZAqOY=").encode()
    'MmRnFLmmF4iqXxKAhjkrkC/+pdABVQipeKSv2EZAqOY='
    """

    value = b''

    def __init__(self, *existing):
        if existing:
            self.value = base64.b64decode(existing[0])
        else:
            self.value = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    def encode(self):
        """Return key encoded"""
        return base64.b64encode(self.value).decode()

################################################################
class Cipher(Core):
    """
    Generic Cipher Wrapper

    >>> key = NaclKey('MmRnFLmmF4iqXxKAhjkrkC/+pdABVQipeKSv2EZAqOY=')
    >>> result = Cipher(key).key_encrypt("test", raw=True)
    >>> Cipher(key).key_decrypt(result, raw=True)
    'test'
    """

    versions = {
        '01': {'type':'nacl'}
    }
    cipher = None
    meta = None

    ############################################################
    def _prep(self, key, orig=None):
        """prepare encryption"""
        if orig:
            ver = orig[:2]
        else:
            ver = '01'

        self.cipher = self.versions[ver]['type']
        key_obj = NaclKey(key)
        self.meta = dict(
            nonce=nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE),
            key=key_obj,
            cipher=nacl.secret.SecretBox(key_obj.value),
            bs=65
        )
        return self

    ############################################################
    def new_key(self):
        """return a key to our standard format"""
        if self.cipher == 'nacl':
            return NaclKey().encode()

    ############################################################
    def encrypt(self, block):
        if self.cipher == 'nacl':
            if not isinstance(block, bytes):
                block = block.encode()
            encrypted = self.meta['cipher'].encrypt(block, self.meta['nonce'])
            return base64.b64encode(encrypted)
        else:
            raise ValueError("self.cipher is not initialized")

    ############################################################
    def encrypt_file(self, key, in_file, out_file):
        self.DEBUG("encrypt({k}, <in>, <out>)".format(k=key), module="Cipher")
        self._prep(key)
        out_file.write('01')
        for block in self._read_block(in_file, self.meta['bs']):
            # it comes at us base64 encoded
            out_file.write(self.encrypt(block).decode())
            out_file.write("\n")

    ############################################################
    def decrypt(self, block):
        if self.cipher == 'nacl':
            data = base64.b64decode(block)
            return self.meta['cipher'].decrypt(data)
        else:
            raise ValueError("self.cipher is not initialized")

    ############################################################
    def decrypt_file(self, key, in_file, out_file):
        first = in_file.read(2)
        self._prep(key, orig=first)
        # it comes in base64 encoded, so just read "a line"
        out_binary = False
        if isinstance(out_file, io.BytesIO):
            out_binary = True
        for block in in_file: # self._read_block(in_file, self.meta['bs']):
            decoded = self.decrypt(block)
            if out_binary:
                if isinstance(decoded, str):
                    decoded = decoded.encode()
            else:
                if isinstance(decoded, bytes):
                    decoded = decoded.decode()
            out_file.write(decoded)

    def _read_block(self, read_file, blocksize):
        while True:
            data = read_file.read(blocksize)
            if not data:
                break
            yield data

################################################################
class Base(Cipher):
    """
    Base object where common and global attributes are defined.
    All remote files are defined with a unique name, which is
    referenced in the configuration to pull other attributes.
    """
    cx_base = os.environ['HOME'] + '/.cryptex'
    cfg_key = None
    cfg = {'files':{}}
    session = str(uuid.uuid1())

    def __init__(self, *_, **kwargs):

        keyfile = self.cx_base + "/ck"
        def _load_key():
            with open(keyfile, 'rt') as in_file:
                self.cfg_key = in_file.read()

        if not os.path.exists(self.cx_base):
            os.mkdir(self.cx_base, 0o700)
        try:
            # need a universal way to pull a common secret tied to the local user
            # session, after they are authenticated.  Something better than this.
            _load_key()
        except IOError:
            print("Detected first time run, initializing cryptex...")
            key = NaclKey()
            with open(keyfile, "wt") as out_file:
                out_file.write(key.encode())
            try:
                _load_key()
            except IOError:
                print("Unable to initialize?")

        if kwargs.get('debug'):
            for module in kwargs['debug']:
                self.debug[module] = True
        self.hostname = platform.node()
        if 'SUDO_USER' in os.environ.keys():
            self.user = os.environ['SUDO_USER']
        else:
            self.user = getpass.getuser()
        if 'EDITOR' in os.environ.keys():
            self.editor = os.environ['EDITOR']
        else:
            # todo: look into this being from libs
            def which(cmd):
                """search os path to find an executable"""
                for path in os.environ["PATH"].split(os.pathsep):
                    full_cmd = os.path.join(path, cmd)
                    if os.path.exists(full_cmd):
                        return full_cmd
            for editor in ('vim', 'vi', 'nano'):
                path = which(editor)
                if path:
                    self.editor = path
                    break


    ############################################################

    ############################################################
    def __reference__(self, reference):
        """Copy across vars from a previously initialized object"""
        self.debug = reference.debug
        self.cfg = reference.cfg
        self.timestamp = reference.timestamp
        self.hostname = reference.hostname
        self.user = reference.user
        self.editor = reference.editor
        self.session = reference.session

    ############################################################
#    def StringIO(self):
#        """Used because python 2.x does unicode with io.StringIO"""
#        #if sys.version_info[0] < 3:
#        #    return StringIO.StringIO()
#        #else:
#            return io.StringIO()

    ############################################################
    def cfg_load(self):
        """Load config file (encrypted)"""
        try:
            self.DEBUG("Config Load:", data=self.cfg, module='config')
            cfgfile = self.cx_base + "/c"
            if os.path.exists(cfgfile):
                decrypted_file = io.BytesIO()
                with open(cfgfile, 'rt') as in_file:
                    self.decrypt_file(self.cfg_key, in_file, decrypted_file)
                    decrypted_file.seek(0)
                    data = decrypted_file.read().decode()
                    self.cfg = json.loads(data)
            else:
                self.DEBUG("No cryptex config", module='config')
        except Exception as err:
            self.NOTICE("Unable to load config!")
            traceback.print_exc()
            self.DEBUG("Reason: " + str(err))
        return self

    ############################################################
    def cfg_save(self):
        """Save config file (encrypted)"""
        decrypted_file = io.BytesIO()
        decrypted_file.write(str.encode(json.dumps(self.cfg)))
        decrypted_file.seek(0)
        try:
            with open(self.cx_base + "/c", 'wt') as out_file:
                self.encrypt_file(self.cfg_key, decrypted_file, out_file)
        except Exception as err:
            self.NOTICE("Unable to save config!")
            traceback.print_exc()
            self.NOTICE("Reason: " + str(err))

################################################################
class RemoteFile(Base):
    """Manage remote file interfacing"""

    opened = None

    ############################################################
    def __init__(self, base, debug=list()):
        """Instantiate with reference object, copy attributes"""
        super(RemoteFile, self).__init__(base, debug)
        self.__reference__(base)
        self.opened = dict()

    ############################################################
    def connect(self, name):
        """Connect to a remote source (s3)"""
        self.DEBUG("connect(" + name + ")", module="RemoteFile")
        if not name in self.opened.keys():
            if not name in self.cfg['files'].keys():
                self.ABORT("Undefined file '" + name + "'")
            rdef = self.cfg['files'][name]['remote']
            # here would be if rdef['type'] == s3
            self.DEBUG("connect(" + name + "<" + rdef['key'] + "@" + rdef['bucket'] + ">)",
                       module="RemoteFile")
            s3_debug = "s3" in self.debug.keys() and "http" in self.debug.keys()
            s3_conn = boto.connect_s3(rdef['key'], rdef['secret'], debug=s3_debug, is_secure=True)
            s3_bucket = s3_conn.get_bucket(rdef['bucket'])
            self.opened[name] = {
                's3_conn': s3_conn,
                's3_bucket': s3_bucket,
            }
        return self.opened[name]['s3_bucket']

    ############################################################
    def key(self, key_name, fname=None):
        """Common wrapper to get a key for s3"""
        self.DEBUG("key(" + key_name + ", fname=" + str(fname) + ")", module="RemoteFile")
        if not fname:
            fname = key_name
        key = botoKey(self.connect(key_name))
        key.key = fname
        return key

    ############################################################
    def delete(self, name, key_name):
        """receive a discrete key (with version) and delete it"""
        self.DEBUG("delete(" + name + ", " + key_name + ")", module="RemoteFile")
        bucket = self.connect(name)
        bucket.delete_key(key_name)

    ############################################################
    def get(self, name, key_name, localfile, version=None, stdout=False, search=None):
        """Download version of file from s3 bucket"""
        self.DEBUG("get({n}, {k})".format(n=name, k=key_name), module="RemoteFile")
        key = self.key(name, fname=self.full_path(name, fname=key_name))
        efile = localfile + ",e" # encrypted
        gfile = localfile + ".gpg" # interim encoded(gpg)
        with open(efile, 'wb') as e_fd:
            key.get_contents_to_file(e_fd)
        with open(localfile + ".gpg", 'wt') as o_fd, open(efile, 'rt') as e_fd:
            self.decrypt_file(self.cfg['files'][name]['key'], e_fd, o_fd)

        # spaghetti to handle the various options for output/editing
        gpghome = self.cfg['files'][name]['gpghome']
        if gpghome:
            gpg = ['gpg', "--homedir", gpghome]
            if not stdout:
                gpg += ["--output", localfile]
            gpg += ["-d", gfile]
            if search:
                gpg_pipe = Popen(gpg, stdout=PIPE)
                grep = Popen(["grep"] + search, stdin=gpg_pipe.stdout)
                gpg_pipe.stdout.close() # Allow p1 to receive a SIGPIPE if p2 exits.
                grep.communicate()
            else:
                subprocess.call(gpg)
        else:
            if not stdout:
                subprocess.call(['cp', gfile, localfile])
            else:
                if search:
                    subprocess.call(["grep"] + search)
                else:
                    subprocess.call(['cat', gfile])

    ############################################################
    # easy way to disable unlinking for debugging
    def unlink(self, path):
        try:
            os.unlink(path)
        except:
            pass

    ############################################################
    def put(self, name, localfile, force=False, lock=True):
        """
        Upload a file to s3.  Process encoding and encrypt to file
        configuration requirements.
        """
        if not len(name):
            self.ABORT("Cannot put without a name")
        self.DEBUG("put({n}, {s}, force={f}, lock={l}"
                   .format(n=name, s=localfile, f=force, l=lock),
                   module="RemoteFile")
        if lock:
            try:
                self.lock_acquire(name, force=force)
            except Exception as err:
                traceback.print_exc()
                self.ABORT(str(err))

        vers_name = name + "," + self.TSTAMP() + "," + self.session
        key = self.key(name, fname=self.full_path(name, fname=vers_name))

        # gpg encode
        efile = localfile + ",e"
        gfile = localfile + ".gpg"
        gpghome = self.cfg['files'][name]['gpghome']
        self.unlink(gfile)
        if gpghome:
            gpgkey = self.cfg['files'][name]['gpgkey']
            subprocess.call(['gpg', "--homedir", gpghome, "-r", gpgkey, "-e", localfile])
        else:
            subprocess.call(['cp', localfile, gfile])
        try:
            with open(efile, 'wt') as e_fd, open(gfile) as s_fd:
                self.encrypt_file(self.cfg['files'][name]['key'], s_fd, e_fd)
            self.unlink(localfile)
            self.unlink(gfile)
            key.set_contents_from_filename(efile, replace=False)
        except:
            self.lock_release(name)
            raise
        finally:
            self.clean_remote(name)
            if lock:
                self.lock_release(name)

    ############################################################
    def clean_local(self, name):
        """Cleanup local scratch files"""
        # keep less local copies
        #-while len(names) > 2:
        try:
            # for now unlink everything, no local copies
            basedir = self.cx_base + '/' + name
            for file in sorted(os.listdir(basedir)):
                self.unlink(basedir + "/" + file)
        except Exception as err:
            print("Failure during clean: " + str(err))

        #os path list | sort by age
        #while len(names) > vers:
        #  unlink()
        #  list_names
        # TODO: cleanup local files too

    ############################################################
    def clean_remote(self, name):
        """Cleanup old versions, remote."""
        # TODO: make sure only .e files are left behind on local disk
        self.DEBUG("clean_remote(" + name + ")", module="RemoteFile")
        versions = self.cfg['files'][name]['versions']
        names = self.list_names(name)
        while len(names) > versions:
            self.NOTICE("Cleaning old version: " + names[0].split(',')[1])
            self.delete(name, names[0])
            names = self.list_names(name)
        self.clean_local(name)

    ############################################################
    def lock_name(self, target):
        """Get the file name to use for a lock."""
        self.DEBUG("lock_name(" + target + ")", module="RemoteFile")
        rdef = self.cfg['files'][target]['remote']
        return rdef['path'] + '/lock:' + target

    ############################################################
    def lock_release(self, target):
        """Release a lock"""
        self.NOTICE("Releasing Lock for " + target)
        self.DEBUG("lock_release(" + target + ")", module="RemoteFile")
        self.delete(target, self.lock_name(target))

    ############################################################
    def lock_acquire(self, target, force=False):
        """Acquire a lock"""
        self.DEBUG("lock_acquire(" + target + ", force=" + str(force) + ")",
                   module="RemoteFile")
        self.NOTICE("Acquiring Lock for " + target)
        key = self.key(target, fname=self.lock_name(target))
        if force:
            return self.lock_set(key, force=force)

        try:
            lockfile = io.BytesIO()
            key.get_contents_to_file(lockfile)
            lockfile.seek(0)
            lock = lockfile.read().decode().split('\t')
            # also allow it if the session matches
            if len(lock) == 3 and lock[2] == self.session:
                return True
        except Exception:
            return self.lock_set(key)

        raise ValueError("File (" + target + ") is currently locked by " +
                         lock[1] + " on " + lock[0])

    ############################################################
    def lock_set(self, key, force=False):
        """
        Set a lock--do not check to see if it exists first.
        Called by lock_acquire()
        """
        self.DEBUG("lock_set(" + key.name + ", force=" + str(force) + ")",
                   module="RemoteFile")
        lockfile = io.StringIO()
        lockfile.write(self.hostname + '\t' + self.user + '\t' + self.session)
        lockfile.seek(0)
        if not key.set_contents_from_file(fp=lockfile, replace=force):
            raise ValueError("Failed to lock(" + key.name + "): already exists")
        return True

    ############################################################
    def full_path(self, name, fname=None):
        """Return a fully qualified path, with our base path"""
        self.DEBUG("full_path(" + name + ", fname=" + str(fname) + ")", module="RemoteFile")
        path = self.cfg['files'][name]['remote']['path']
        if not fname:
            fname = name
        if re.match("^" + path + "/+(.*)$", fname):
            return fname
        elif path == '/':
            path = ''
        return path + '/' + fname

    ############################################################
    def format_list(self, flist, detailed=True):
        """Receive a list of remote files, format it and return."""
        self.DEBUG("format_list()", module="RemoteFile")
        out = []
        for file in flist:
            if detailed:
                name = file.name
            else:
                name = file
            split = name.split('/')[-1].split(',')
            buf = "    " + split[1] + " " + split[2]
            if detailed:
                buf += "  " + file.last_modified
            out.append(buf)
        return out

    ############################################################
    def list(self, name, prefix=None):
        """Return a list of remote files as keys, matching file name"""
        self.DEBUG("list(" + name + ", prefix=" + str(prefix) + ")", module="RemoteFile")
        bucket = self.connect(name)
        prefix = self.cfg['files'][name]['remote']['path']
        return bucket.list(prefix=prefix)

    ############################################################
    def list_names(self, name, filter=None, details=False):
        """Return a list of remote files as names, matching file name"""
        self.DEBUG("list_names(" + name + ", filter=" + str(filter) + ")", module="RemoteFile")
        path = self.full_path(name)
        filerx = re.compile(path + ",([0-9]{14}|[0-9_:-]{19}),.*$")
        # because other stuff could creep in and mess it up
        # iterate and inspect each one
        matched = []
        for file in self.list(name):#, prefix=name):
            if filerx.match(file.name):
                if not filter or filter in file.name:
                    if details:
                        matched.append(file)
                    else:
                        matched.append(str(file.name))
        return sorted(matched)

################################################################
class CLI(Base):
#
    ############################################################
    def config_print_cli(self):
        """Print the config."""
        altcfg = self.cfg
        for name in altcfg['files']:
            dat = altcfg['files'][name]
            rem = altcfg['files'][name]['remote']
            buf = "{file} --remote s3://{key}:{secret}@{bucket}/{path}".format(file=name, **rem)
            if dat.get("key"):
                buf += " --key=" + dat['key']
            if dat.get("versions"):
                buf += " --versions=" + str(dat['versions'])
            if dat.get("gpghome"):
                buf += " --gpghome=" + str(dat['gpghome'])
            self.NOTICE("cryptex -c " + buf)

        self.NOTICE("\n" + json.dumps(altcfg, indent=2))

    ############################################################################
    def list_cli(self):
        """CLI Interface -- list files"""
        remote = RemoteFile(self)
        for name in self.cfg['files'].keys():
            for file in remote.format_list(remote.list_names(name, details=True), \
                                        detailed=True):
                self.NOTICE(name + ": " + file)

    ############################################################
    def config_cli(self, name, path=None, force=False, key=None,
                   gpghome=None, versions=None, remote=None, gpgkey=None):
        """Update / Define / Configure a file in local config"""
        if not force and name in self.cfg['files'].keys():
            self.ABORT("File '" + name + "' is already defined, specify --force to override")

        print("here")
        # if a file path is defined, create new (generate key)
        if path:
            if not os.path.exists(path):
                self.ABORT("Cannot find file: " + path)
            if not key:
                self.NOTICE("Generating key...")
                key = self.new_key()

        # specify attributes if they are not defined
        if name in self.cfg['files'].keys():
            default = self.cfg['files'][name]
        else:
            if not gpghome:
                gpghome = None
            if not versions:
                versions = 50
            default = {
                'gpghome':gpghome,
                'key':key,
                'versions':versions,
            }
        if gpghome or gpgkey:
            if not gpghome or not gpgkey:
                self.ABORT("both --gpghome and --gpgkey must be defined together")
            default['gpghome'] = gpghome
            default['gpgkey'] = gpgkey
        if key == "generate":
            default['key'] = self.new_key()
        elif key:
            default['key'] = key
        else:
            print("No key defined, generating new one.  Replace with --key")
            default['key'] = self.new_key()
        if versions:
            default['versions'] = versions

        if remote:
            # TODO: in the future pull the secret via tty input like gpg
            match = re.match(r'^s3://([A-Z0-9]+):([^@]+)@([a-z0-9-]+)/?(.*)$', remote)
            if not match:
                self.ABORT("Unrecognized REMOTE definition")
            s3_path = match.group(4)
            default['remote'] = {
                'type':'s3',
                'key':match.group(1),
                'secret':match.group(2),
                'bucket':match.group(3),
                'path':s3_path
            }

        if not 'remote' in default.keys():
            self.ABORT("Must specify --remote")
        self.cfg['files'][name] = default
        print(json.dumps(self.cfg, indent=2))
        self.cfg_save()
        self.NOTICE("File '" + name + "' defined")
        if path:
            self.NOTICE("Uploading '" + name + "'")
            RemoteFile(self).put(name, path, force)

    ############################################################
    def remove_file_cli(self, name, forced):
        """Remove a file from configuration"""
        if not forced:
            self.ABORT("Specify --force to delete a file and all of its versions")
        self.NOTICE("Deleting '" + name + "' and all of its stored files:")
        remote = RemoteFile(self)
        map(lambda s: print("    " + s.name), remote.list(name))
        self.NOTICE("Waiting 5 seconds...")
        time.sleep(5)
        for key in remote.list(name):
            self.NOTICE("rm " + key.name)
            remote.delete(name, key.name)
        del self.cfg['files'][name]
        self.cfg_save()

    ############################################################
    def open_cli(self, name, search=list(), edit=False, editor=False, force=False, version=None):
        """Open and optionally edit a file, using latest remote version."""
        if not name in self.cfg['files'].keys():
            self.ABORT("You have not defined a file named '" + name + "'")

        target = None
        remote = RemoteFile(self)
        if edit:
            self.NOTICE("Editing '" + name + "'")
            try:
                remote.lock_acquire(name, force=force)
            except Exception as err:
                self.NOTICE(str(err))
                self.ABORT("\nTry with --force")
        else:
            self.NOTICE("Viewing '" + name + "'")

        matches = remote.list_names(name, filter=version)
        created = True
        if not matches:
            created = False
            target = self.cfg['files'][name]['remote']['path']

        else:
            if version:
                if len(matches) > 1:
                    self.NOTICE("Matches:")
                    map(self.NOTICE, remote.format_list(matches))
                    self.ABORT("Too many matches to version=" + version)
                elif len(matches) == 0:
                    self.ABORT("No matches for version=" + version)
                else:
                    target = matches[0].split('/')[-1]
                    created = False
            else:
                target = matches[-1].split('/')[-1]

        localdir = self.cx_base + '/' + name
        if not os.path.exists(localdir):
            os.mkdir(localdir)

        # always reset the privs
        os.chmod(localdir, stat.S_IRWXU)
        localfile = localdir + '/' + target
        if not os.path.exists(localfile):
            if created:
                remote.get(name, remote.full_path(name, fname=target),
                           localfile, search=search, stdout=not editor)

        keep = False
        if editor:
            # TODO: set read-only option in editor if !created
            subprocess.call(['vim', localfile])

            if edit:
                # inquire if user wants to upload
                answer = input("Commit changes? [y] ")
                if not len(answer) or re.match("^(yes|y)$", answer, flags=re.IGNORECASE):
                    remote.put(name, localfile, lock=False)
                    keep = True
            else:
                self.NOTICE("Not uploading changes")

        if keep:
            remote.clean_remote(name)
        else:
            remote.clean_local(name)
        remote.lock_release(name)

################################################################
def main():
    cmd = os.path.basename(__file__)
    def help_doc():
        print(syntax())
        sys.exit(0)

    def syntax():
        return '''
Cryptex manages secure documents for you, stored centrally, and versioned
It is used differently depending upon what you desire to do:

Register an existing remote file:
  ''' + cmd + ''' -c/--config=NAME [config args]

  [config args] are any of:
    --remote, --versions, --gpghome, --key

Add a new file:
  ''' + cmd + ''' -c/--config=NAME -f/--file=FILE [config args]

Define GPG encoding:
  ''' + cmd + ''' -c/--config NAME --gpghome=PATH --gpgkey=NAME

See existing configuration:
  ''' + cmd + ''' -c/--config

List files:
  ''' + cmd + ''' -ls/--list

Delete a file:
  ''' + cmd + ''' --delete=NAME

View the latest file:
  ''' + cmd + ''' NAME

Search the latest file for MATCH:
  ''' + cmd + ''' NAME MATCH

Edit the latest file:
  ''' + cmd + ''' NAME --e?dit

Other options:
  --force      required for some actions
  -d/--debug=m enable debuging of module (m), may be specified multiple times
               modules: base, RemoteFile, http
  --gpghome=x  Define the gpghome; if undefined, not encoded.
  --gpgkey=x   Define the gpgkey name used for gpg encryption.
  --version=v  specify a specific version to view (look at --ls)
  --versions=x specify how many versions to keep with --add, default: 50
  --remote=def specify the remote registry, format:
                    s3://API_KEY:API_SECRET@BUCKET/PATH
 '''

    editor = bool(cmd[0:2] == "vi")
    parser = argparse.ArgumentParser(add_help=False, usage=syntax())
    parser.add_argument("--help", "-h", action='store_true')
    parser.add_argument("--debug", "-d", action='append')
    parser.add_argument("--remote", "-r", action='store')
    parser.add_argument("--config", "--configure", "-c", nargs='*')
    parser.add_argument("--list", "-ls", '--ls', action='store_true', dest='ls')
    parser.add_argument("--seed", action='store')
    parser.add_argument("--remove", action='store')
    parser.add_argument("--file", "-f", action='store', dest='path')
    parser.add_argument("--force", action='store_true')
    parser.add_argument("--version", action='store')
    parser.add_argument("--versions", action='store', type=int)
    parser.add_argument("--edit", "-e", action='store_true')
    parser.add_argument("--gpghome", action='store')
    parser.add_argument("--gpgkey", action='store')
    parser.add_argument("--key", action='store')
    parser.add_argument("file", nargs='*')

    args = parser.parse_args()
    cli = CLI(debug=args.debug).cfg_load()

    if args.help:
        help_doc()
    elif args.config == []:
        cli.config_print_cli()
    elif args.config != None:
        cli.config_cli(args.config[0], versions=args.versions, path=args.path,
                       force=args.force, gpghome=args.gpghome, key=args.key,
                       remote=args.remote, gpgkey=args.gpgkey)
    elif args.ls:
        cli.list_cli()
    elif args.remove:
        cli.remove_file_cli(args.remove, args.force)
    elif len(args.file) == 0:
        print(syntax())
        cli.ABORT("Missing file NAME")
    else:
        search = args.file[1:]
        cli.open_cli(args.file[0], search=search, edit=args.edit, force=args.force,
                     version=args.version, editor=editor)

if __name__ == "__main__":
    main()
