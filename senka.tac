#!/usr/bin/env python
"""
Copyright (c) 2011 Patrick Mylund Nielsen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

__version__ = '1.0'

try:
    from twisted.internet import epollreactor
    epollreactor.install()
except:
    # Cross-platform select reactor (default) is used.
    pass

import sys
import base64
from twisted.application import internet, service
from twisted.cred import portal, checkers, credentials
from twisted.conch import error as concherror, avatar, recvline, interfaces as conchinterfaces
from twisted.conch.ssh import factory, userauth, connection, keys, session, forwarding
from twisted.internet import inotify
from twisted.python import failure, log, randbytes
from twisted.python.filepath import FilePath
from zope.interface import implements
from Crypto.PublicKey import RSA

class PublicKeyCredentialsChecker(object):
    implements(checkers.ICredentialsChecker)
    credentialInterfaces = (credentials.ISSHPrivateKey,)

    def __init__(self, authorizedKeys):
        self.authorizedKeys = authorizedKeys

    def requestAvatarId(self, credentials):
        if credentials.username in self.authorizedKeys:
            userKeys = self.authorizedKeys[credentials.username]
            incKey = "{0} {1}".format(credentials.algName, base64.encodestring(credentials.blob).replace('\n', ''))
            if not incKey in userKeys:
                raise failure.Failure(concherror.ConchError("Unknown key"))
            if not credentials.signature:
                return failure.Failure(concherror.ValidPublicKey())
            pubKey = keys.Key.fromString(incKey).public()
            if pubKey.verify(credentials.signature, credentials.sigData):
                return credentials.username
            else:
                return failure.Failure(concherror.ConchError("Incorrect signature"))
        else:
            return failure.Failure(concherror.ConchError("No such user"))

class SSHSession(session.SSHSession):

    def _noshell(self):
        if not self.closing:
            self.write("No shell or exec.\n")
            self.loseConnection()
        return 0

    def request_shell(self, data):
        log.msg("Shell request rejected")
        return self._noshell()

    def request_exec(self, data):
        log.msg("Execution request rejected")
        return self._noshell()

    def request_pty_req(self, data):
        log.msg("PTY request rejected")
        return self._noshell()

    def request_window_change(self, data):
        log.msg("Window change request rejected")
        return 0

class SSHAvatar(avatar.ConchUser): 
    implements(conchinterfaces.ISession)

    def __init__(self, username): 
        avatar.ConchUser.__init__(self) 
        self.username = username
        channelProperties = {
            'session': SSHSession,
            'direct-tcpip': forwarding.openConnectForwardingClient,
        }
        self.channelLookup.update(channelProperties)

    def openShell(self, protocol): 
        pass

    def getPty(self, terminal, windowSize, attrs):
        return None

    def execCommand(self, protocol, cmd): 
        raise NotImplementedError

    def closed(self):
        pass

class SSHRealm(object):
    implements(portal.IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):
        if conchinterfaces.IConchUser in interfaces:
            return interfaces[0], SSHAvatar(avatarId), lambda: None
        else:
            raise Exception, "No supported interfaces found."

def generateRSAKey(keyLength=2048):
    return keys.Key(RSA.generate(keyLength, randbytes.secureRandom))

def getRSAKey(filepath):
    if not filepath.exists():
        key = generateRSAKey()
        with filepath.open('w+b') as f:
            f.write(key.toString('openssh'))
        filepath.chmod(0600)
    else:
        with filepath.open() as f:
            data = f.read()
            key = keys.Key.fromString(data)
    return key

def parseAuthorizedKeysFile(filepath):
    if filepath.exists():
        authorizedKeys = {}
        with filepath.open() as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue
                username, sep, key = line.rstrip().partition(' ')
                if not key.startswith('ssh-rsa '):
                    key = 'ssh-rsa ' + key
                key = ' '.join(key.split(' ')[:2])
                if not username in authorizedKeys:
                    authorizedKeys[username] = list()
                authorizedKeys[username].append(key)
        if authorizedKeys:
            return authorizedKeys
        else:
            print("No client keys defined in {0} -- see the file for examples.".format(filepath.path))
            sys.exit()
    else:
        # Don't edit. Run 'python senka.py' once, then modify authorized_keys.
        with filepath.open('w+b') as f:
            f.write(
                """# Examples:
#    user1 ssh-rsa AAAAB3NzaC1yc2E...
#    user2 ssh-rsa iO2NpFXc7ERmG2N...
#    user2 ssh-rsa 39AlR8iZHYZXCzn...
""")
            print("Authorized keys file created: {0}".format(filepath.path))
            print("Add your clients' usernames and public keys to this file in the format '<username> <public key>' (one set per line), then run Senka again. If a username has more than one public key, make several lines for that same username.")
            sys.exit()

def getAuthorizedKeysChecker(filepath):
    return PublicKeyCredentialsChecker(parseAuthorizedKeysFile(filepath))

def getApplication(keyFilepath, authorizedKeysFilepath, ports):

    def refreshAuthorizedKeys():
        checker.authorizedKeys = parseAuthorizedKeysFile(authorizedKeysFilepath)

    def notify(ignored, filepath, mask):
        if mask == inotify.IN_MODIFY:
            refreshAuthorizedKeys()

    application = service.Application("senka")
    key = getRSAKey(keyFilepath)
    checker = PublicKeyCredentialsChecker(parseAuthorizedKeysFile(authorizedKeysFilepath))
    serverfactory = factory.SSHFactory()
    serverfactory.portal = portal.Portal(SSHRealm())
    serverfactory.portal.registerChecker(checker)
    serverfactory.publicKeys = {'ssh-rsa': key.public()}
    serverfactory.privateKeys = {'ssh-rsa': key}

    notifier = inotify.INotify()
    notifier.startReading()
    notifier.watch(authorizedKeysFilepath, callbacks=[notify,])

    listeners = []
    for port in ports:
        internet.TCPServer(port, serverfactory).setServiceParent(application)
    return application

### Configuration
keyFilepath = FilePath('server.key')
authorizedKeysFilepath = FilePath('authorized_keys')
ports = (
    2222,
    # 2223,
    # 2224,
)
### End of configuration
application = getApplication(keyFilepath, authorizedKeysFilepath, ports)

if __name__ == '__main__':
    print("Run Senka with twistd -noy senka.tac or twistd -oy senka.tac (daemon mode).")