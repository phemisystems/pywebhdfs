import kerberos
from subprocess import Popen, PIPE


class KerberosHelper(object):
    def __init__(self, krb_server, credentials, keytab):
        self.krb_server = krb_server
        self.credentials = credentials
        self.keytab = keytab

        self.refresh_kerberos_cache()


    def acquire_kerberos_context(self):
        kerberos_principal = self.credentials["principal"]
        kerberos_realm = self.credentials["realm"]
        keytab_filepath = self.keytab

        _, krb_context = kerberos.authGSSClientInit(self.krb_server)
        kerberos.authGSSClientStep(krb_context, "")
        ticket = kerberos.authGSSClientResponse(krb_context)

        return ticket


    def refresh_kerberos_cache(self):
        # FIXME Temporary hack for debugging. We need to be sure that we have
        # a valid ticket before trying to authenticate against Kerberos.
        kinit = Popen(["kinit", "-k", "-t", self.keytab,
                "%s@%s" % (self.credentials['principal'], self.credentials['realm'])],
                stdin=PIPE, stdout=PIPE, stderr=PIPE)
        kinit.wait()
        if kinit.stderr.readlines():
            return None
