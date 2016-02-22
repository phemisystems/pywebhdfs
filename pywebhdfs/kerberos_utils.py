import kerberos
import os.path
import subprocess


class KerberosContextManager(object):
    def __init__(self, krb_conn_settings, use_keytab=True):
        for param in ['principal', 'realm', 'server']:
            if param not in krb_conn_settings:
                raise ValueError('Missing parameter {0}'.format(param))

        if use_keytab:
            if 'keytab' not in krb_conn_settings:
                raise ValueError('Failed to specify path to keytab')
            keytab = krb_conn_settings['keytab']
            if not os.path.isfile(keytab):
                raise ValueError('Keytab does not exist')
        else:
            if 'passwd' not in krb_conn_settings:
                raise ValueError('Password is required if not using keytab')

        self.krb_conn_settings = krb_conn_settings
        self.use_keytab = use_keytab

    def refresh_kerberos_tgt(self, aux_args=None):
        kinit_cmd = ['kinit']
        if aux_args:
            kinit_cmd.extend(aux_args)

        if self.use_keytab:
            keytab = self.krb_conn_settings['keytab']
            kinit_cmd.extend(['-k', '-t', keytab])

        credentials = '{0}@{1}'.format(self.krb_conn_settings['principal'],
                                       self.krb_conn_settings['realm'])

        try:
            err_msg = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            if err_msg:
                return False, err_msg
        except subprocess.CalledProcessError as err:
            return False, err.output

        return True, ""

    def acquire_kerberos_context(self):
        krb_server = self.krb_conn_settings['server']
        _, krb_context = kerberos.authGSSClientInit(krb_server)

        kerberos.authGSSClientStep(krb_context, "")
        ticket = kerberos.authGSSClientResponse(krb_context)

        return ticket
