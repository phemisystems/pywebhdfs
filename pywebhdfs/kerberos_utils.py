import kerberos, krbcontext
import os.path
import subprocess


class KerberosContextManager(object):
    def __init__(self, krb_conn_settings, using_keytab=True):
        for param in ['principal', 'realm', 'server']:
            if param not in krb_conn_settings:
                raise ValueError('Missing parameter {0}'.format(param))

        if using_keytab:
            if 'keytab_file' not in krb_conn_settings:
                raise ValueError('Failed to specify path to keytab')
            keytab = krb_conn_settings['keytab_file']
            if not os.path.isfile(keytab):
                raise ValueError('Keytab does not exist')
        else:
            if 'passwd' not in krb_conn_settings:
                raise ValueError('Password is required if not using keytab')

        self.krb_conn_settings = krb_conn_settings
        self.using_keytab = using_keytab

    def refresh_kerberos_ccache(self, aux_args=None):
        if self.using_keytab:
            krbcontext.krbcontext(principal=self.krb_conn_settings['principal'],
                       using_keytab=self.using_keytab,
                       keytab_file=self.krb_conn_settings['keytab_file'])
        else:
            credentials = '{0}@{1}'.format(self.krb_conn_settings['principal'],
                                       self.krb_conn_settings['realm'])

            kinit_cmd = ['kinit', credentials]
            if aux_args:
                kinit_cmd.extend(aux_args)

            try:
                kinit = subprocess.Popen(*kinit_cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
                kinit.stdin.write('{0}\n'.format(self.krb_conn_settings['passwd']))
                kinit.wait()
            except subprocess.CalledProcessError as badcall:
                return False, badcall.output
            except OSError as oserr:
                return False, oserr.strerr

        return True, ""

    def acquire_kerberos_ticket(self):
        self.refresh_kerberos_ccache()

        krb_server = 'HTTP@{0}'.format(self.krb_conn_settings['server'])
        _, krb_context = kerberos.authGSSClientInit(krb_server)

        kerberos.authGSSClientStep(krb_context, '')
        ticket = kerberos.authGSSClientResponse(krb_context)

        return 'Negotiate {0}'.format(ticket)
