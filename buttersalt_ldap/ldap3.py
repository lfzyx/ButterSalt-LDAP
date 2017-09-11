from ButterSalt import salt
from flask import current_app


class Ldap3(object):

    def __init__(self):
        self.tgt = current_app.config.get('LDAP_SERVER')
        self.connect = {'url': 'ldap://127.0.0.1:389',
                        'bind': {
                            'password': current_app.config.get('LDAP_BINDPW'),
                            'method': 'simple',
                            'dn': current_app.config.get('LDAP_BINDDN')},
                        }

    def search(self, scope, filterstr):
        data = salt.execution_command_low(tgt=self.tgt, fun='ldap3.search',
                                          args=[self.connect],
                                          kwargs={'base': current_app.config.get('LDAP_BASEDN'),
                                                  'scope': scope,
                                                  'filterstr': filterstr, }).get(current_app.config.get('LDAP_SERVER'))
        return data

    def add(self, cn=None, ou=None, o=None, userpassword=None, mail=None, key=None):
        data = salt.execution_command_low(tgt=self.tgt, fun='ldap3.add',
                                          args=[self.connect],
                                          kwargs={'dn': 'cn=%s,ou=%s,%s' %
                                                        (cn, ou, current_app.config.get('LDAP_BASEDN')),
                                                  'attributes': {'userPassword':  [userpassword],
                                                                 'sn': [cn], 'mail': [mail],
                                                                 'ou': [ou], 'o': [o], 'userPKCS12': [key],
                                                                 'objectClass': ['inetOrgPerson',
                                                                                 'organizationalPerson',
                                                                                 'person', 'top']}})
        return data

    def delete(self, dn):
        data = salt.execution_command_low(tgt=self.tgt,
                                          fun='ldap3.delete',
                                          args=[self.connect],
                                          kwargs={'dn': dn})
        return data
