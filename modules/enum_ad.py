"""
enum_ad.py — Active Directory enumeration module for ANCScan.

Two enumeration paths are provided:

1. LDAP-based (requires valid domain credentials): full user/group listing,
   Kerberoastable detection (SPN present), AS-REP roastable detection
   (DONT_REQ_PREAUTH flag), Domain Admins membership.

2. Anonymous/credential-less (no credentials required, matches real
   attacker capability at the pre-foothold stage):
   - SAMR-based username enumeration over a null SMB session
   - Direct Kerberos AS-REQ probing per username to detect AS-REP
     roastable accounts, with no LDAP bind and no valid credentials
     needed at all — this mirrors impacket's GetNPUsers.py -no-pass
     technique.

Kerberoasting itself is NOT made credential-less here: requesting a TGS
for an SPN account genuinely requires a valid TGT (i.e. a valid domain
credential) as a protocol requirement, not an implementation limitation.
This matches real-world attacker capability — Kerberoasting always
follows an initial foothold, never precedes it.
"""
import datetime
import random

from ldap3 import Server, Connection, ALL, SUBTREE

from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nt_errors import STATUS_MORE_ENTRIES

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal

UF_DONT_REQUIRE_PREAUTH = 0x400000  # 4194304


class ADEnum:
    def __init__(self, dc_ip, domain, username='', password=''):
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.base_dn = ','.join(f'DC={part}' for part in domain.split('.'))
        self.conn = None

    # ---------------- LDAP path (requires credentials) ----------------

    def connect(self):
        server = Server(self.dc_ip, get_info=ALL)
        if self.username:
            user = f"{self.username}@{self.domain}"  # UPN format
            self.conn = Connection(server, user=user, password=self.password, auto_bind=True)
        else:
            self.conn = Connection(server, auto_bind=True)
        return self.conn

    def get_all_users(self):
        if not self.conn:
            self.connect()
        self.conn.search(
            self.base_dn,
            '(&(objectClass=user)(objectCategory=person))',
            SUBTREE,
            attributes=['sAMAccountName', 'userAccountControl', 'servicePrincipalName', 'memberOf']
        )
        return self.conn.entries

    def get_kerberoastable(self):
        if not self.conn:
            self.connect()
        self.conn.search(
            self.base_dn,
            '(&(objectClass=user)(servicePrincipalName=*))',
            SUBTREE,
            attributes=['sAMAccountName', 'servicePrincipalName', 'memberOf']
        )
        return [str(e.sAMAccountName) for e in self.conn.entries]

    def get_asrep_roastable(self):
        """LDAP-based detection. Requires credentials. Kept for when creds are available."""
        if not self.conn:
            self.connect()
        self.conn.search(
            self.base_dn,
            f'(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={UF_DONT_REQUIRE_PREAUTH}))',
            SUBTREE,
            attributes=['sAMAccountName', 'userAccountControl']
        )
        return [str(e.sAMAccountName) for e in self.conn.entries]

    def get_privileged_members(self, group_name='Domain Admins'):
        if not self.conn:
            self.connect()
        self.conn.search(
            self.base_dn,
            f'(&(objectClass=group)(cn={group_name}))',
            SUBTREE,
            attributes=['member']
        )
        if not self.conn.entries:
            return []
        return [str(m) for m in self.conn.entries[0].member]

    # ---------------- Anonymous / credential-less path ----------------

    def get_anonymous_users_samr(self):
        """
        Enumerate domain usernames via SAMR over a null SMB session.
        Requires no credentials. Will simply return an empty list if the
        target's anonymous-access restrictions block it (RestrictAnonymous,
        RestrictNullSessAccess, etc.) — that is treated as a normal,
        non-fatal outcome, not an error.
        """
        users = []
        try:
            smb_conn = SMBConnection(self.dc_ip, self.dc_ip)
            smb_conn.login('', '')

            rpctransport = transport.SMBTransport(
                self.dc_ip, filename=r'\samr', smb_connection=smb_conn
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_handle = resp['ServerHandle']

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp['Buffer']['Buffer']
            if not domains:
                return users

            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domains[0]['Name'])
            resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle, domainId=resp['DomainId'])
            domain_handle = resp['DomainHandle']

            status = STATUS_MORE_ENTRIES
            enumeration_context = 0
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(
                        dce, domain_handle, enumerationContext=enumeration_context
                    )
                except DCERPCException as e:
                    if 'STATUS_MORE_ENTRIES' not in str(e):
                        raise
                    resp = e.get_packet()

                for user in resp['Buffer']['Buffer']:
                    users.append(str(user['Name']))

                enumeration_context = resp['EnumerationContext']
                status = resp['ErrorCode']

            dce.disconnect()
        except Exception:
            # Anonymous SAMR access blocked or unavailable — normal outcome, not fatal.
            return users
        return users

    def check_asrep_roastable(self, username):
        """
        Direct Kerberos AS-REQ probe for a single username, no credentials
        required. Mirrors impacket's GetNPUsers.py '-no-pass' technique.

        Returns one of: 'vulnerable', 'not_vulnerable', 'user_not_found', 'error'
        """
        try:
            client_name = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            domain_upper = self.domain.upper()
            server_name = Principal(
                f'krbtgt/{domain_upper}', type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )

            as_req = AS_REQ()
            pac_request = KERB_PA_PAC_REQUEST()
            pac_request['include-pac'] = True
            encoded_pac_request = encoder.encode(pac_request)

            as_req['pvno'] = 5
            as_req['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
            as_req['padata'] = noValue
            as_req['padata'][0] = noValue
            as_req['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
            as_req['padata'][0]['padata-value'] = encoded_pac_request

            req_body = seq_set(as_req, 'req-body')
            opts = [
                constants.KDCOptions.forwardable.value,
                constants.KDCOptions.renewable.value,
                constants.KDCOptions.proxiable.value,
            ]
            req_body['kdc-options'] = constants.encodeFlags(opts)
            seq_set(req_body, 'sname', server_name.components_to_asn1)
            seq_set(req_body, 'cname', client_name.components_to_asn1)
            req_body['realm'] = domain_upper

            now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
            req_body['till'] = KerberosTime.to_asn1(now)
            req_body['rtime'] = KerberosTime.to_asn1(now)
            req_body['nonce'] = random.getrandbits(31)

            supported_ciphers = (int(constants.EncryptionTypes.rc4_hmac.value),)
            seq_set_iter(req_body, 'etype', supported_ciphers)

            message = encoder.encode(as_req)

            try:
                r = sendReceive(message, domain_upper, self.dc_ip)
            except KerberosError as e:
                if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                    return 'user_not_found'
                if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                    supported_ciphers = (
                        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
                    )
                    seq_set_iter(req_body, 'etype', supported_ciphers)
                    message = encoder.encode(as_req)
                    try:
                        r = sendReceive(message, domain_upper, self.dc_ip)
                    except KerberosError as e2:
                        if e2.getErrorCode() == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                            return 'user_not_found'
                        return 'error'
                else:
                    return 'error'

            # r now holds either a genuine AS-REP (vulnerable) or a
            # KRB-ERROR with PREAUTH_REQUIRED (not vulnerable) — sendReceive
            # only returns (rather than raises) for these two cases.
            try:
                decoder.decode(r, asn1Spec=KRB_ERROR())[0]
                return 'not_vulnerable'
            except Exception:
                try:
                    decoder.decode(r, asn1Spec=AS_REP())[0]
                    return 'vulnerable'
                except Exception:
                    return 'error'
        except Exception:
            return 'error'

    def get_anonymous_asrep_roastable(self, candidate_usernames=None):
        """
        Probe a list of usernames for AS-REP roastability with zero
        credentials. If candidate_usernames is not supplied, attempts
        anonymous SAMR enumeration first to build the candidate list.
        """
        if candidate_usernames is None:
            candidate_usernames = self.get_anonymous_users_samr()

        vulnerable = []
        checked = []
        for username in candidate_usernames:
            result = self.check_asrep_roastable(username)
            checked.append({'username': username, 'result': result})
            if result == 'vulnerable':
                vulnerable.append(username)
        return {'vulnerable': vulnerable, 'checked': checked}

    # ---------------- combined run ----------------

    def run(self):
        results = {'domain': self.domain, 'dc_ip': self.dc_ip, 'credentials_used': bool(self.username)}

        # Always attempt the anonymous path first — this works regardless
        # of whether credentials were supplied, and reflects what a real
        # attacker can see before any foothold.
        anon_users = self.get_anonymous_users_samr()
        results['anonymous_users_found'] = len(anon_users)
        anon_asrep = self.get_anonymous_asrep_roastable(candidate_usernames=anon_users if anon_users else None)
        results['asrep_roastable'] = anon_asrep['vulnerable']
        results['asrep_check_detail'] = anon_asrep['checked']

        if self.username:
            # Credentialed path: full LDAP enumeration, including Kerberoasting
            # (which genuinely requires a valid credential to test at all).
            try:
                self.connect()
                results['users'] = [str(e.sAMAccountName) for e in self.get_all_users()]
                results['kerberoastable'] = self.get_kerberoastable()
                results['domain_admins'] = self.get_privileged_members('Domain Admins')
                # Merge in any additional AS-REP roastable accounts LDAP can see
                # that anonymous SAMR enumeration may have missed.
                ldap_asrep = self.get_asrep_roastable()
                results['asrep_roastable'] = sorted(set(results['asrep_roastable']) | set(ldap_asrep))
            except Exception as e:
                results['error'] = str(e)
                results.setdefault('users', [])
                results.setdefault('kerberoastable', [])
                results.setdefault('domain_admins', [])
        else:
            results['users'] = anon_users
            results['kerberoastable'] = []
            results['kerberoastable_note'] = (
                'Kerberoasting requires a valid domain credential to request a '
                'service ticket (TGS) — this is a genuine Kerberos protocol '
                'requirement, not a tool limitation. Supply AD credentials to '
                'test this attack path.'
            )
            results['domain_admins'] = []

        return results


if __name__ == "__main__":
    import json
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--dc-ip", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--username", default='')
    parser.add_argument("--password", default='')
    args = parser.parse_args()

    enum = ADEnum(args.dc_ip, args.domain, args.username, args.password)
    results = enum.run()
    print(json.dumps(results, indent=2, default=str))
