import os
import luther
import json
import unittest
import tempfile
import base64

class LutherTestCase(unittest.TestCase):
    def post_json(self, url, data, environ_base={'REMOTE_ADDR':'1.1.1.1'}):
        return self.app.post(
            url,
            data=data,
            content_type='application/json',
            environ_base=environ_base
        )

    def put_json(self, url, data, environ_base={'REMOTE_ADDR':'1.1.1.1'}):
        return self.app.put(
            url,
            data=data,
            content_type='application/json',
            environ_base=environ_base
        )

    def post_json_auth(self, url, data, username, password, environ_base={'REMOTE_ADDR':'1.1.1.1'}):
        creds = '%s:%s' % (username, password)
        b64_str = base64.standard_b64encode(bytes(creds.encode('ascii')))
        return self.app.post(
            url,
            data=data,
            content_type='application/json',
            environ_base=environ_base,
            headers={
                'Authorization': 'Basic %s' % b64_str.decode('ascii')
            }
        )

    def put_json_auth(self, url, data, username, password, environ_base={'REMOTE_ADDR':'1.1.1.1'}):
        creds = '%s:%s' % (username, password)
        b64_str = base64.standard_b64encode(bytes(creds.encode('ascii')))
        return self.app.put(
            url,
            data=data,
            content_type='application/json',
            environ_base=environ_base,
            headers={
                'Authorization': 'Basic %s' % b64_str.decode('ascii')
            }
        )


    def delete_json_auth(self, url, data, username, password, environ_base={'REMOTE_ADDR':'1.1.1.1'}):
        creds = '%s:%s' % (username, password)
        b64_str = base64.standard_b64encode(bytes(creds.encode('ascii')))
        return self.app.delete(
            url,
            data=data,
            content_type='application/json',
            environ_base=environ_base,
            headers={
                'Authorization': 'Basic %s' % b64_str.decode('ascii')
            }
        )

    def open_with_auth(self, url, method, username, password, data=None, environ_base={'REMOTE_ADDR':'1.1.1.1'}):
        creds = '%s:%s' % (username, password)
        b64_str = base64.standard_b64encode(bytes(creds.encode('ascii')))
        return self.app.open(
            url,
            method=method,
            headers={
                'Authorization': 'Basic %s' % b64_str.decode('ascii')
            },
            data=data,
            environ_base=environ_base
        )


    # I know this is bad but it works for me for now...
    def setUp(self):
        self.app = luther.app.test_client()

    def tearDown(self):
        pass

    ##############
    # Good tests #
    ##############

    def test_aa_guess_ipv4(self):
        rv = self.app.get('/api/v1/guess_ip', environ_base={'REMOTE_ADDR':'1.1.1.1'})
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rd['status'], 200)
        self.assertEqual(rd['guessed_ip'], '1.1.1.1')

    def test_ab_guess_ipv6_compact(self):
        rv = self.app.get('/api/v1/guess_ip', environ_base={'REMOTE_ADDR':'FE80::0202:B3FF:FE1E:8329'})
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rd['status'], 200)
        self.assertEqual(rd['guessed_ip'], 'FE80::0202:B3FF:FE1E:8329')

    def test_ac_guess_ipv6_long(self):
        rv = self.app.get('/api/v1/guess_ip', environ_base={'REMOTE_ADDR':'FE80:0000:0000:0000:0202:B3FF:FE1E:8329'})
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rd['status'], 200)
        self.assertEqual(rd['guessed_ip'], 'FE80:0000:0000:0000:0202:B3FF:FE1E:8329')

    def test_ba_frontend_unauth_user(self):
        # How are unauthenticated requests handled
        rv = self.app.get('/api/v1/subdomains', environ_base={'REMOTE_ADDR':'1.1.1.1'})
        self.assertEqual(rv.status_code, 403)

    def test_bb_add_user(self):
        # Can we add a user
        d = '{"email":"tester@travis-ci.org", "password":"weakpassword"}'
        rv = self.post_json('/api/v1/user', d)
        self.assertEqual(rv.status_code, 201)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 201)
        self.assertEqual(rd['email'], "tester@travis-ci.org")
        self.assertEqual(rd['status'], 201)

        d = '{"email":"anothertester@travis-ci.org", "password":"weakpassword"}'
        rv = self.post_json('/api/v1/user', d)
        self.assertEqual(rv.status_code, 201)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 201)
        self.assertEqual(rd['email'], "anothertester@travis-ci.org")
        self.assertEqual(rd['status'], 201)

    def test_bc_auth_user(self):
        # Can we authenticate as the user we added
        rv = self.open_with_auth('/api/v1/subdomains', 'GET', 'tester@travis-ci.org', 'weakpassword')
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rd['status'], 200)
        self.assertEqual(len(rd['subdomains']), 0)

    def test_bd_edit_user(self):
        d = '{"new_password":"betterpassword"}'
        rv = self.put_json_auth('/api/v1/user', d, 'tester@travis-ci.org', 'weakpassword')
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rd['message'], 'Password updated')
        rv = self.open_with_auth('/api/v1/subdomains', 'GET', 'tester@travis-ci.org', 'betterpassword')
        self.assertEqual(rv.status_code, 200)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(len(rd['subdomains']), 0)
        self.assertEqual(rd['status'], 200)

    def test_be_delete_user(self):
        d = '{"confirm":"DELETE"}'
        rv = self.delete_json_auth('/api/v1/user', d, 'tester@travis-ci.org', 'betterpassword')
        rd = json.loads(rv.data.decode('ascii'))
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rd['status'], 200)
        self.assertEqual(rd['message'], 'User deleted, bai bai :<')
        d = '{"email":"tester@travis-ci.org", "password":"betterpassword"}'
        rv = self.post_json('/api/v1/user', d)
        self.assertEqual(rv.status_code, 201)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 201)
        self.assertEqual(rd['email'], "tester@travis-ci.org")
        self.assertEqual(rd['status'], 201)

    def test_caa_add_sub_guess_ip(self):
        d = '{"subdomain":"travis-example"}'
        rv = self.post_json_auth('/api/v1/subdomains', d, 'tester@travis-ci.org', 'betterpassword')
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 201)
        self.assertEqual(rd['status'], 201)
        self.assertEqual(rd['subdomain'], 'travis-example')
        self.assertEqual(rd['ip'], '1.1.1.1')

    def test_cab_add_sub_spec_ip(self):
        d = '{"subdomain":"travis-ip-example", "ip":"FE80::0202:B3FF:FE1E:8329"}'
        rv = self.post_json_auth('/api/v1/subdomains', d, 'tester@travis-ci.org', 'betterpassword')
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 201)
        self.assertEqual(rd['status'], 201)
        self.assertEqual(rd['subdomain'], 'travis-ip-example')
        self.assertEqual(rd['ip'], 'fe80:0000:0000:0000:0202:b3ff:fe1e:8329')

    def test_cba_get_and_update_subs(self):
        # Get list of subdomains
        rv = self.open_with_auth('/api/v1/subdomains', 'GET', 'tester@travis-ci.org', 'betterpassword')
        self.assertEqual(rv.status_code, 200)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rd['status'], 200)
        self.assertEqual(len(rd['subdomains']), 2)
        self.assertEqual(rd['subdomains'][0]['ip'], '1.1.1.1')
        self.assertEqual(rd['subdomains'][0]['subdomain'], 'travis-example')
        self.assertEqual(rd['subdomains'][1]['ip'], 'fe80:0000:0000:0000:0202:b3ff:fe1e:8329')
        self.assertEqual(rd['subdomains'][1]['subdomain'], 'travis-ip-example')
        self.assertIsNotNone(rd['subdomains'][0]['subdomain_token'])
        self.assertIsNotNone(rd['subdomains'][1]['subdomain_token'])
        addr_one = rd['subdomains'][0]['GET_update_URI']
        addr_two = rd['subdomains'][1]['GET_update_URI']

        # Update via GET interface
        rv = self.app.get(addr_one+'/5.5.5.5', environ_base={'REMOTE_ADDR':'1.1.1.1'})
        self.assertEqual(rv.status_code, 200)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rd['status'], 200)
        self.assertEqual(rd['subdomain'], 'travis-example')
        self.assertEqual(rd['ip'], '5.5.5.5')

        # Convert to IPv6
        rv = self.app.get(addr_two+'/2001:db8:1234:ffff:ffff:ffff:ffff:ffff', environ_base={'REMOTE_ADDR':'1.1.1.1'})
        self.assertEqual(rv.status_code, 200)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rd['status'], 200)
        self.assertEqual(rd['subdomain'], 'travis-ip-example')
        self.assertEqual(rd['ip'], '2001:0db8:1234:ffff:ffff:ffff:ffff:ffff')

    def test_cbb_get_and_fancy_update_subs(self):
        # Get list of subdomains
        rv = self.open_with_auth('/api/v1/subdomains', 'GET', 'tester@travis-ci.org', 'betterpassword')
        self.assertEqual(rv.status_code, 200)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rd['status'], 200)
        self.assertEqual(len(rd['subdomains']), 2)
        self.assertEqual(rd['subdomains'][0]['ip'], '5.5.5.5')
        self.assertEqual(rd['subdomains'][0]['subdomain'], 'travis-example')
        self.assertEqual(rd['subdomains'][1]['ip'], '2001:0db8:1234:ffff:ffff:ffff:ffff:ffff')
        self.assertEqual(rd['subdomains'][1]['subdomain'], 'travis-ip-example')
        self.assertIsNotNone(rd['subdomains'][0]['subdomain_token'])
        self.assertIsNotNone(rd['subdomains'][1]['subdomain_token'])
        token_one = rd['subdomains'][0]['subdomain_token']
        token_two = rd['subdomains'][1]['subdomain_token']

        # Update via fancy interface inc. guess, convert back to IPv4
        d = '{"subdomains": [{"subdomain": "travis-example", "subdomain_token": "'+token_one+'"},{"subdomain": "travis-ip-example", "subdomain_token": "'+token_two+'", "ip": "8.8.8.8"}]}'
        rv = self.put_json('/api/v1/subdomains', d)
        self.assertEqual(rv.status_code, 200)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rd['status'], 200)
        self.assertEqual(rd['subdomains'][0]['ip'], '1.1.1.1')
        self.assertEqual(rd['subdomains'][0]['subdomain'], 'travis-example')
        self.assertEqual(rd['subdomains'][1]['ip'], '8.8.8.8')
        self.assertEqual(rd['subdomains'][1]['subdomain'], 'travis-ip-example')
        self.assertIsNotNone(rd['subdomains'][0]['subdomain_token'])
        self.assertIsNotNone(rd['subdomains'][1]['subdomain_token'])

    def test_cc_regen_sub_tokens(self):
        rv = self.open_with_auth('/api/v1/subdomains', 'GET', 'tester@travis-ci.org', 'betterpassword')
        self.assertEqual(rv.status_code, 200)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rd['status'], 200)
        self.assertEqual(len(rd['subdomains']), 2)
        self.assertEqual(rd['subdomains'][0]['ip'], '1.1.1.1')
        self.assertEqual(rd['subdomains'][0]['subdomain'], 'travis-example')
        self.assertEqual(rd['subdomains'][1]['ip'], '8.8.8.8')
        self.assertEqual(rd['subdomains'][1]['subdomain'], 'travis-ip-example')
        self.assertIsNotNone(rd['subdomains'][0]['subdomain_token'])
        self.assertIsNotNone(rd['subdomains'][1]['subdomain_token'])
        addr_one = rd['subdomains'][0]['regenerate_subdomain_token_URI']
        addr_two = rd['subdomains'][1]['regenerate_subdomain_token_URI']
        token_one = rd['subdomains'][0]['subdomain_token']
        token_two = rd['subdomains'][1]['subdomain_token']

        rv = self.open_with_auth(addr_one, 'POST', 'tester@travis-ci.org', 'betterpassword', environ_base={'REMOTE_ADDR':'1.1.1.1'})
        self.assertEqual(rv.status_code, 200)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rd['status'], 200)
        self.assertNotEqual(rd['subdomain_token'], token_one)

        rv = self.open_with_auth(addr_two, 'POST', 'tester@travis-ci.org', 'betterpassword', environ_base={'REMOTE_ADDR':'1.1.1.1'})
        self.assertEqual(rv.status_code, 200)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rd['status'], 200)
        self.assertNotEqual(rd['subdomain_token'], token_two)


    #############
    # Bad tests #
    #############

    # Can we add bad users?
    def test_xaa_add_bad_user_email(self):
        # bad email (regex)
        d = '{"email":"tester", "password":"weakpassword"}'
        rv = self.post_json('/api/v1/user', d)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 400)
        self.assertEqual(rd['status'], 400)
        self.assertEqual(rd['message'], 'Invalid email address')

    def test_xab_add_bad_user_pass(self):
        # bad password
        d = '{"email":"tester@gmail.com", "password":""}'
        rv = self.post_json('/api/v1/user', d)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 400)
        self.assertEqual(rd['status'], 400)
        self.assertEqual(rd['message'], 'Bad request, missing arguments')

    def test_xac_add_bad_user_mx(self):
        # bad email (MX check)
        d = '{"email":"tester@fakefakeasdasd.badtld", "password":"password"}'
        rv = self.post_json('/api/v1/user', d)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 400)
        self.assertEqual(rd['status'], 400)
        self.assertEqual(rd['message'], 'Invalid email address')

    def test_xba_auth_bad_user(self):
        # Can we authenticate a random user not registered
        rv = self.open_with_auth('/api/v1/subdomains', 'GET', 'der@der.com', 'weakpassword')
        self.assertEqual(rv.status_code, 403)

    def test_xbb_auth_bad_user_pass(self):
        # Bad credentials
        rv = self.open_with_auth('/api/v1/subdomains', 'GET', 'der@der.com', '')
        self.assertEqual(rv.status_code, 403)

    def test_xbc_auth_bad_user_email(self):
        rv = self.open_with_auth('/api/v1/subdomains', 'GET', '', 'weakpassword')
        self.assertEqual(rv.status_code, 403)

    def test_xbd_auth_bad_user_both(self):
        rv = self.open_with_auth('/api/v1/subdomains', 'GET', '', '')
        self.assertEqual(rv.status_code, 403)

    def test_xca_delete_user_bad_creds(self):
        d = '{"confirm":"DELETE"}'
        rv = self.delete_json_auth('/api/v1/user', d, 'tester@travis-ci.org', 'notmypassword')
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 403)
        self.assertEqual(rd['error'], 'Unauthorized access')

    def test_xda_delete_sub_bad_user(self):
        d = '{"subdomain":"travis-example", "confirm":"DELETE"}'
        rv = self.delete_json_auth('/api/v1/subdomains', d, 'anothertester@travis-ci.org', 'weakpassword')
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 400)
        self.assertEqual(rd['status'], 400)
        self.assertEqual(rd['message'], 'Bad request, invalid subdomain')

    def test_xdb_delete_sub_no_user(self):
        d = '{"subdomain":"travis-example", "confirm":"DELETE"}'
        rv = self.delete_json_auth('/api/v1/subdomains', d, '', '')
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 403)
        self.assertEqual(rd['error'], 'Unauthorized access')

    def test_xdc_delete_sub_bad_sub(self):
        d = '{"subdomain":"travis-not-an-example", "confirm":"DELETE"}'
        rv = self.delete_json_auth('/api/v1/subdomains', d, 'anothertester@travis-ci.org', 'weakpassword')
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 400)
        self.assertEqual(rd['status'], 400)
        self.assertEqual(rd['message'], 'Bad request, invalid subdomain')

    def test_xx_guess_bad_ip(self):
        rv = self.app.get('/api/v1/guess_ip', environ_base={'REMOTE_ADDR':'asdimnotaipaddress'})
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 400)
        self.assertEqual(rd['status'], 400)
        self.assertEqual(rd['message'], 'Invalid IP address')

    def test_xxx_guess_bad_ip(self):
        rv = self.app.get('/api/v1/guess_ip', environ_base={'REMOTE_ADDR':'7.7.7.7.7'})
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 400)
        self.assertEqual(rd['status'], 400)
        self.assertEqual(rd['message'], 'Invalid IP address')

    def test_xxxx_guess_bad_ip(self):
        rv = self.app.get('/api/v1/guess_ip', environ_base={'REMOTE_ADDR':'2074613113'})
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 400)
        self.assertEqual(rd['status'], 400)
        self.assertEqual(rd['message'], 'Invalid IP address')

    ##########################
    # Cleanup, also tests... #
    ##########################

    def test_z_delete_subs(self):
        d = '{"subdomain":"travis-example", "confirm":"DELETE"}'
        rv = self.delete_json_auth('/api/v1/subdomains', d, 'tester@travis-ci.org', 'betterpassword')
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rd['status'], 200)
        self.assertEqual(rd['message'], 'Subdomain deleted')

        d = '{"subdomain":"travis-ip-example", "confirm":"DELETE"}'
        rv = self.delete_json_auth('/api/v1/subdomains', d, 'tester@travis-ci.org', 'betterpassword')
        self.assertEqual(rv.status_code, 200)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rd['status'], 200)
        self.assertEqual(rd['message'], 'Subdomain deleted')

    def test_zz_list_no_subs(self):
        rv = self.open_with_auth('/api/v1/subdomains', 'GET', 'tester@travis-ci.org', 'betterpassword')
        self.assertEqual(rv.status_code, 200)
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rd['status'], 200)
        self.assertEqual(len(rd['subdomains']), 0)

    def test_zzz_delete_users(self):
        d = '{"confirm":"DELETE"}'
        rv = self.delete_json_auth('/api/v1/user', d, 'tester@travis-ci.org', 'betterpassword')
        rd = json.loads(rv.data.decode('ascii'))
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rd['status'], 200)
        self.assertEqual(rd['message'], 'User deleted, bai bai :<')

        d = '{"confirm":"DELETE"}'
        rv = self.delete_json_auth('/api/v1/user', d, 'anothertester@travis-ci.org', 'weakpassword')
        rd = json.loads(rv.data.decode('ascii'))
        rd = json.loads(rv.data.decode('ascii'))
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rd['status'], 200)
        self.assertEqual(rd['message'], 'User deleted, bai bai :<')

    def test_zzzz_rate_limit(self):
        with self.assertRaises(AssertionError):
            for i in range(luther.app.config['RATE_LIMIT_ACTIONS']):
                rv = self.app.get('/api/v1/guess_ip', environ_base={'REMOTE_ADDR':'99.99.99.99'})
                rd = json.loads(rv.data.decode('ascii'))
                self.assertEqual(rv.status_code, 200)
                self.assertEqual(rd['status'], 200)
                self.assertEqual(rd['guessed_ip'], '1.1.1.1')

if __name__ == '__main__':
    luther.app.config['TESTING'] = True
    unittest.main()
