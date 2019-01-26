import requests
import hashlib

TEST_MODE = 1
def _update_dns(domain,challenge,action):

 if action == 'add' :
     action = ''
 elif action == 'delete':
     action = ''
 connection_options = {
        'live' : {
         # IP whitelisting required
             'reseller_username': '<YOUR RESELLER USERNAME>',
             'api_key':'<YOUR API KEY>',
             'api_host_port': 'https://rr-n1-tor.opensrs.net:55443',
        },
        'test' : {
             # IP whitelisting not required
             'reseller_username': 'zaincloud',
             'api_key':'8fdc8834a8e27b73cd132632324ad87d25c9ccd116c7e2b94229915bf5c25f56a59394b13ab16e7caa67aefee2fd076d12aaf5c5fa78fbc2',
             'api_host_port': 'https://horizon.opensrs.net:55443',

        }
 }

 if TEST_MODE == 1:
    connection_details = connection_options['test']
 else:
    connection_details = connection_options['live']

 xml = '''
<?xml version='1.0' encoding='UTF-8' standalone='no' ?>
<!DOCTYPE OPS_envelope SYSTEM 'ops.dtd'>
<OPS_envelope>
<header>
    <version>0.9</version>
</header>
<body>
<data_block>
    <dt_assoc>
        <item key="protocol">XCP</item>
        <item key="action">{0}</item>
        <item key="object">DOMAIN</item>
        <item key="attributes">
         <dt_assoc>
               <item key="attributes">
                    <dt_assoc>
                        <item key="domain">{1}</item>
                        <item key="records">
                            <dt_assoc>
                                <item key="TXT">
                                    <dt_array>
                                        <item key="0">
                                            <dt_assoc>
                                                <item key="subdomain">_acme-challenge</item>
                                                <item key="text">{2}</item>
                                            </dt_assoc>
                                        </item>
                                    </dt_array>
                                </item>
                            </dt_assoc>
                        </item>
                    </dt_assoc>
                </item>
         </dt_assoc>
        </item>
    </dt_assoc>
</data_block>
</body>
</OPS_envelope>
'''.format(domain,challenge,action)

 md5_obj = hashlib.md5()
 md5_obj.update((xml + connection_details['api_key']).encode('utf-8'))
 signature = md5_obj.hexdigest()

 md5_obj = hashlib.md5()
 md5_obj.update((signature + connection_details['api_key']).encode('utf-8'))
 signature = md5_obj.hexdigest()

 headers = {
        'Content-Type':'text/xml',
        'X-Username': connection_details['reseller_username'],
        'X-Signature':signature,
 };

 print("Request to {} as reseller {}:".format(connection_details['api_host_port'],connection_details['reseller_username']))
 print(xml)

 r = requests.post(connection_details['api_host_port'], data = xml, headers=headers )

 print("Response:")
 if r.status_code == requests.codes.ok:
    print(r.text)
 else:
    print(r.status_code)
    print (r.text)
 return r