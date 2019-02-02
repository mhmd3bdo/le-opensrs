import requests
import hashlib
import xml.etree.ElementTree as ET

def _update_dns(domain,challenge):

    def text_element(parent, tag, text, *args, **kwargs):
        element = ET.SubElement(parent, tag, *args, **kwargs)
        element.text = text
        return element

    def xml_request(domain, action, data=''):
        root = ET.Element("OPS_envelope")
        header = ET.Element("header")
        body = ET.Element("body")
        version = ET.Element("version")
        data_block = ET.Element("data_block")
        dt_assoc = ET.Element("dt_assoc")
        attr_dt_assoc = ET.Element("dt_assoc")
        item_attributes = ET.Element("item")
        item_attributes.attrib = {'key': 'attributes'}
        version.text = '0.9'
        root.append(header)
        root.append(body)
        header.append(version)
        body.append(data_block)
        data_block.append(dt_assoc)
        text_element(dt_assoc, 'item', 'XCP', attrib={'key': 'protocol'})
        text_element(dt_assoc, 'item', action, attrib={'key': 'action'})
        text_element(dt_assoc, 'item', 'DOMAIN', attrib={'key': 'object'})
        dt_assoc.append(item_attributes)
        item_attributes.append(attr_dt_assoc)
        text_element(attr_dt_assoc, 'item', domain, attrib={'key': 'domain'})
        if data != '':
            attr_dt_assoc.append(res_item)
        xml = ET.tostring(root, encoding="unicode", method="xml")
        xml = ("\n"
               "<?xml version=\'1.0\' encoding=\'UTF-8\' standalone=\'no\'?>\n"
               "<!DOCTYPE OPS_envelope SYSTEM \'ops.dtd\'>\n" + xml)
        return xml

    def xml_header(xml):
        md5_obj = hashlib.md5()
        md5_obj.update((xml + connection_details['api_key']).encode('utf-8'))
        signature = md5_obj.hexdigest()

        md5_obj = hashlib.md5()
        md5_obj.update((signature + connection_details['api_key']).encode('utf-8'))
        signature = md5_obj.hexdigest()

        headers = {'Content-Type': 'text/xml', 'X-Username': connection_details['reseller_username'],
                   'X-Signature': signature, };
        return headers

    # main
    action = 'get_dns_zone'


    TEST_MODE = 1
    connection_options = {'live': {# IP whitelisting required
        'reseller_username': 'zaincloud',
        'api_key': '0261e22a98a7017ca635ef68161f12cd5320fb1f1cc6f12b943e574a8b090cc58d02c48b17b049d4364dc3a13b29b7d57fd711343bfc8492',
        'api_host_port': 'https://rr-n1-tor.opensrs.net:55443', }, 'test': {# IP whitelisting not required
        'reseller_username': 'zaincloud',
        'api_key': '8fdc8834a8e27b73cd132632324ad87d25c9ccd116c7e2b94229915bf5c25f56a59394b13ab16e7caa67aefee2fd076d12aaf5c5fa78fbc2',
        'api_host_port': 'https://horizon.opensrs.net:55443',

    }}

    if TEST_MODE == 1:
        connection_details = connection_options['test']
    else:
        connection_details = connection_options['live']

    xml = xml_request(domain, action)
    headers = xml_header(xml)
    print("Request to {} as reseller {}:".format(connection_details['api_host_port'],
                                                 connection_details['reseller_username']))
    print(xml)

    r = requests.post(connection_details['api_host_port'], data=xml, headers=headers)

    print("Response:")
    if r.status_code == requests.codes.ok:
        print(r.text)
    else:
        print(r.status_code)
        print(r.text)

    res = ET.fromstring(r.text)
    res_item = res.find("./body/data_block/dt_assoc/item/[@key='attributes']/dt_assoc/item/[@key='records']")
    acme = res.find(
        "./body/data_block/dt_assoc/item/[@key='attributes']/dt_assoc/item/[@key='records']/dt_assoc/item/[@key='TXT']/dt_array/item/dt_assoc/item/[@key='text']")
    print(acme.text)
    acme.text = challenge
    action = 'set_dns_zone'
    xml = xml_request(domain, action, res_item)
    headers = xml_header(xml)
    print("Request to {} as reseller {}:".format(connection_details['api_host_port'],
                                                 connection_details['reseller_username']))
    print(xml)

    r = requests.post(connection_details['api_host_port'], data=xml, headers=headers)

    print("Response:")
    if r.status_code == requests.codes.ok:
        print(r.text)
    else:
        print(r.status_code)
        print(r.text)

    return (r)
