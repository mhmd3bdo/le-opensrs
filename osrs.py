import configparser
import requests
import hashlib
import logging
import xml.etree.ElementTree as et


log = logging.getLogger('le-opensrs')
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)

def _update_dns(domain,challenge):
    def text_element(parent, tag, text, *args, **kwargs):
        element = et.SubElement(parent, tag, *args, **kwargs)
        element.text = text
        return element

    def xml_request(domain, action, data=''):
        root = et.Element("OPS_envelope")
        header = et.Element("header")
        body = et.Element("body")
        version = et.Element("version")
        data_block = et.Element("data_block")
        dt_assoc = et.Element("dt_assoc")
        attr_dt_assoc = et.Element("dt_assoc")
        item_attributes = et.Element("item")
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
            attr_dt_assoc.append(records)
        xml = et.tostring(root, encoding="unicode", method="xml")
        xml = ("\n"
               "<?xml version=\'1.0\' encoding=\'UTF-8\' standalone=\'no\'?>\n"
               "<!DOCTYPE OPS_envelope SYSTEM \'ops.dtd\'>\n" + xml)
        return xml

    def xml_header(xml):
        md5_obj = hashlib.md5()
        md5_obj.update((xml + config['opensrs']['api_key']).encode('utf-8'))
        signature = md5_obj.hexdigest()

        md5_obj = hashlib.md5()
        md5_obj.update((signature + config['opensrs']['api_key']).encode('utf-8'))
        signature = md5_obj.hexdigest()

        headers = {'Content-Type': 'text/xml', 'X-Username': config['opensrs']['reseller_username'],
                   'X-Signature': signature, };
        return headers

    # main
    action = 'get_dns_zone'
    config = configparser.ConfigParser()
    config.read('config')
    xml = xml_request(domain, action)
    headers = xml_header(xml)
    log.info("Request to {} as reseller {}:".format(config['opensrs']['api_host_port'],
                                                    config['opensrs']['reseller_username']))
    log.info(xml)
    r = requests.post(config['opensrs']['api_host_port'], data=xml, headers=headers)
    log.info("Response:")
    log.info(r.text)
    res = et.fromstring(r.text)
    dt_assoc = et.Element("dt_assoc")
    dt_array = et.Element("dt_array")
    item_rcd = et.Element("item")
    record_exist = False
    records = res.find("./body/data_block/dt_assoc/item/[@key='attributes']/dt_assoc/item/[@key='records']")
    txt_records = res.findall(
        "./body/data_block/dt_assoc/item/[@key='attributes']/dt_assoc/item/[@key='records']/dt_assoc/item/[@key='TXT']/dt_array/item")
    txt_index = len(txt_records)
    txt_record = res.find(
        "./body/data_block/dt_assoc/item/[@key='attributes']/dt_assoc/item/[@key='records']/dt_assoc/item/[@key='TXT']/dt_array")
    if txt_index == 0:
        log.info("There is no TXT record resources ... will be added")
        res_item = res.find(
            "./body/data_block/dt_assoc/item/[@key='attributes']/dt_assoc/item/[@key='records']/dt_assoc")
        item_rcd.attrib = {'key': 'records'}
        item_rcd.append(res_item)
        item_txt = et.Element("item")
        item_txt.attrib = {'key': 'TXT'}
        item_txt.append(dt_array)
        res_item.append(item_txt)
        item_n = et.Element("item")
        item_n.attrib = {'key': '{0}'.format(txt_index)}
        item_n.append(dt_assoc)
        text_element(dt_assoc, 'item', '_acme-challenge', attrib={'key': 'subdomain'})
        text_element(dt_assoc, 'item', challenge, attrib={'key': 'text'})
        dt_array.append(item_n)
    else:
        log.info("TXT record resources are exist")
        for x in txt_records:
            f = x.find("./dt_assoc/item/[@key='subdomain']").text
            if f == '_acme-challenge':
                record_exist = True
                log.info("found previous TXT record for acme .... will attempts to update it")
                pointer = x.attrib
                break
        if record_exist:
            acme = records.find(
                "./dt_assoc/item/[@key='TXT']/dt_array/item/[@key='{0}']/dt_assoc/item/[@key='text']".format(
                    pointer['key']))
            acme.text = challenge
        else:
            log.info("install new acme TXT record")
            item_n = et.Element("item")
            item_n.attrib = {'key': '{0}'.format(txt_index)}
            item_n.append(dt_assoc)
            text_element(dt_assoc, 'item', '_acme-challenge', attrib={'key': 'subdomain'})
            text_element(dt_assoc, 'item', challenge, attrib={'key': 'text'})
            txt_record.append(item_n)
    action = 'set_dns_zone'
    xml = xml_request(domain, action, records)
    headers = xml_header(xml)
    log.info("Request to {} as reseller {}:".format(config['opensrs']['api_host_port'],
                                                    config['opensrs']['reseller_username']))
    log.info(xml)
    r = requests.post(config['opensrs']['api_host_port'], data=xml, headers=headers)
    log.info("Response:")
    log.info(r.text)
