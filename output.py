import os
import sys
import csv
import json
import traceback

from stix.core import STIXPackage

from stix.indicator import Indicator
from cybox.core import Observable
from cybox.objects.address_object import Address
from cybox.objects.file_object import File
from cybox.common import Hash
from cybox.objects.uri_object import URI
from cybox.objects.win_registry_key_object import WinRegistryKey

# from cybox.objects.domain_name_object import DomainName
OUTPUT_FORMATS = ('csv', 'json', 'yara', 'autofocus', 'stix')


def getHandler(output_format):
    output_format = output_format.lower()
    if output_format not in OUTPUT_FORMATS:
        print("[WARNING] Invalid output format specified.. using CSV")
        output_format = 'csv'

    handler_format = "OutputHandler_" + output_format
    handler_class = getattr(sys.modules[__name__], handler_format)

    return handler_class()


class OutputHandler(object):
    def print_match(self, fpath, page, name, match, last=False):
        pass

    def print_header(self, fpath):
        pass

    def print_footer(self, fpath):
        pass

    def print_error(self, fpath, exception):
        traceback.print_exc()
        print("[ERROR] %s" % (exception))


class OutputHandler_stix(OutputHandler):
    def __init__(self):
        self.stix_package = STIXPackage()
        self.ind_dict = {}
        self.add_ind_list = []

    def print_match(self, fpath, page, name, match):
        # print name

        #In lib cybox.utils.__init__.normalize_to_xml an attempt is made to create
        #a unicode object from this match str. If the str is utf-8 encoded, this will fall over.
        #convert to a unicode object by decoding with utf-8 to handle both ascii & utf-8 encoded strings.

        if isinstance(match, str):
            match = unicode(match, encoding='utf-8')

        if name not in self.ind_dict:
            if name == 'IP':
                ind_ip = Indicator(title=fpath + " IP Watchlist")
                ind_ip.add_indicator_type("IP Watchlist")
                self.ind_dict['IP'] = ind_ip

            elif name == 'MD5' or name == 'SHA1' or name == 'SHA256' or name == 'Filename' or name == 'Filepath':
                ind_file = Indicator(title=fpath + " (File Hash Watchlist)")
                ind_file.add_indicator_type("File Hash Watchlist")
                self.ind_dict['MD5'] = ind_file
                self.ind_dict['SHA1'] = ind_file
                self.ind_dict['SHA256'] = ind_file
                self.ind_dict['Filename'] = ind_file
                self.ind_dict['Filepath'] = ind_file

            elif name == 'URL':
                ind_url = Indicator(title=fpath + " (URL Watchlist)")
                ind_url.add_indicator_type("URL Watchlist")
                self.ind_dict['URL'] = ind_url

            elif name == 'Host':
                ind_domain = Indicator(title=fpath + " (Domain Watchlist)")
                ind_domain.add_indicator_type("Domain Watchlist")
                self.ind_dict['Host'] = ind_domain

            elif name == 'Email':
                ind_email = Indicator(title=fpath + " (Malicious E-mail)")
                ind_email.add_indicator_type("Malicious E-mail")
                self.ind_dict['Email'] = ind_email

            elif name == 'Registry':
                ind_registrykey = Indicator(title=fpath + " (Host Characteristics)")
                ind_registrykey.add_indicator_type("Host Characteristics")
                self.ind_dict['Registry'] = ind_registrykey

        def create_file():
            new_obj = File()
            new_obj.file_name = ""
            new_obj.file_extension = ""
            new_obj.device_path = ""
            new_obj.full_path = ""
            new_obj.file_format = ""

            return new_obj

        if name in self.ind_dict:
            indicator = self.ind_dict[name]

            # ===========
            # Add new object handlers here:

            if name == 'IP':
                new_obj = Address(address_value=match, category=Address.CAT_IPV4)

            elif name == 'MD5' or name == 'SHA1' or name == 'SHA256':
                new_obj = create_file()
                new_obj.add_hash(Hash(match))

            elif name == 'URL':
                new_obj = URI(type_=URI.TYPE_URL, value=match)

            elif name == 'Host':
                new_obj = URI(type_=URI.TYPE_DOMAIN, value=match)

            elif name == 'Email':
                new_obj = Address(address_value=match,
                                  category=Address.CAT_EMAIL)  # Not sure if this is right - should this be using the email_message_object?

            elif name == 'Registry':
                new_obj = WinRegistryKey()
                new_obj.key = match
                new_obj.hive = ""

            elif name == 'Filename':
                new_obj = create_file()
                new_obj.file_name = match

            elif name == 'Filepath':  # Filepath requires filename
                new_obj = create_file()
                new_obj.file_name = match.rsplit("\\", 1)[1]  # Splits match (complete filepath) to provide filename
                new_obj.file_path = match.rsplit("\\", 1)[0]  # Splits match (complete filepath) to provide filepath


                # elif name == <type_from_parser>:
                # new_obj = STIX_Object()
            # ===========
            new_obs = Observable(new_obj, description="%s on page %d" % (fpath, page))
            indicator.add_observable(new_obs)

    def print_footer(self, fpath):
        # print "add_ind_list before: " + str(add_ind_list)

        for key in self.ind_dict:
            if self.ind_dict[key] not in self.add_ind_list:
                self.add_ind_list.append(self.ind_dict[key])
                self.stix_package.add_indicator(self.ind_dict[key])

        print self.stix_package.to_xml()


class OutputHandler_csv(OutputHandler):
    def __init__(self):
        self.csv_writer = csv.writer(sys.stdout, delimiter='\t')

    def print_match(self, fpath, page, name, match):
        self.csv_writer.writerow((fpath, page, name, match))

    def print_error(self, fpath, exception):
        self.csv_writer.writerow((fpath, '0', 'error', exception))


class OutputHandler_json(OutputHandler):
    def print_match(self, fpath, page, name, match):
        data = {
            'path': fpath,
            'file': os.path.basename(fpath),
            'page': page,
            'type': name,
            'match': match
        }

        print(json.dumps(data))

    def print_error(self, fpath, exception):
        data = {
            'path': fpath,
            'file': os.path.basename(fpath),
            'type': 'error',
            'exception': exception
        }

        print(json.dumps(data))


class OutputHandler_yara(OutputHandler):
    def __init__(self):
        self.rule_enc = ''.join(
                chr(c) if chr(c).isupper() or chr(c).islower() or chr(c).isdigit() else '_' for c in range(256))

    def print_match(self, fpath, page, name, match):
        if name in self.cnt:
            self.cnt[name] += 1
        else:
            self.cnt[name] = 1

        string_id = "$%s%d" % (name, self.cnt[name])
        self.sids.append(string_id)
        string_value = match.replace('\\', '\\\\')
        print("\t\t%s = \"%s\"" % (string_id, string_value))

    def print_header(self, fpath):
        rule_name = os.path.splitext(os.path.basename(fpath))[0].translate(self.rule_enc)

        print("rule %s" % (rule_name))
        print("{")
        print("\tstrings:")

        self.cnt = {}
        self.sids = []

    def print_footer(self, fpath):
        cond = ' or '.join(self.sids)

        print("\tcondition:")
        print("\t\t" + cond)
        print("}")


class OutputHandler_autofocus(OutputHandler):
    def __init__(self):
        self.rule_enc = ''.join(
                chr(c) if chr(c).isupper() or chr(c).islower() or chr(c).isdigit() else '_' for c in range(256))

    def print_match(self, fpath, page, name, match):
        string_value = match.replace('hxxp', 'http').replace('\\', '\\\\')

        if name == "MD5":
            auto_focus_query = '{"field":"sample.md5","operator":"is","value":\"%s\"},' % (string_value)
        elif name == "SHA1":
            auto_focus_query = '{"field":"sample.sha1","operator":"is","value":\"%s\"},' % (string_value)
        elif name == "SHA256":
            auto_focus_query = '{"field":"sample.sha256","operator":"is","value":\"%s\"},' % (string_value)
        elif name == "URL":
            auto_focus_query = '{"field":"sample.tasks.connection","operator":"contains","value":\"%s\"},' % (
            string_value)
        elif name == "Host":
            auto_focus_query = '{"field":"sample.tasks.dns","operator":"contains","value":\"%s\"},' % (string_value)
        elif name == "Registry":
            # auto_focus_query = '{"field":"sample.tasks.registry","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "Filepath":
            # auto_focus_query = '{"field":"sample.tasks.file","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "Filename":
            # auto_focus_query = '{"field":"alias.filename","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "Email":
            # auto_focus_query = '{"field":"alias.email","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "IP":
            auto_focus_query = '{"field":"sample.tasks.connection","operator":"contains","value":\"%s\"},' % (
            string_value)
        elif name == "CVE":
            return
        print(auto_focus_query)

    def print_header(self, fpath):
        rule_name = os.path.splitext(os.path.basename(fpath))[0].translate(self.rule_enc)

        print("AutoFocus Search for: %s" % (rule_name))
        print('{"operator":"Any","children":[')

    def print_footer(self, fpath):
        rule_name = os.path.splitext(os.path.basename(fpath))[0].translate(self.rule_enc)
        print('{"field":"sample.tag","operator":"is in the list","value":[\"%s\"]}]}' % (rule_name))
