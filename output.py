import os
import sys
import csv
import json
import traceback

from stix.core import STIXPackage
from stix.utils import set_id_namespace
from stix.indicator import Indicator
from cybox.core import Observable
from cybox.objects.address_object import Address
from cybox.objects.file_object import File
from cybox.common import Hash
from cybox.objects.uri_object import URI
from cybox.objects.win_registry_key_object import WinRegistryKey

ipwatchlist = 0
filehashwatchlist = 0
urlwatchlist = 0
domainwatchlist = 0
malemailist = 0
hostcharlist = 0

ind_dict = {}

#from cybox.objects.domain_name_object import DomainName
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
    def print_match(self, fpath, page, name, match, last = False):
        pass

    def print_header(self, fpath):
        pass

    def print_footer(self, fpath):
        pass

    def print_error(self, fpath, exception):
        traceback.print_exc()
        print("[ERROR] %s" % (exception))




class OutputHandler_stix(OutputHandler):
    def print_matc(self, fpath, page, name, match, last = False):        
        pass

    global stix_package
    global ind_dict
    global add_ind_list


    NAMESPACE = {"http://www.cert.gov.uk" : "certuk"} # Add appropriate namespace here
    set_id_namespace(NAMESPACE) # new ids will be prefixed by "certuk"
    stix_package = STIXPackage()
    add_ind_list = []
    

    def print_match(self, fpath, page, name, match):   
        global ipwatchlist
        global filehashwatchlist
        global urlwatchlist
        global domainwatchlist
        global malemailist
        global hostcharlist

        #print name
        
        global ind_dict    
        print name
        if name == 'IP': 
            #print "IP WATCHLIST: " + str(ipwatchlist)
            if ipwatchlist == 0:
                #print "ipwatchlist = " + str(ipwatchlist) 
                ind_ip = Indicator() 
                ind_ip.add_indicator_type("IP Watchlist") 
                ind_dict['IP'] = ind_ip
                ipwatchlist = 1
        
        elif name == 'MD5' or name == 'SHA1' or name == 'SHA256':
            if filehashwatchlist == 0:   
                ind_file = Indicator()             
                ind_file.add_indicator_type("File Hash Watchlist") 
                ind_dict['MD5'] = ind_file
                ind_dict['SHA1'] = ind_file
                ind_dict['SHA256'] = ind_file
                filehashwatchlist = 1




        elif name == 'URL':
            if urlwatchlist == 0:  
                ind_url = Indicator()            
                ind_url.add_indicator_type("URL Watchlist")
                ind_dict['URL'] = ind_url
                urlwatchlist = 1

        elif name == 'Host':
            if domainwatchlist == 0:  
                ind_domain = Indicator()              
                ind_domain.add_indicator_type("Domain Watchlist")
                ind_dict['Host'] = ind_domain
                domainwatchlist = 1

        elif name == 'Email':
            if malemailist == 0:  
                ind_email = Indicator()             
                ind_email.add_indicator_type("Malicious E-mail")
                ind_dict['Email'] = ind_email
                malemailist = 1

        elif name == 'Registry':
            if hostcharlist == 0: 
                ind_registrykey = Indicator()              
                ind_registrykey.add_indicator_type("Host Characteristics")
                ind_dict['Registry'] = ind_registrykey
                hostcharlist = 1

        elif name == 'Filename':
            if filehashwatchlist == 0 or 'Filename' not in ind_dict: 
                ind_file = Indicator()               
                ind_file.add_indicator_type("File Hash Watchlist")
                ind_dict['Filename'] = ind_file
                filehashwatchlist = 1

        elif name == 'Filepath':  # Filepath requires filename    
            if filehashwatchlist == 0 or 'Filepath' not in ind_dict: 
                ind_file = Indicator()               
                ind_file.add_indicator_type("File Hash Watchlist")
                ind_dict['Filepath'] = ind_file
                filehashwatchlist = 1



        if name in ind_dict:            
            indicator = ind_dict[name]
            indicator.title = fpath            
            #===========
            # Add new object handlers here:
            
            if name == 'IP':                
                new_obj = Address(address_value=match, category=Address.CAT_IPV4)

            elif name == 'MD5' or name == 'SHA1' or name == 'SHA256':
                new_obj = File()                
                new_obj.add_hash(Hash(match))

            elif name == 'URL':
                new_obj = URI(type_=URI.TYPE_URL, value=match)

            elif name == 'Host':
                new_obj = URI(type_=URI.TYPE_DOMAIN, value=match)

            elif name == 'Email':
                new_obj = Address(address_value=match, category=Address.CAT_EMAIL) #Not sure if this is right - should this be using the email_message_object? 

            elif name == 'Registry':
                new_obj = WinRegistryKey(values=match)

            elif name == 'Filename':  
                new_obj = File()                
                new_obj.file_name = match

            elif name == 'Filepath':  # Filepath requires filename                             
                new_obj = File()
                new_obj.file_name = match.rsplit("\\",1)[1] #Splits match (complete filepath) to provide filename
                new_obj.file_path = match.rsplit("\\",1)[0] #Splits match (complete filepath) to provide filepath


            #elif name == <type_from_parser>:
                #new_obj = STIX_Object()
            #===========

            new_obs = Observable(new_obj)
            new_obs.title = "Page Ref: " + str(page)
            indicator.add_observable(new_obs)

    def print_footer(self, fpath):
        global ind_dict
        global add_ind_list
        #print "add_ind_list before: " + str(add_ind_list)


        for key in ind_dict:            
            if ind_dict[key] not in add_ind_list:
                add_ind_list.append(ind_dict[key])
                stix_package.add_indicator(ind_dict[key])




       
        #print stix_package.to_xml()
        data = stix_package.to_xml()
        

        scriptpath = os.getcwd()        
        outputpath = scriptpath + ("/Output/")  #

        head, sep, tail = fpath.partition('.')
        outputfile = head + ".xml"
        newstixfile = open(outputpath + outputfile, "w")
        newstixfile.write(data)
        newstixfile.close()

class OutputHandler_csv(OutputHandler):
    def __init__(self):
        self.csv_writer = csv.writer(sys.stdout, delimiter = '\t')

    def print_match(self, fpath, page, name, match):
        self.csv_writer.writerow((fpath, page, name, match))

    def print_error(self, fpath, exception):
        self.csv_writer.writerow((fpath, '0', 'error', exception))

class OutputHandler_json(OutputHandler):
    def print_match(self, fpath, page, name, match):
        data = {
            'path' : fpath,
            'file' : os.path.basename(fpath),
            'page' : page,
            'type' : name,
            'match': match
        }

        print(json.dumps(data))

    def print_error(self, fpath, exception):
        data = {
            'path'      : fpath,
            'file'      : os.path.basename(fpath),
            'type'      : 'error',
            'exception' : exception
        }

        print(json.dumps(data))

class OutputHandler_yara(OutputHandler):
    def __init__(self):
        self.rule_enc = ''.join(chr(c) if chr(c).isupper() or chr(c).islower() or chr(c).isdigit() else '_' for c in range(256))

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
        self.rule_enc = ''.join(chr(c) if chr(c).isupper() or chr(c).islower() or chr(c).isdigit() else '_' for c in range(256))

    def print_match(self, fpath, page, name, match):
        string_value = match.replace('hxxp', 'http').replace('\\', '\\\\')

        if name == "MD5":
            auto_focus_query = '{"field":"sample.md5","operator":"is","value":\"%s\"},' % (string_value)
        elif name == "SHA1":
            auto_focus_query = '{"field":"sample.sha1","operator":"is","value":\"%s\"},' % (string_value)
        elif name == "SHA256":
            auto_focus_query = '{"field":"sample.sha256","operator":"is","value":\"%s\"},' % (string_value)
        elif name == "URL":
            auto_focus_query = '{"field":"sample.tasks.connection","operator":"contains","value":\"%s\"},' % (string_value)
        elif name == "Host":
            auto_focus_query = '{"field":"sample.tasks.dns","operator":"contains","value":\"%s\"},' % (string_value)
        elif name == "Registry":
            #auto_focus_query = '{"field":"sample.tasks.registry","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "Filepath":
            #auto_focus_query = '{"field":"sample.tasks.file","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "Filename":
            #auto_focus_query = '{"field":"alias.filename","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "Email":
            #auto_focus_query = '{"field":"alias.email","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "IP":
            auto_focus_query = '{"field":"sample.tasks.connection","operator":"contains","value":\"%s\"},' % (string_value)
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



