#This takes as input a .nessus scan file with either vulnerability or compliance info (or both)
#and dumps the data into elasticsearc into wazuh  index
#
#autor: @Ar0xA / ar0xa@tldr.nu
#
#note: assumes timezone on nessus scanner and this script are the same!

from bs4 import BeautifulSoup

import argparse
import sys
import os
import io
import json
import configparser
import urllib3
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from objdict import ObjDict
from dateutil.parser import parse
from datetime import timedelta

#check if index exists
def ES_index_check (args):
  #what index to we need to post to?
  #can we reach the server?
  es_server =  args.elasticsearchserver
  es_port = args.elasticsearchport
  es_index = args.elasticsearchindex
  es_url = "http://" + es_server + ":" + str(es_port) + "/"

  #construct indexname
  year, month, day, hour, minute = time.strftime("%Y,%m,%d,%H,%M").split(',')
  es_index = es_index + "-" +  year + "." + month +"."+ day

  #test if index esists
  http = urllib3.PoolManager()
  r = http.request('HEAD', es_url+es_index)

  #we need the existing index
  if r.status == 404:
      print ("Index %s does not exist, sorry. quitting." % (es_index))
      sys.exit(1)
  elif r.status == 200:
      print ("Index already exists. Lets insert our data!")

  elif not r.status == 200:
      print ("Something is wrong with the index, but i have no idea what. I give up!")
      print (r.status)
      sys.exit(1)

#we retreive the agent.id from the /var/ossec/etc/client.keys
def get_id_from_keys(args, hostip):
    try:
        with open(args.ossec,'r') as keysfile:
            filedata = keysfile.readlines()
            for line in filedata:
                if hostip in line:
                    #if we find it, we need the first number 
                    return line.split(" ",1)[0]
    except:
        print ("Cant open %s. am I in the correct group or on the right system?" % (args.ossec))
        sys.exit(1)
    return False

#post data to elastic
def post_to_ES(json_data,args, task_id):
  #what index to we need to post to?
  #can we reach the server?
  es_server =  args.elasticsearchserver
  es_port = args.elasticsearchport
  es_index = args.elasticsearchindex
  es_url = "http://" + es_server + ":" + str(es_port) + "/"

  #construct indexname
  year, month, day, hour, minute = time.strftime("%Y,%m,%d,%H,%M").split(',')
  es_index = es_index + "-" +  year + "." + month +"."+ day

  http = urllib3.PoolManager()

  #index exists, lets post the data #yolo
 
  r = http.request('POST', es_url+es_index+"/wazuh", headers={'Content-Type':'application/json'}, body=json_data)
  if not r.status  == 201:
    print ("well, something went wrong, thats embarrasing")
    print (r.status)
    print (r.reason)
    sys.exit(1)

#here we parse results from the nessus file, we extract the vulnerabiltiy information
# we create a host, where we have general data and findings.
# General date is always there, findings can be none, one or many
# Some items in teh findings are always there, some are optional.
# The optional ones have some which can be arrays

def parse_to_json(nessus_xml_data, args):

    #some quick report checking
    data =ObjDict()

    tmp_scanname = nessus_xml_data.report['name']
    if len(tmp_scanname) == 0:
        print ('Didn\'t find report name in file. is this a valid nessus file?')
        sys.exit(1)
    else:
        data.scanname = tmp_scanname

    #policyused
    data.scanpolicy = nessus_xml_data.policyname.get_text()

    # see if there are any hosts that are reported on
    hosts = nessus_xml_data.findAll('reporthost')
    if len(hosts) == 0:
        print ('Didn\'t find any hosts in file. Is this a valid nessus file?')
        sys.exit(1)
    else:
        print ('Found %i hosts' % (len(hosts)))

    #find the Task ID for uniqueness checking
    #test: is this unique per RUN..or per task?
    task_id = ""
    tmp_prefs = nessus_xml_data.findAll('preference')
    for pref in tmp_prefs:
        if "report_task_id" in str(pref):
            task_id = pref.value.get_text()

    #Lets see if the index already exists or not
    if not args.fake:
        ES_index_check (args)

    print ("Checking for results and posting to ElasticSearch. This might take a while...")
    for host in hosts:
        #lets iterate through the reportItem, here the compliance items will be
        reportItems = host.findAll('reportitem')
        for rItem in reportItems:
            host_info = ObjDict()
            host_info.agent = ObjDict()
            host_info.rule = ObjDict()
            host_info.data = ObjDict()
            host_info.manager = ObjDict()

            #TODO make configurable to OSSEC server
            host_info.manager.name = "debian"
            #lets get the host information
            #host_info.hostname = host['name']
            host_info.agent.ip = host.find('tag', attrs={'name': 'host-ip'}).get_text()
            #we got the IP...from here we need the agent.id 
            agent_id = get_id_from_keys(args,host_info.agent.ip)
            host_info.agent.id = agent_id
            if agent_id:
                #default fields to make wazuh work
                #host_info.rule.groups = "oscap, oscap-result"
                host_info.rule.groups = "oscap"
                host_info.location = "nessus_CIS-benchmark"                   
                timeoffset = int((time.localtime().tm_gmtoff)/3600)
                hostscanend = host.find('tag', attrs={'name': 'HOST_END'}).get_text()
                hostscanend = parse(hostscanend)
                hostscanend =  hostscanend - timedelta(hours=timeoffset)
                host_info["@timestamp"] = hostscanend.strftime("%Y-%m-%dT%H:%M:%S")

                #fqdn might be optional
                host_fqdn = host.find('tag', attrs={'name': 'host-fqdn'})
                host_info.predecoder =  ObjDict()
                if host_fqdn:
                    host_info.predecoder.hostname = host_fqdn.get_text()
                else:
                    host_info.predecoder.hostname = host_info.agent.ip

                #get all report findings info
                host_info.data.oscap = ObjDict()
                host_info.data.oscap.check = ObjDict()
                host_info.data.oscap.scan = ObjDict()
                host_info.data.oscap.check.oval = ObjDict()
                host_info.data.oscap.scan.benchmark = ObjDict()
                host_info.data.oscap.scan.profile = ObjDict()

                #a limitation of nessus is how severity is done in CIS benchmarking compared to oscap
                #a benchmark scan in NEssus is always a severity 3, 
                #a missing warning because of wrong OS is 2
                try:
                    severity = rItem['severity']
                    if severity == "0":
                        host_info.data.oscap.check.severity = "informational"
                        host_info.rule.level = 3
                    elif severity == "1":
                        print ("Severity 1 shouldn't happen with CIS benchmark scans!")
                        sys.exit(1)
#                       host_info.data.oscap.check.severity = "low"
#                       host_info.rule.level = 5
                    elif severity == "2": #warnings
                       host_info.data.oscap.check.severity = "low"
                       host_info.rule.level = 7
                    elif severity == "3":
                       host_info.data.oscap.check.severity = "medium"
                       host_info.rule.level = 10
                    else:
                        print ("unknown severity: %s" % (severity))
                        sys.exit(1)

                    host_info.data.oscap.scan.id = task_id
                    #these fields should always be present
                    host_info.data.oscap.check.oval.id = rItem['pluginid']
                    #host_info.data.oscap.scan.benchmark.id = rItem['pluginname'] #not needed for wazuh report screen
                    host_info.data.oscap.scan.profile.title = rItem['pluginname']

                    compliance_item = rItem.find('compliance')

                    #we're only interested in compliance items, really
                    if compliance_item:
                        #this stuff only around when its a compliance scan anyway

                        comaudit = rItem.find('cm:compliance-audit-file')
                        if comaudit:
                            #host_info.data.oscap.check.id =  comaudit.get_text()
                            #host_info.data.oscap.scan.profile.id =  comaudit.get_text()
                            host_info.data.oscap.scan.content = comaudit.get_text()
                        else:
                            #host_info.data.oscap.check.id =  None
                            #host_info.data.oscap.scan.profile.id =  None
                            host_info.data.oscap.scan.content = None

                        comcheck = rItem.find('cm:compliance-check-name')
                        if comcheck:
                            #host_info.data.oscap.check.description =  comcheck.get_text()
                            host_info.data.oscap.check.title = comcheck.get_text()
                        else:
                            #host_info.data.oscap.check.description =  comcheck.get_text()
                            host_info.data.oscap.check.title = comcheck.get_text()

                        cominfo = rItem.find('cm:compliance-info')
                        if cominfo:
                            host_info.data.oscap.check.rationale =  cominfo.get_text().replace("\n","")
                        else:
                           host_info.data.oscap.check.rationale = None


                        comref = rItem.find('cm:compliance-reference')
                        if comref:
                            host_info.data.oscap.check.references =  comref.get_text()
                        else:
                            host_info.data.oscap.check.references = None

                        comres = rItem.find('cm:compliance-result')
                        if comres:
                            complianceresult = comres.get_text()
                            if complianceresult == "PASSED":
                                host_info.data.oscap.check.result = "pass"
                            elif complianceresult == "FAILED":
                                host_info.data.oscap.check.result = "fail"
                            elif complianceresult == "WARNING":
                                host_info.data.oscap.check.result  = "informational"
                            else:
                                print ("unknown compliance result:")
                                print (complianceresult)
                                sys.exit(1)
                        else:
                            host_info.complianceresult = None

                        #both compliance and vuln scan
                        descrip = rItem.find('description')
                        if descrip:
                            host_info.full_log = descrip.get_text()
                        else:
                            host_info.full_log = None

                        #we have all data in host_info, why not send that instead?
                        #print ("Finding for %s complete, sending to ES" % (host_info.hostname))
                        json_data = host_info.dumps()
                        #print (json_data)
                        if not args.fake:
                            post_to_ES(json_data, args, task_id)
                            #sys.exit(1)
                except Exception as e:
                    print ("Error:")
                    print (e)
                    print (rItem)
                    sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(description = 'Push data into elasticsearch from a .nessus result file.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--input', help = 'Input file in .nessus format',
        default = None)
    parser.add_argument('-o', '--ossec', help = 'Ossec key file',
        default = '/var/ossec/etc/client.keys')
    parser.add_argument('-es', '--elasticsearchserver', help = 'elasticsearch server',
        default = '127.0.0.1')
    parser.add_argument('-ep', '--elasticsearchport', help = 'elasticsearch port',
        default = 9200)
    parser.add_argument('-ei','--elasticsearchindex', help='What index to post the report data to',
        default = 'wazuh-alerts-3.x')
    parser.add_argument('-t', '--type', help = 'What type of result to parse the file for.', choices = ['both', 'vulnerability','compliance' ],
        default = 'both')
    parser.add_argument('-f','--fake', help = 'Do everything but actually send data to elasticsearch', action = 'store_true')
    group.add_argument('-c', '--config', help = 'Config file for script to read settings from. Overwrites all other cli parameters', default = None)
    args = parser.parse_args()
    return args

#replace args from config file instead
def replace_args(args):
    if os.path.isfile(args.config):
        print ("Reading configuration from config file")
        Config = ConfigParser.ConfigParser()
        try:
            Config.read(args.config)
            args.input = Config.get("General","Input")
            args.type = Config.get("General","Type")
            args.fake = Config.getboolean("General","Fake")
            args.ossec = Config.get("General", "OSSEC")
            args.elasticsearchserver = Config.get("elasticsearch","elasticsearchServer")
            args.elasticsearchport = Config.getint("elasticsearch","elasticsearchPort")
        except IOError:
                print('could not read config file "' + args.config + '".')
                sys.exit(1)
    else:
        print('"' + args.config + '" is not a valid file.')
        sys.exit(1)
    return args

def main():
    args = parse_args()

    #do we have a config file instead of cli?
    if args.config:
        args = replace_args(args)

    #ok, if not
    if (not args.input) and (not args.nessusscanname):
        print('Need input file to export. Specify one in the configuation file,  with -i (file) or -rn (reportname)\n See -h for more info')
        sys.exit(1)

    if args.input:
        nessus_scan_file = args.input
    else:
        nessus_scan_file = args.nessustmp + "/" + args.nessusscanname
    print ("Nessus file to parse is %s" % (nessus_scan_file))

    # read the file..might be big though...
    with open(nessus_scan_file, 'r') as f:
        print ('Parsing file %s as xml into memory, hold on...' % (args.input))
        nessus_xml_data = BeautifulSoup(f.read(), 'lxml')

    parse_to_json(nessus_xml_data, args)

if __name__ == "__main__":
  main()
  print ("Done.")
