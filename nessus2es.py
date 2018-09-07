#This takes as input a .nessus scan file with either vulnerability or compliance info (or both)
#and dumps the data into elasticsearc
#
#autor: @Ar0xA / ar0xa@tldr.nu

from bs4 import BeautifulSoup

import argparse
import sys
import os
import io
import json
import ConfigParser

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from objdict import ObjDict
from dateutil.parser import parse

#check if index exists
def ES_index_check (args,task_id):
  #what index to we need to post to?
  #can we reach the server?
  es_server =  args.elasticsearchserver
  es_port = args.elasticsearchport
  es_index = args.elasticsearchindex
  es_url = "http://" + es_server + ":" + str(es_port) + "/"

  #construct indexname
  es_index = es_index + "-" + task_id

  #test if index esists
  http = urllib3.PoolManager()
  r = http.request('HEAD', es_url+es_index)

  #if index exists, there's already data from this task_id in ES. Quit
  #if index DOES NOT exist, create it.
  if r.status == 404:
      print "Index \"%s\" does not exist. Creating it" % (es_index)
      r = http.request('PUT', es_url +es_index)
      if r.status == 200:
          print "Index %s created" % (es_index)
      else:
          print "Creating index failed. I give up"
          sys.exit(1)
  elif r.status == 200:
      print "Index already exists. Not inserting same data into this index unless you override"
      print "TODO: create override"
      sys.exit(1)
  elif not r.status == 200:
      print "Something is wrong with the index, but i have no idea what. I give up!"
      print r.status
      sys.exit(1)

#post data to elastic
def post_to_ES(json_data,args, task_id):
  #what index to we need to post to?
  #can we reach the server?
  es_server =  args.elasticsearchserver
  es_port = args.elasticsearchport
  es_index = args.elasticsearchindex
  es_url = "http://" + es_server + ":" + str(es_port) + "/"

  #construct indexname
  es_index = es_index + "-" + task_id
  http = urllib3.PoolManager()

  #index exists, lets post the data #yolo
  r = http.request('POST', es_url+es_index+"/vulnresult", headers={'Content-Type':'application/json'}, body=json_data)
  if not r.status  == 201:
    print "well, something went wrong, thats embarrasing"
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
        print 'Didn\'t find report name in file. is this a valid nessus file?'
        sys.exit(1)
    else:
        data.scanname = tmp_scanname

    #policyused
    data.scanpolicy = nessus_xml_data.policyname.get_text()

    # see if there are any hosts that are reported on
    hosts = nessus_xml_data.findAll('reporthost')
    if len(hosts) == 0:
        print 'Didn\'t find any hosts in file. Is this a valid nessus file?'
        sys.exit(1)
    else:
        print 'Found %i hosts' % (len(hosts))

    #find the Task ID for uniqueness checking
    #test: is this unique per RUN..or per task?
    task_id = ""
    tmp_prefs = nessus_xml_data.findAll('preference')
    for pref in tmp_prefs:
        if "report_task_id" in str(pref):
            task_id = pref.value.get_text()

    #ok we got the task ID; to be sure before anything else, lets see if the index already exists or not
    ES_index_check (args, task_id)

    print "Checking for results and posting to ElasticSearch. This might take a while..."
    for host in hosts:
        #lets iterate through the reportItem, here the compliance items will be
        reportItems = host.findAll('reportitem')
        for rItem in reportItems:
            host_info = ObjDict()
            #host_info.reportfindings = []

            #lets get the host information
            host_info.hostname = host['name']

            host_info.hostip = host.find('tag', attrs={'name': 'host-ip'}).get_text()

            macaddress = host.find('tag', attrs={'name': 'mac-address'})
            if macaddress:
                host_info.hostmacaddress = macaddress.get_text()
            else:
                host_info.hostmacaddress = None

            credscan = host.find('tag', attrs={'name': 'Credentialed_Scan'})
            if credscan:
                 host_info.credentialedscan = credscan.get_text()
            else:
                host_info.credentialedscan = None

            host_info.hostscanstart = host.find('tag', attrs={'name': 'HOST_START'}).get_text()
            #convert to normal date format
            host_info.hostscanstart = parse(host_info.hostscanstart)
            host_info.hostscanend = host.find('tag', attrs={'name': 'HOST_END'}).get_text()
            host_info.hostscanend = parse(host_info.hostscanend)

            host_info["@timestamp"] = host_info.hostscanend

            #fqdn might be optional
            host_fqdn = host.find('tag', attrs={'name': 'host-fqdn'})
            if host_fqdn:
                host_info.hostfqdn = host_fqdn.get_text()
            else:
                host_info.hostfqdn = None

            #get all report findings info
            try:
                #these fields should always be present
                host_info.severity = rItem['severity']
                host_info.port = rItem['port']
                host_info.svc_name = rItem['svc_name']
                host_info.protocol = rItem['protocol']
                host_info.pluginid = rItem['pluginid']
                host_info.pluginname = rItem['pluginname']
                host_info.plugintype = rItem.find('plugin_type').get_text()
                host_info.pluginfamily = rItem['pluginfamily']
                host_info.riskfactor = rItem.find('risk_factor').get_text()
                agent = rItem.find('agent')
                if agent:
                    host_info.agent = agent.get_text()
                else:
                    host_info.agent = None

                compliance_item = rItem.find('compliance')
                if compliance_item:
                    host_info.compliance = True
                else:
                    host_info.compliance = False

                #this stuff only around when its a compliance scan anyway
                host_info.compliancecheckname = None
                host_info.complianceauditfile = None
                host_info.complianceinfo = None
                host_info.complianceresult = None
                host_info.compliancereference = None
                host_info.complianceseealso = None
                if host_info.compliance:
                    host_info.complianceauditfile = rItem.find('cm:compliance-audit-file').get_text()
                    host_info.compliancecheckname = rItem.find('cm:compliance-check-name').get_text()
                    host_info.complianceinfo = rItem.find('cm:compliance-info').get_text()
                    host_info.complianceresult = rItem.find('cm:compliance-result').get_text()
                    host_info.compliancereference = rItem.find('cm:compliance-reference').get_text()
                    host_info.complianceseealso = rItem.find('cm:compliance-see-also').get_text()

                descrip = rItem.find('description')
                if descrip:
                    host_info.description = descrip.get_text()
                else:
                    host_info.description = None

                synop = rItem.find('synopsis')
                if synop:
                    host_info.synopsis = synop.get_text()
                else:
                    host_info.synopsis = None

                solut = rItem.find('solution')
                if solut:
                    host_info.solution = solut.get_text()
                else:
                    host_info.solution = None

                plugin_output = rItem.find('plugin_output')
                if plugin_output:
                    host_info.pluginoutput = plugin_output.get_text()
                else:
                    host_info.pluginoutput = None

                expl_avail = rItem.find('exploit_available')
                if expl_avail:
                    host_info.exploitavailable = expl_avail.get_text()
                else:
                    host_info.exploitavailable = None

                expl_ease = rItem.find('exploitability_ease')
                if expl_ease:
                      host_info.exploitabilityease = expl_ease.get_text()
                else:
                      host_info.exploitabilityease = None

                cvss = rItem.find('cvss_base_score')
                if cvss:
                    host_info.cvssbasescore = cvss.get_text()
                else:
                    host_info.cvssbasescore = None

                cvss3 = rItem.find('cvss3_base_score')
                if cvss3:
                    host_info.cvss3basescore = cvss3.get_text()
                else:
                    host_info.cvss3basescore = None

                ppdate = rItem.find('patch_publication_date')
                if ppdate:
                    host_info.patchpublicationdate = parse(ppdate.get_text())
                else:
                    host_info.patchpublicationdate = None

                #these items can be none, one or many if found
                host_info.cve = []
                host_info.osvdb = []
                host_info.rhsa = []
                host_info.xref = []

                allcve = rItem.findAll('cve')
                if allcve:
                    for cve in allcve:
                        host_info.cve.append(cve.get_text())

                allosvdb = rItem.findAll('osvdb')
                if allosvdb:
                    for osvdb in allosvdb:
                        host_info.osvdb.append(osvdb.get_text())


                allrhsa = rItem.findAll('rhsa')
                if allrhsa:
                    for rhsa in allrhsa:
                        host_info.rhsa.append(rhsa.get_text())

                allxref = rItem.findAll('xref')
                if allxref:
                    for xref in allxref:
                        host_info.xref.append(xref.get_text())

                #we have all data in host_info, why not send that instead?
                #print "Finding for %s complete, sending to ES" % (host_info.hostname)
                json_data = host_info.dumps()
                print json_data
                post_to_ES(json_data, args, task_id)
            except Exception as e:
                print "Error:"
                print e
                print rItem
                sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(description = 'Push data into elasticsearch from a .nessus result file.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--input', help = 'Input file in .nessus format',
        default = None)
    parser.add_argument('-es', '--elasticsearchserver', help = 'elasticsearch server',
        default = '127.0.0.1')
    parser.add_argument('-ep', '--elasticsearchport', help = 'elasticsearch port',
        default = 9200)
    parser.add_argument('-ei','--elasticsearchindex', help='What index to post the report data to',
        default = 'nessusdata')
    parser.add_argument('-t', '--type', help = 'What type of result to parse the file for.', choices = ['both', 'vulnerability','compliance' ],
        default = 'both')
    parser.add_argument('-f','--fake', help = 'Do everything but actually send data to elasticsearch', action = 'store_true')
    group.add_argument('-c', '--config', help = 'Config file for script to read settings from. Overwrites all other cli parameters', default = None)
    args = parser.parse_args()
    return args

#replace args from config file instead
def replace_args(args):
    if os.path.isfile(args.config):
        print "Reading configuration from config file"
        Config = ConfigParser.ConfigParser()
        try:
            Config.read(args.config)
            args.input = Config.get("General","Input")
            args.type = Config.get("General","Type")
            args.fake = Config.getboolean("General","Fake")
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
    print "Nessus file to parse is %s" % (nessus_scan_file)

    # read the file..might be big though...
    with open(nessus_scan_file, 'r') as f:
        print 'Parsing file %s as xml into memory, hold on...' % (args.input)
        nessus_xml_data = BeautifulSoup(f.read(), 'lxml')

    parse_to_json(nessus_xml_data, args)

if __name__ == "__main__":
  main()
  print "Done."
