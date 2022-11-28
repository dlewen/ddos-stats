#!/usr/bin/env python3
import sys
import sqlite3, csv
import requests
import urllib.parse
import json
import pprint
import datetime
import configparser
import argparse
import re

class db():
    def __init__(self,dbfile):
        try:
            self.con = sqlite3.connect(dbfile)
        except sqlite3.Error as e:
            print("Error %s:" % e.args[0])
            sys.exit(1)

class Alerts():
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read(args.config)
        self.db = db(self.config['db']['filename'])
        self.init_db()
        self.apiurl = self.config['api']['url']
        self.apitoken = self.config['api']['apitoken']
        self.cafile = self.config['api']['cafile']
        self.ca_verify = self.config['api'].getboolean('ca_verify')
        self.init_request()


    def init_db(self):
        cur = self.db.con.cursor()
        for row in cur.execute('select name from sqlite_master where type="table";'):
            if row[0] == 'alerts':
                return
        cur.execute("CREATE TABLE alerts(id INT, start_time INT, stop_time INT, bps INT, pps INT, ip TEXT)")
        cur.close()
        self.db.con.commit()

    def init_request(self):
        self.session = requests.Session()
        self.session.headers.update({'X-Arbux-APIToken': self.apitoken})
        if self.ca_verify == False:
            self.session.verify = False
        elif self.cafile:
            self.session.verify = self.cafile

    def totimestamp(self,strt):
        return int(datetime.datetime.strptime(strt,'%Y-%m-%dT%H:%M:%S%z').timestamp())

    def fromtimestamp(self,it):
        return datetime.datetime.utcfromtimestamp(it).strftime('%Y-%m-%dT%H:%M:%S')

    def parse(self,alert):
        ret={}
        ret['id'] = alert['id']
        ret['start_time'] = self.totimestamp(alert['attributes']['start_time'])
        if 'stop_time' in alert['attributes']:
            ret['stop_time'] = self.totimestamp(alert['attributes']['stop_time'])
        else:
            ret['stop_time'] = ret['start_time']
        ret['ip'] = alert['attributes']['subobject']['host_address']
        if 'impact_bps' in alert['attributes']['subobject']:
            ret['bps'] = alert['attributes']['subobject']['impact_bps']
        else:
            ret['bps'] = 0
        if 'impact_pps' in alert['attributes']['subobject']:
            ret['pps'] = alert['attributes']['subobject']['impact_pps']
        else:
            ret['pps'] = 0
        return ret

    def findduplicates(self,alert):
        cur = self.db.con.cursor()
        query = "SELECT id,start_time,stop_time,bps,pps from alerts where ip == :ip and ((:start <= start_time and :stop >= start_time) or (:start >= start_time and :stop <= stop_time) or (:start <= start_time and :stop >= stop_time) or (:start <= stop_time and :stop >= stop_time))"
        cur.execute(query, {'ip': alert['ip'],'start':alert['start_time'],'stop':alert['stop_time']})
        return cur.fetchall()

    def addtodb(self,alert):
        cur = self.db.con.cursor()
        query = "INSERT into alerts (id,start_time,stop_time,bps,pps,ip) VALUES(:id,:start_time,:stop_time,:bps,:pps,:ip)"
        cur.execute(query,alert)
        cur.close()

    def deduplicate(self,alert,dups):
        update = False
        u= {}
        for row in dups:
            u['id'] = row[0]
            u['start_time'] = row[1]
            u['stop_time'] = row[2]
            u['bps'] = row[3]
            u['pps'] = row[4]
            if alert['start_time'] < u['start_time']:
                update = True
                u['start_time'] = alert['start_time']
            if alert['stop_time'] > u['stop_time']:
                update = True
                u['stop_time'] = alert['stop_time']
            if alert['bps'] > u['bps']:
                u['bps'] = alert['bps']
            if alert['pps'] > u['pps']:
                u['pps'] = alert['pps']
        if update:
            cur = self.db.con.cursor()
            query = "UPDATE alerts set start_time= :start_time, stop_time = :stop_time, bps = :bps, pps = :pps where id = :id"
            cur.execute(query,u)
            cur.close()

    def getlasttimestamp(self):
        cur = self.db.con.cursor()
        q = "select start_time from alerts order by start_time DESC limit 1"
        cur.execute(q)
        res = cur.fetchall()
        if res:
            return self.fromtimestamp(res[0][0])

    def progress(self,links):
        cpage = str(urllib.parse.parse_qs(links['self'])['page'][0])
        if 'last' in links:
            lpage = str(urllib.parse.parse_qs(links['last'])['page'][0])
            return f"Fetching page {cpage} of {lpage}"

    def fetch(self):
        lasttimestamp = self.getlasttimestamp()
        if not lasttimestamp:
            lasttimestamp = self.config['api']['firstfetchdate']

        resnext = f"{self.apiurl}/api/sp/alerts/?filter=/data/attributes/alert_class=dos+AND+/data/attributes/importance=2+AND+/data/attributes/start_time>{lasttimestamp}"
        resself = "1"
        reslast = "2"
        while True:
            if resself != reslast:
                if args.verbose:
                    pp.pprint(resnext)
                response = self.session.get(resnext)
                links = response.json()['links']
                print(self.progress(links))
                resself = links['self']
                if 'last' in links:
                    reslast = links['last']
                else:
                    reslast = resself
                if 'next' in links:
                    resnext = links['next']
            for alert in response.json()['data']:
                id = alert['id']
                if alert['attributes']['alert_type']=='dos_host_detection':
                    a = self.parse(alert)
                    f = self.findduplicates(a)
                    if f:
                        self.deduplicate(a,f)
                        if args.verbose:
                            print("duplicates")
                            print(f)
                    else:
                        if args.verbose:
                            print(a)
                        self.addtodb(a)
            if resself == reslast:
                break
        self.db.con.commit()

    def topow(self,rate):
        m = re.match("([0-9]+)([a-zA-z]+)",rate)
        q = int(m.group(1))
        unit = m.group(2)
        bpsunits = {'bps':1,'Kbps':3,'Mbps':6,'Gbps':9,'Tbps':12,'Pbps':15}
        ppsunits = {'pps':1,'Kpps':3,'Mpps':6,'Gpps':9,'Tpps':12,'Ppps':15}
        if unit in bpsunits:
            value=q*pow(10,bpsunits[unit])
            unit = 'bps'
        elif unit in ppsunits:
            value=q*pow(10,ppsunits[unit])
            unit = 'pps'
        return unit,value

    def statssql(self,rates,interval,limit):
        cur = self.db.con.cursor()
        if interval == 'monthly':
            intervalsql = "'start of month'"
            limitsql = f"{intervalsql},'-{limit} month'"
        elif interval == 'weekly':
            intervalsql = "'weekday 1','-7 day'"
            limitsql = f"'-{limit*7} day'"
        elif interval == 'dayly':
            intervalsql = 'start of day'
            limitsql = f"'-{limit} day"
        numrates = len(rates)
        q = "SELECT am.month"
        for idx,trate in enumerate(rates):
            q+= f",IFNULL(a{idx}.count,0)"
        q+= f" FROM (SELECT count() as count,date(datetime(start_time,'unixepoch'),{intervalsql}) as month from alerts"
        q+= f" where datetime(start_time,'unixepoch') > datetime(date(),{limitsql}) GROUP BY month) as am"
        for idx,trate in enumerate(rates):
            unit,rate = self.topow(trate)
            q+=" LEFT JOIN "
            q+= f"(SELECT count() as count,date(datetime(start_time,'unixepoch'),{intervalsql}) as month from alerts"
            q+= f" where pps > 0 AND {unit} > {rate}"
            if idx < numrates-1:
                q+= f" AND {unit} < {self.topow(rates[idx+1])[1]}"
            else:
                igu,igv=self.topow(self.config[unit]['ignoreabove'])
                q+= f" AND {unit} < {igv}"
            q+= f" AND datetime(start_time,'unixepoch') > datetime(date(),{limitsql})"
            q+= f" GROUP BY month) as a{idx}"
            q+= f" ON am.month = a{idx}.month"
        if args.verbose:
            print(q)
        cur.execute(q)
        return cur.fetchall()

    def makestats(self,interval,limit):
        bpslevels = json.loads(self.config['bps']['levels'])
        ppslevels = json.loads(self.config['pps']['levels'])
        bpsstats = self.statssql(bpslevels,interval,limit)
        ppsstats = self.statssql(ppslevels,interval,limit)
        csvout = open(args.outfile[0],'w')
        writer = csv.writer(csvout,delimiter=';')
        writer.writerow(['Startdate']+bpslevels+ppslevels)
        for row in bpsstats:
            combined = row + ppsstats.pop(0)[1:]
            writer.writerow(combined)
        

global pp
pp = pprint.PrettyPrinter(indent=4)

parser = argparse.ArgumentParser()
parser.add_argument('--update', help='Fetch alerts and store in local DB', action='store_true')
parser.add_argument('--monthly', nargs='?', type=int, const=12, metavar='N', help='Show monthly stastitics for N last months')
parser.add_argument('--weekly', nargs='?', type=int, const=10, metavar='N', help='Show weekly stastitics for N last weeks')
parser.add_argument('-o','--outfile',nargs=1,help='File to output csv to')
parser.add_argument('--verbose',help='Print debug info',action='store_true')
parser.add_argument('-c','--config',help='Configuration file',default='config.ini')

if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    sys.exit(1)

args = parser.parse_args()

alerts = Alerts()

if args.update == True:
    alerts.fetch()
if args.weekly != None:
    alerts.makestats('weekly',args.weekly)
elif args.monthly != None:
    alerts.makestats('monthly',args.monthly)


