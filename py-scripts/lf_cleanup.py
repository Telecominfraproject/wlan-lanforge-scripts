#!/usr/bin/env python3
"""
NAME: lf_cleanup.py

PURPOSE: clean up stations, cross connects and endpoints

EXAMPLE:  ./lf_cleanup.py --mgr <lanforge ip>

Copyright 2021 Candela Technologies Inc
License: Free to distribute and modify. LANforge systems must be licensed.
"""
import sys
import os
import importlib
import argparse
import time

if sys.version_info[0] != 3:
    print("This script requires Python 3")
    exit(1)

sys.path.append(os.path.join(os.path.abspath(__file__ + "../../../")))

LFUtils = importlib.import_module("py-json.LANforge.LFUtils")
realm = importlib.import_module("py-json.realm")
Realm = realm.Realm


class lf_clean(Realm):
    def __init__(self,
                 host="localhost",
                 port=8080,
                 clean_cxs=None,
                 clean_endp=None,
                 clean_sta=None):
        super().__init__(lfclient_host=host,
                         lfclient_port=port),
        self.host = host
        self.port = port
        self.clean_cxs = clean_cxs
        self.clean_endp = clean_endp
        self.clean_sta = clean_sta
        self.cxs_done = False
        self.endp_done = False
        self.sta_done = False

    def cxs_clean(self):
        still_looking_cxs = True
        iterations_cxs = 1
        while still_looking_cxs and iterations_cxs <= 10:
            iterations_cxs += 1
            print("cxs_clean: iterations_cxs: {iterations_cxs}".format(iterations_cxs=iterations_cxs))
            cx_json = super().json_get("cx")
            if cx_json is not None:
                print("Removing old cross connects")
                for name in list(cx_json):
                    if name != 'handler' and name != 'uri' and name != 'empty':
                        print(name)
                        req_url = "cli-json/rm_cx"
                        data = {
                            "test_mgr": "default_tm",
                            "cx_name": name
                        }
                        super().json_post(req_url, data)
                        time.sleep(.5)
                time.sleep(1)
            else:
                print("No cross connects found to cleanup")
                still_looking_cxs = False
        print("clean_cxs still_looking_cxs {cxs_looking}".format(cxs_looking=still_looking_cxs))
        if not still_looking_cxs:
            self.cxs_done = True
        return still_looking_cxs

    def endp_clean(self):
        still_looking_endp = True
        iterations_endp = 0
        while still_looking_endp and iterations_endp <= 10:
            iterations_endp += 1
            print("endp_clean: iterations_endp: {iterations_endp}".format(iterations_endp=iterations_endp))
            # get and remove current endps
            endp_json = super().json_get("endp")
            if endp_json is not None:
                print("Removing old endpoints")
                for name in list(endp_json['endpoint']):
                    print(list(name)[0])
                    if name[list(name)[0]]["name"] == '':
                        continue
                    req_url = "cli-json/rm_endp"
                    data = {
                        "endp_name": list(name)[0]
                    }
                    print(data)
                    super().json_post(req_url, data)
                    time.sleep(.5)
                time.sleep(1)
            else:
                print("No endpoints found to cleanup")
                still_looking_endp = False
        print("clean_endp still_looking_endp {ednp_looking}".format(ednp_looking=still_looking_endp))
        if not still_looking_endp:
            self.endp_done = True
        return still_looking_endp

    def sta_clean(self):
        still_looking_sta = True
        iterations_sta = 0
        while still_looking_sta and iterations_sta <= 10:
            iterations_sta += 1
            print("sta_clean: iterations_sta: {iterations_sta}".format(iterations_sta=iterations_sta))
            try:
                sta_json = super().json_get(
                    "port/1/1/list?field=alias")['interfaces']
            except TypeError:
                sta_json = None

            # get and remove current stations
            if sta_json is not None:
                # print(sta_json)
                print("Removing old stations ")
                for name in list(sta_json):
                    for alias in list(name):
                        if 'sta' in alias:
                            print(alias)
                            info = self.name_to_eid(alias)
                            req_url = "cli-json/rm_vlan"
                            data = {
                                "shelf": info[0],
                                "resource": info[1],
                                "port": info[2]
                            }
                            # print(data)
                            super().json_post(req_url, data)
                            time.sleep(.5)
                        if 'wlan' in alias:
                            info = self.name_to_eid(alias)
                            req_url = "cli-json/rm_vlan"
                            data = {
                                "shelf": info[0],
                                "resource": info[1],
                                "port": info[2]
                            }
                            # print(data)
                            super().json_post(req_url, data)
                            time.sleep(.5)
                        if 'moni' in alias:
                            info = self.name_to_eid(alias)
                            req_url = "cli-json/rm_vlan"
                            data = {
                                "shelf": info[0],
                                "resource": info[1],
                                "port": info[2]
                            }
                            # print(data)
                            super().json_post(req_url, data)
                            time.sleep(.5)
                        if 'Unknown' in alias:
                            info = self.name_to_eid(alias)
                            req_url = "cli-json/rm_vlan"
                            data = {
                                "shelf": info[0],
                                "resource": info[1],
                                "port": info[2]
                            }
                            # print(data)
                            super().json_post(req_url, data)
                            time.sleep(.5)
                        if ('Unknown' not in alias) and ('wlan' not in alias) and ('sta' not in alias):
                            still_looking_sta = False
                time.sleep(1)

            else:
                print("No stations found to cleanup")
                still_looking_sta = False
        print("clean_sta still_looking_sta {sta_looking}".format(sta_looking=still_looking_sta))
        if not still_looking_sta:
            self.sta_done = True
        return still_looking_sta

    '''
        1: delete cx
        2: delete endp
        3: delete sta
        when deleting sta first, you will end up with phantom CX
    '''

    def cleanup(self):
        if self.clean_cxs:
            # also clean the endp when cleaning cxs
            still_looking_cxs = self.cxs_clean()
            still_looking_endp = self.endp_clean()
            print("clean_cxs: still_looking_cxs {looking_cxs} still_looking_endp {looking_endp}".format(
                looking_cxs=still_looking_cxs, looking_endp=still_looking_endp))
        if self.clean_endp and not self.clean_cxs:
            still_looking_endp = self.endp_clean()
            print("clean_endp: still_looking_endp {looking_endp}".format(looking_endp=still_looking_endp))

        if self.clean_sta:
            still_looking_sta = self.sta_clean()
            print("clean_sta: still_looking_sta {looking_sta}".format(looking_sta=still_looking_sta))


def main():

    parser = argparse.ArgumentParser(
        prog='lf_cleanup.py',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''\
            Clean up cxs and endpoints
            ''',
        description='''\
lf_cleanup.py:
--------------------
Generic command layout:

python3 ./lf_clean.py --mgr MGR

    default port is 8080

    clean up stations, cxs and enspoints.
    NOTE: will only cleanup what is present in the GUI
            So will need to iterate multiple times with script
            ''')
    parser.add_argument(
        '--mgr',
        '--lfmgr',
        help='--mgr <hostname for where LANforge GUI is running>',
        default='localhost')
    parser.add_argument(
        '--cxs',
        help="--cxs, this will clear all the endps and cxs",
        action='store_true')
    parser.add_argument(
        '--endp',
        help="--endp, this will clear all the endps",
        action='store_true')
    parser.add_argument(
        '--sta',
        help="--sta, this will clear all the stations",
        action='store_true')

    args = parser.parse_args()
    if args.cxs or args.endp or args.sta:
        clean = lf_clean(host=args.mgr, clean_cxs=args.cxs, clean_endp=args.endp, clean_sta=args.sta)
        print("cleaning cxs: {cxs} endpoints: {endp} stations: {sta} start".format(cxs=args.cxs, endp=args.endp, sta=args.sta))
        if args.cxs:
            print("cleaning cxs will also clean endp")
            clean.cxs_clean()
            clean.endp_clean()
        if args.endp and not args.cxs:
            clean.endp_clean()
        if args.sta:
            clean.sta_clean()
        print("Clean done")
        # print("Clean  cxs_done {cxs_done} endp_done {endp_done} sta_done {sta_done}"
        #    .format(cxs_done=clean.cxs_done,endp_done=clean.endp_done,sta_done=clean.sta_done))
    else:
        print("please add option of --cxs ,--endp, or --sta to clean")


if __name__ == "__main__":
    main()
