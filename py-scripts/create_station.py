#!/usr/bin/env python3

"""
    Script for creating a variable number of stations.
"""

import sys
import os
import argparse

if sys.version_info[0] != 3:
    print("This script requires Python 3")
    exit(1)

if 'py-json' not in sys.path:
    sys.path.append(os.path.join(os.path.abspath('..'), 'py-json'))
from LANforge.lfcli_base import LFCliBase
from LANforge import LFUtils
from realm import Realm
import time
import pprint


class CreateStation(Realm):
    def __init__(self,
                 _ssid=None,
                 _security=None,
                 _password=None,
                 _host=None,
                 _port=None,
                 _sta_list=None,
                 _number_template="00000",
                 _radio="wiphy0",
                 _proxy_str=None,
                 _debug_on=False,
                 _up=True,
                 _exit_on_error=False,
                 _exit_on_fail=False):
        super().__init__(_host,
                         _port)
        self.host = _host
        self.port = _port
        self.ssid = _ssid
        self.security = _security
        self.password = _password
        self.sta_list = _sta_list
        self.radio = _radio
        self.timeout = 120
        self.number_template = _number_template
        self.debug = _debug_on
        self.up = _up
        self.station_profile = self.new_station_profile()
        self.station_profile.lfclient_url = self.lfclient_url
        self.station_profile.ssid = self.ssid
        self.station_profile.ssid_pass = self.password,
        self.station_profile.security = self.security
        self.station_profile.number_template_ = self.number_template
        self.station_profile.mode = 0
        if self.debug:
            print("----- Station List ----- ----- ----- ----- ----- ----- \n")
            pprint.pprint(self.sta_list)
            print("---- ~Station List ----- ----- ----- ----- ----- ----- \n")


    def build(self):
        # Build stations
        self.station_profile.use_security(self.security, self.ssid, self.password)
        self.station_profile.set_number_template(self.number_template)

        print("Creating stations")
        self.station_profile.set_command_flag("add_sta", "create_admin_down", 1)
        self.station_profile.set_command_param("set_port", "report_timer", 1500)
        self.station_profile.set_command_flag("set_port", "rpt_timer", 1)
        self.station_profile.create(radio=self.radio, sta_names_=self.sta_list, debug=self.debug)
        if self.up:
            self.station_profile.admin_up()

        self._pass("PASS: Station build finished")


def main():
    parser = LFCliBase.create_basic_argparse(
        prog='create_station.py',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''\
         Create stations
            ''',

        description='''\
        create_station.py
--------------------
Command example:
./create_station.py
    --upstream_port eth1
    --radio wiphy0
    --num_stations 3
    --security open
    --ssid netgear
    --passwd BLANK
    --debug
            ''')
    required = parser.add_argument_group('required arguments')
    #required.add_argument('--security', help='WiFi Security protocol: < open | wep | wpa | wpa2 | wpa3 >', required=True)

    args = parser.parse_args()
    #if args.debug:
    #    pprint.pprint(args)
    #    time.sleep(5)
    if (args.radio is None):
       raise ValueError("--radio required")

    num_sta = 2
    if (args.num_stations is not None) and (int(args.num_stations) > 0):
        num_stations_converted = int(args.num_stations)
        num_sta = num_stations_converted

    station_list = LFUtils.port_name_series(prefix="sta",
                           start_id=0,
                           end_id=num_sta-1,
                           padding_number=10000,
                           radio=args.radio)

    create_station = CreateStation(_host=args.mgr,
                       _port=args.mgr_port,
                       _ssid=args.ssid,
                       _password=args.passwd,
                       _security=args.security,
                       _sta_list=station_list,
                       _radio=args.radio,
                       _proxy_str=args.proxy,
                       _debug_on=args.debug)

    create_station.build()

if __name__ == "__main__":
    main()
