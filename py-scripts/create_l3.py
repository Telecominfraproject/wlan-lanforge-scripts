#!/usr/bin/env python3

"""
    This script will create a variable number of stations each with their own set of cross-connects and endpoints.
    It will then create layer 3 traffic over a specified amount of time, testing for increased traffic at regular intervals.
    This test will pass if all stations increase traffic over the full test duration.

    Use './test_ipv4_variable_time.py --help' to see command line usage and options
"""

import sys
import os

if sys.version_info[0] != 3:
    print("This script requires Python 3")
    exit(1)

if 'py-json' not in sys.path:
    sys.path.append(os.path.join(os.path.abspath('..'), 'py-json'))

import argparse
from LANforge.lfcli_base import LFCliBase
from LANforge import LFUtils
from realm import Realm
import time
import datetime
from realm import TestGroupProfile

class CreateL3(Realm):
    def __init__(self,
                 ssid, security, password, sta_list, name_prefix, upstream, radio,
                 host="localhost", port=8080, mode = 0, ap=None,
                 side_a_min_rate=56, side_a_max_rate=0,
                 side_b_min_rate=56, side_b_max_rate=0,
                 number_template="00000",  use_ht160=False,
                 _debug_on=False,
                 _exit_on_error=False,
                 _exit_on_fail=False):
        super().__init__(host, port)
        self.upstream = upstream
        self.host = host
        self.port = port
        self.ssid = ssid
        self.sta_list = sta_list
        self.security = security
        self.password = password
        self.radio = radio
        self.mode= mode
        self.ap=ap
        self.number_template = number_template
        self.debug = _debug_on
        self.name_prefix = name_prefix
        self.station_profile = self.new_station_profile()
        self.cx_profile = self.new_l3_cx_profile()
        self.station_profile.lfclient_url = self.lfclient_url
        self.station_profile.ssid = self.ssid
        self.station_profile.ssid_pass = self.password
        self.station_profile.security = self.security
        self.station_profile.number_template_ = self.number_template
        self.station_profile.debug = self.debug
        self.station_profile.use_ht160 = use_ht160
        if self.station_profile.use_ht160:
            self.station_profile.mode = 9
        self.station_profile.mode = mode
        if self.ap is not None:
            self.station_profile.set_command_param("add_sta", "ap",self.ap)
        #self.station_list= LFUtils.portNameSeries(prefix_="sta", start_id_=0, end_id_=2, padding_number_=10000, radio='wiphy0') #Make radio a user defined variable from terminal.


        self.cx_profile.host = self.host
        self.cx_profile.port = self.port
        self.cx_profile.name_prefix = self.name_prefix
        self.cx_profile.side_a_min_bps = side_a_min_rate
        self.cx_profile.side_a_max_bps = side_a_max_rate
        self.cx_profile.side_b_min_bps = side_b_min_rate
        self.cx_profile.side_b_max_bps = side_b_max_rate


    def __get_rx_values(self):
        cx_list = self.json_get("endp?fields=name,rx+bytes", debug_=self.debug)
        if self.debug:
            print(self.cx_profile.created_cx.values())
            print("==============\n", cx_list, "\n==============")
        cx_rx_map = {}
        for cx_name in cx_list['endpoint']:
            if cx_name != 'uri' and cx_name != 'handler':
                for item, value in cx_name.items():
                    for value_name, value_rx in value.items():
                      if value_name == 'rx bytes' and item in self.cx_profile.created_cx.values():
                        cx_rx_map[item] = value_rx
        return cx_rx_map

    def start(self, print_pass=False, print_fail=False):
        self.station_profile.admin_up()
        temp_stas = self.station_profile.station_names.copy()

        if self.wait_for_ip(temp_stas):
            self._pass("All stations got IPs")
        else:
            self._fail("Stations failed to get IPs")
            self.exit_fail()
        self.cx_profile.start_cx()


    def stop(self):
        self.cx_profile.stop_cx()
        self.station_profile.admin_down()

    def pre_cleanup(self):
        self.cx_profile.cleanup_prefix()
        for sta in self.sta_list:
            self.rm_port(sta, check_exists=True)

    def cleanup(self):
        self.cx_profile.cleanup()
        self.station_profile.cleanup()
        LFUtils.wait_until_ports_disappear(base_url=self.lfclient_url,
                                            port_list=self.station_profile.station_names,
                                            debug=self.debug)

    def build(self):

        self.station_profile.use_security(self.security,
                                            self.ssid,
                                            self.password)
        self.station_profile.set_number_template(self.number_template)
        print("Creating stations")
        self.station_profile.set_command_flag("add_sta", "create_admin_down", 1)
        self.station_profile.set_command_param("set_port", "report_timer", 1500)
        self.station_profile.set_command_flag("set_port", "rpt_timer", 1)
        self.station_profile.create(radio=self.radio,
                                    sta_names_=self.sta_list,
                                    debug=self.debug)
        self.cx_profile.create(endp_type="lf_udp",
                                side_a=self.station_profile.station_names,
                                side_b=self.upstream,
                                sleep_time=0)
        self._pass("PASS: Station build finished")

def main():
    parser = LFCliBase.create_basic_argparse(
        prog='create_l3.py',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''\
            Create stations to test connection and traffic on VAPs of varying security types (WEP, WPA, WPA2, WPA3, Open)
            ''',

        description='''\
test_ipv4_variable_time.py:
--------------------
Generic command layout:

python3 ./test_ipv4_variable_time.py
    --upstream_port eth1
    --radio wiphy0
    --num_stations 32
    --security {open|wep|wpa|wpa2|wpa3} \\
    --mode   1
        {"auto"   : "0",
        "a"      : "1",
        "b"      : "2",
        "g"      : "3",
        "abg"    : "4",
        "abgn"   : "5",
        "bgn"    : "6",
        "bg"     : "7",
        "abgnAC" : "8",
        "anAC"   : "9",
        "an"     : "10",
        "bgnAC"  : "11",
        "abgnAX" : "12",
        "bgnAX"  : "13",
    --ssid netgear
    --password admin123
    --a_min 1000
    --b_min 1000
    --ap "00:0e:8e:78:e1:76"
    --debug
            ''')

    required_args=None
    for group in parser._action_groups:
        if group.title == "required arguments":
            required_args=group
            break;
    if required_args is not None:
        required_args.add_argument('--a_min', help='--a_min bps rate minimum for side_a', default=256000)
        required_args.add_argument('--b_min', help='--b_min bps rate minimum for side_b', default=256000)

    optional_args=None
    for group in parser._action_groups:
        if group.title == "optional arguments":
            optional_args=group
            break;
    if optional_args is not None:
        optional_args.add_argument('--mode',help='Used to force mode of stations')
        optional_args.add_argument('--ap',help='Used to force a connection to a particular AP')
    args = parser.parse_args()

    num_sta = 2
    if (args.num_stations is not None) and (int(args.num_stations) > 0):
        num_sta = int(args.num_stations)

    station_list = LFUtils.portNameSeries(prefix_="sta", start_id_=0, end_id_=num_sta-1, padding_number_=10000, radio=args.radio)
    ip_var_test = CreateL3(host=args.mgr,
                                   port=args.mgr_port,
                                   number_template="0000",
                                   sta_list=station_list,
                                   name_prefix="VT",
                                   upstream=args.upstream_port,
                                   ssid=args.ssid,
                                   password=args.passwd,
                                   radio=args.radio,
                                   security=args.security,
                                   use_ht160=False,
                                   side_a_min_rate=args.a_min,
                                   side_b_min_rate=args.b_min,
                                   mode=args.mode,
                                   ap=args.ap,
                                   _debug_on=args.debug)

    ip_var_test.pre_cleanup()
    ip_var_test.build()
    if not ip_var_test.passes():
        print(ip_var_test.get_fail_message())
        ip_var_test.exit_fail()


if __name__ == "__main__":
    main()
