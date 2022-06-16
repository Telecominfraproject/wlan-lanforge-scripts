#!/usr/bin/env python3

"""
NAME: lf_multipsk.py

PURPOSE:
        to test the multipsk feature in access point. Multipsk feature states connecting clients using same ssid but different passwords ,
        here we will create two or 3 passwords with different vlan id on single ssid and try to connect client with different passwords.

DESCRIPTION:
            The script will follow basic functionality as:-
            1- create station on input parameters provided
            2- the input parameters consist of dictionary of passwords,upstream,mac address, number of clients and radio as input
            3- will create layer3 cx for tcp and udp
            3- verify layer3 cx
            4- verify the ip for each station is comming from respective vlan id or not.
example :-
         python3 lf_multipsk.py --mgr localhost  --mgr_port 8802  --ssid "MDU Wi-Fi"  --security wpa2

INCLUDE_IN_README
    -Nikita Yadav
    Copyright 2021 Candela Technologies Inc
    License: Free to distribute and modify. LANforge systems must be licensed.
"""
import sys
import os
import importlib
import argparse
import time
import allure
from tabulate import tabulate

if sys.version_info[0] != 3:
    print("This script requires Python 3")
    exit(1)

sys.path.append(os.path.join(os.path.abspath(__file__ + "../../../")))

lfcli_base = importlib.import_module("py-json.LANforge.lfcli_base")
LFCliBase = lfcli_base.LFCliBase
LFUtils = importlib.import_module("py-json.LANforge.LFUtils")
realm = importlib.import_module("py-json.realm")
Realm = realm.Realm


class MultiPsk(Realm):
    def __init__(self,
                 host=None,
                 port=8080,
                 ssid=None,
                 input=None,
                 security=None,
                 passwd=None,
                 radio=None,
                 num_sta=None,
                 start_id=0,
                 resource=1,
                 upstream_resource=1,
                 sta_prefix="sta",
                 debug_=False,
                 ):
        super().__init__(lfclient_host=host,
                         lfclient_port=port),
        self.lfclient_host = host
        self.lfclient_port = port
        self.ssid = ssid
        self.input = input
        self.security = security
        self.passwd = passwd
        self.radio = radio
        self.num_sta = num_sta
        self.start_id = start_id
        self.resource = resource
        self.sta_prefix = sta_prefix
        self.debug = debug_
        self.station_profile = self.new_station_profile()
        self.upstream_resource = upstream_resource

    def build(self):
        station_list = []
        data_table = ""
        dict_table = {}
        for idex, input in enumerate(self.input):
            # print(input)
            if "." in input['upstream']:
                num = input['upstream'].split('.')[1]
                sta_name = "1." + str(self.resource) + ".sta" + str(num)
                # print(sta_name)
                station_list.append(sta_name)
            else:
                station_list = LFUtils.portNameSeries(prefix_="sta", start_id_=self.start_id,
                                                      end_id_=input['num_station'] - 1, padding_number_=100,
                                                      radio=self.radio)
                # implementation for non vlan pending ****
            print("creating stations")
            self.station_profile.use_security(self.security, self.ssid, str(input['password']))
            self.station_profile.set_command_flag("add_sta", "create_admin_down", 1)
            self.station_profile.set_command_param("set_port", "report_timer", 1500)
            self.station_profile.set_command_flag("set_port", "rpt_timer", 1)
            self.station_profile.create(radio=input['radio'], sta_names_=station_list, debug=self.debug)
            self.wait_until_ports_appear(sta_list=station_list)
            for sta_name in station_list:
                if '1.1.' in sta_name:
                    sta_name = sta_name.strip('1.1.')
                try:
                    cli_base = LFCliBase(_lfjson_host=self.lfclient_host, _lfjson_port=self.lfclient_port)
                    resp = cli_base.json_get(_req_url=f'port/1/1/{sta_name}')
                    dict_data = resp['interface']
                    dict_table[""] = list(dict_data.keys())
                    dict_table["Before"] = list(dict_data.values())
                except Exception as e:
                    print(e)
            self.station_profile.admin_up()
            if self.wait_for_ip(station_list, timeout_sec=120):
                print("All stations got IPs")
            else:
                print("Stations failed to get IPs")
            for sta_name2 in station_list:
                if '1.1.' in sta_name2:
                    sta_name2 = sta_name2.strip('1.1.')
                try:
                    cli_base = LFCliBase(_lfjson_host=self.lfclient_host, _lfjson_port=self.lfclient_port)
                    resp = cli_base.json_get(_req_url=f'port/1/1/{sta_name2}')
                    dict_data = resp['interface']
                    dict_table["After"] = list(dict_data.values())
                    try:
                        data_table = tabulate(dict_table, headers='keys', tablefmt='fancy_grid')
                    except Exception as e:
                        print(e)
                    allure.attach(name=f'{sta_name2} info', body=data_table)
                except Exception as e:
                    print(e)
            print("create udp endp")
            self.cx_profile_udp = self.new_l3_cx_profile()
            self.cx_profile_udp.side_a_min_bps = 128000
            self.cx_profile_udp.side_b_min_bps = 128000
            self.cx_profile_udp.side_a_min_pdu = 1200
            self.cx_profile_udp.side_b_min_pdu = 1500
            self.cx_profile_udp.report_timer = 1000
            self.cx_profile_udp.name_prefix = "udp"
            port_list = list(self.find_ports_like("%s+" % self.sta_prefix))
            # print("port list", port_list)
            if (port_list is None) or (len(port_list) < 1):
                raise ValueError("Unable to find ports named '%s'+" % self.sta_prefix)
            self.cx_profile_udp.create(endp_type="lf_udp",
                                       side_a=port_list,
                                       side_b="%d.%s" % (int(self.upstream_resource), input['upstream']),
                                       suppress_related_commands=True)

            # Create TCP endpoints
            print("create tcp endp")
            self.l3_tcp_profile = self.new_l3_cx_profile()
            self.l3_tcp_profile.side_a_min_bps = 128000
            self.l3_tcp_profile.side_b_min_bps = 56000
            self.l3_tcp_profile.name_prefix = "tcp"
            self.l3_tcp_profile.report_timer = 1000
            self.l3_tcp_profile.create(endp_type="lf_tcp",
                                       side_a=list(self.find_ports_like("%s+" % self.sta_prefix)),
                                       side_b="%d.%s" % (int(self.upstream_resource), input['upstream']),
                                       suppress_related_commands=True)

    def start(self):
        self.cx_profile_udp.start_cx()
        self.l3_tcp_profile.start_cx()

    def monitor_vlan_ip(self):
        # this function gives vlan ip dict eg{'eth2.100': '172.17.0.1'}
        vlan_ips = {}
        for i in self.input:
            # print(i)
            if "." in i['upstream']:
                # print(str(i['upstream']) + " is a vlan upstream port")
                print("checking its ip ..")
                data = self.json_get("ports/list?fields=IP")
                for val in data["interfaces"]:
                    for j in val:
                        if "1." + str(self.upstream_resource) + "." + str(i['upstream']) == j:
                            ip_upstream = val["1." + str(self.upstream_resource) + "." + str(i['upstream'])]['ip']
                            vlan_ips[i['upstream']] = ip_upstream
                            # print(ip_upstream)
                            # print(vlan_ips)
        return vlan_ips
        # {'eth2.100': '172.17.0.1', 'eth2.200': '172.18.0.1'}

    def monitor_non_vlan_ip(self):
        non_vlan_ips = {}
        for i in self.input:
            if "." not in i['upstream']:
                # print(str(i['upstream']) + " is not an vlan upstream port")
                print("checking its ip ..")
                data = self.json_get("ports/list?fields=IP")
                for val in data["interfaces"]:
                    for j in val:
                        if "1." + str(self.upstream_resource) + "." + str(i['upstream']) == j:
                            ip_upstream = val["1." + str(self.upstream_resource) + "." + str(i['upstream'])]['ip']
                            non_vlan_ips[i['upstream']] = ip_upstream
                            # print(ip_upstream)
                            # print(non_vlan_ips)
        return non_vlan_ips

    def get_sta_ip(self):
        station_ip = {}
        port_list = list(self.find_ports_like("%s+" % self.sta_prefix))
        # print("port list", port_list)
        # port list ['1.1.sta200', '1.1.sta00', '1.1.sta100']
        for name, id in zip(port_list, self.input):
            # print(name)
            # print(type(name))
            x = id['upstream'].split('.')[1]
            # print(x)

            if name == "1." + str(self.resource) + ".sta" + str(x):
                data = self.json_get("ports/list?fields=IP")
                for i in data["interfaces"]:
                    # print(i)
                    for j in i:
                        if j == name:
                            sta_ip = i[name]['ip']
                            # print(sta_ip)
                            station_ip[id['upstream']] = sta_ip
            # print(station_ip)
            return station_ip

    def get_sta_ip_for_more_vlan(self):
        input = [{'password': 'lanforge1', 'upstream': 'eth2.100', 'mac': '', 'num_station': 1, 'radio': 'wiphy4'},
                 {'password': 'lanforge2', 'upstream': 'eth2.200', 'mac': '', 'num_station': 1, 'radio': 'wiphy4'},
                 {'password': 'lanforge3', 'upstream': 'eth2', 'mac': '', 'num_station': 1, 'radio': 'wiphy0'}]
        port_list = ['1.1.sta200', '1.1.sta00', '1.1.sta100']
        upstream_list = []
        id_num = []
        station_ip = {}
        for i in input:
            if "." in i['upstream']:
                # print(i['upstream'])
                upstream_list.append(i['upstream'])
                x = i['upstream'].split('.')[1]
                id_num.append(x)

        # print(upstream_list)
        # print(id_num)
        # print(port_list)
        port = []

        for i in port_list:
            # print(i.split(".")[2])
            for num in id_num:
                if i.split(".")[2] == "sta" + str(num):
                    port.append(i)
        sorted_port = sorted(port)

        for name, id in zip(sorted_port, self.input):
            # print(name)
            # print(type(name))
            x = id['upstream'].split('.')[1]
            # print(x)

            if name == "1." + str(self.resource) + ".sta" + str(x):
                data = self.json_get("ports/list?fields=IP")
                for i in data["interfaces"]:
                    # print(i)
                    for j in i:
                        if j == name:
                            sta_ip = i[name]['ip']
                            # print(sta_ip)
                            station_ip[id['upstream']] = sta_ip
        # print(station_ip)
        return station_ip

    def get_non_vlan_sta_ip(self):
        station_nonvlan_ip = {}
        x = ""
        port_list = list(self.find_ports_like("%s+" % self.sta_prefix))
        # print("port list", port_list)
        for id in self.input:
            if "." not in id['upstream']:
                x = id['upstream']
        # print(x)
        for name in port_list:
            if name == "1.1.sta00":
                data = self.json_get("ports/list?fields=IP")
                for i in data["interfaces"]:
                    # print(i)
                    for j in i:
                        if j == name:
                            sta_ip = i[name]['ip']
                            # print(sta_ip)
        station_nonvlan_ip[x] = sta_ip
        return station_nonvlan_ip

    def compare_ip(self):
        vlan_ip = self.monitor_vlan_ip()
        station_ip = self.get_sta_ip()
        # vlan_ip = {'eth2.100': '172.17.0.1', 'eth2.200': '172.18.0.1'}
        # station_ip = {'eth2.100': '172.17.0.237', 'eth2.200': '172.18.100.222'}
        for i, j in zip(vlan_ip, station_ip):
            if i == j:
                x = vlan_ip[i].split('.')
                y = station_ip[j].split('.')
                if x[0] == y[0] and x[1] == y[1]:
                    print("station got ip from vlan")
                    return "Pass"
                else:
                    print("station did not got ip from vlan")
                    return "Fail"

    def compare_nonvlan_ip_nat(self):
        non_vlan_sta_ip = self.get_non_vlan_sta_ip()
        # print(non_vlan_sta_ip)
        for id in self.input:
            if "." not in id['upstream']:
                x = id['upstream']
        # print(non_vlan_sta_ip[x])
        non_vlan = non_vlan_sta_ip[x].split(".")
        if non_vlan[0] == "192" and non_vlan[1] == "168":
            # print("Pass")
            x = 'Pass'
        else:
            x = "Fail"
        return x

    def compare_nonvlan_ip_bridge(self):
        upstream_ip = self.monitor_non_vlan_ip()
        non_vlan_sta_ip = self.get_non_vlan_sta_ip()
        result1 = "Fail"
        for i, j in zip(upstream_ip, non_vlan_sta_ip):
            # print(i)
            if i == j:
                x = upstream_ip[i].split('.')
                y = non_vlan_sta_ip[j].split('.')
                if x[0] == y[0] and x[1] == y[1]:
                    print("station got ip from upstream")
                    result1 = "Pass"
                else:
                    print("station did not got ip from upstream")
                    result1 = "Fail"
        return result1

    def postcleanup(self):
        self.cx_profile_udp.cleanup()
        self.l3_tcp_profile.cleanup()
        self.station_profile.cleanup()
        LFUtils.wait_until_ports_disappear(base_url=self.lfclient_host, port_list=self.station_profile.station_names,
                                           debug=self.debug)
        print("Test Completed")


def main():
    parser = Realm.create_basic_argparse(
        prog="lf_multipsk.py",
        formatter_class=argparse.RawTextHelpFormatter,
        description="lanforge webpage download Test Script")
    parser.add_argument('--n_vlan', help="type number of vlan using in test eg 1 or 2", default=1)
    parser.add_argument('--mode', help="Mode for lf_multipsk", default=None)
    args = parser.parse_args()

    input_data = [{
        "password": args.passwd,
        "upstream": "eth2.100",
        "mac": "",
        "num_station": 1,
        "radio": "wiphy4"
    },
        {
            "password": "lanforge2",
            "upstream": "eth2.200",
            "mac": "",
            "num_station": 1,
            "radio": "wiphy4"
        },
        {
            "password": "lanforge2",
            "upstream": "eth2.300",
            "mac": "",
            "num_station": 1,
            "radio": "wiphy4"
        },
        {
            "password": "lanforge",
            "upstream": "eth2",
            "mac": "",
            "num_station": 1,
            "radio": "wiphy0"
        },

    ]
    multi_obj = MultiPsk(host=args.mgr,
                         port=args.mgr_port,
                         ssid=args.ssid,
                         passwd=args.passwd,
                         input=input_data,
                         security=args.security,
                         debug_=args.debug,
                         radio=args.radio)

    multi_obj.build()
    multi_obj.start()
    time.sleep(60)
    multi_obj.monitor_vlan_ip()
    if args.n_vlan == "1":
        multi_obj.get_sta_ip()
    else:
        multi_obj.get_sta_ip_for_more_vlan()

    result = multi_obj.compare_ip()
    print("checking for vlan ips")
    if result == "Pass":
        print("Test pass")
    else:
        print("Test Fail")
    print("now checking ip for non vlan port")
    multi_obj.monitor_non_vlan_ip()
    multi_obj.get_non_vlan_sta_ip()
    if args.mode == "BRIDGE":
        result1 = multi_obj.compare_nonvlan_ip_bridge()
    else:
        result1 = multi_obj.compare_nonvlan_ip_nat()
    if result1 == "Pass":
        print("Test passed for non vlan ip ")
    else:
        print("Test failed for non vlan ip")
    print("all result gathered")
    print("clean up")
    multi_obj.postcleanup()


if __name__ == '__main__':
    main()

