#!/usr/bin/env python3

import sys
if sys.version_info[0] != 3:
    print("This script requires Python 3")
    exit(1)

if 'py-json' not in sys.path:
    sys.path.append('../py-json')

# import argparse
from LANforge.lfcli_base import LFCliBase
from LANforge.LFUtils import *
from LANforge import LFUtils
from LANforge import add_file_endp
from LANforge.add_file_endp import *
import argparse
from realm import Realm
import time
import datetime
import pprint


class FileIOTest(Realm):
    def __init__(self, host, port, ssid, security, password,
                 number_template="00000",
                 radio="wiphy0",
                 test_duration="5m",
                 upstream_port="eth1",
                 num_ports=1,
                 server_mount="10.40.0.1:/var/tmp/test",
                 macvlan_parent=None,
                 first_mvlan_ip=None,
                 netmask=None,
                 gateway=None,
                 dhcp=True,
                 use_macvlans=False,
                 use_test_groups=False,
                 write_only_test_group=None,
                 read_only_test_group=None,
                 port_list=[],
                 ip_list=None,
                 connections_per_port=1,
                 mode="both",
                 update_group_args={"name": None, "action": None, "cxs": None},
                 _debug_on=False,
                 _exit_on_error=False,
                 _exit_on_fail=False):
        super().__init__(host, port)
        self.host = host
        self.port = port
        self.radio = radio
        self.upstream_port = upstream_port
        self.ssid = ssid
        self.security = security
        self.password = password
        self.number_template = number_template
        self.test_duration = test_duration
        self.port_list = []
        self.connections_per_port = connections_per_port
        self.use_macvlans = use_macvlans
        self.mode = mode.lower()
        self.ip_list = ip_list
        self.netmask = netmask
        self.gateway = gateway
        self.dhcp = dhcp
        if self.use_macvlans:
            if macvlan_parent is not None:
                self.macvlan_parent = macvlan_parent
                self.port_list = port_list
        else:
            self.port_list = port_list

        self.use_test_groups = use_test_groups
        if self.use_test_groups:
            if self.mode == "write":
                if write_only_test_group is not None:
                    self.write_only_test_group = write_only_test_group
                else:
                    raise ValueError("--write_only_test_group must be used to set test group name")
            if self.mode == "read":
                if read_only_test_group is not None:
                    self.read_only_test_group = read_only_test_group
                else:
                    raise ValueError("--read_only_test_group must be used to set test group name")
            if self.mode == "both":
                if write_only_test_group is not None and read_only_test_group is not None:
                    self.write_only_test_group = write_only_test_group
                    self.read_only_test_group = read_only_test_group
                else:
                    raise ValueError("--write_only_test_group and --read_only_test_group "
                                     "must be used to set test group names")



        self.wo_profile = self.new_fio_endp_profile()
        self.mvlan_profile = self.new_mvlan_profile()

        if not self.use_macvlans and len(self.port_list) > 0:
            self.station_profile = self.new_station_profile()
            self.station_profile.lfclient_url = self.lfclient_url
            self.station_profile.ssid = self.ssid
            self.station_profile.ssid_pass = self.password
            self.station_profile.security = self.security
            self.station_profile.number_template_ = self.number_template
            self.station_profile.mode = 0

        self.wo_profile.server_mount = server_mount
        self.wo_profile.num_connections_per_port = connections_per_port

        self.ro_profile = self.wo_profile.create_ro_profile()

        if self.use_macvlans:
            self.mvlan_profile.num_macvlans = int(num_ports)
            self.mvlan_profile.desired_macvlans = self.port_list
            self.mvlan_profile.macvlan_parent = self.macvlan_parent
            self.mvlan_profile.dhcp = dhcp
            self.mvlan_profile.netmask = netmask
            self.mvlan_profile.first_ip_addr = first_mvlan_ip
            self.mvlan_profile.gateway = gateway

        self.created_ports = []
        if self.use_test_groups:
            if self.mode is not None:
                if self.mode == "write":
                    self.wo_tg_profile = self.new_test_group_profile()
                    self.wo_tg_profile.group_name = self.write_only_test_group
                elif self.mode == "read":
                    self.ro_tg_profile = self.new_test_group_profile()
                    self.ro_tg_profile.group_name = self.read_only_test_group
                elif self.mode == "both":
                    self.wo_tg_profile = self.new_test_group_profile()
                    self.ro_tg_profile = self.new_test_group_profile()
                    self.wo_tg_profile.group_name = self.write_only_test_group
                    self.ro_tg_profile.group_name = self.read_only_test_group
                else:
                    raise ValueError("Unknown mode given ", self.mode)
            else:
                raise ValueError("Mode ( read, write, or both ) must be specified")

        if update_group_args is not None and update_group_args['name'] is not None:
            temp_tg = self.new_test_group_profile()
            temp_cxs = update_group_args['cxs'].split(',')
            if update_group_args['action'] == "add":
                temp_tg.group_name = update_group_args['name']
                if not temp_tg.check_group_exists():
                    temp_tg.create_group()
                for cx in temp_cxs:
                    if "CX_" not in cx:
                        cx = "CX_" + cx
                    temp_tg.add_cx(cx)
            if update_group_args['action'] == "del":
                temp_tg.group_name = update_group_args['name']
                if temp_tg.check_group_exists():
                    for cx in temp_cxs:
                        temp_tg.rm_cx(cx)
            time.sleep(5)

        self.wo_tg_exists = False
        self.ro_tg_exists = False
        self.wo_tg_cx_exists = False
        self.ro_tg_cx_exists = False
        print("Checking for pre-existing test groups and cxs")
        if self.use_test_groups:
            if self.mode == "write":
                if self.wo_tg_profile.check_group_exists():
                    self.wo_tg_exists = True
                    if len(self.wo_tg_profile.list_cxs()) > 0:
                        self.wo_tg_cx_exists = True
            elif self.mode == "read":
                if self.ro_tg_profile.check_group_exists():
                    self.ro_tg_exists = True
                    if len(self.ro_tg_profile.list_cxs()) > 0:
                        self.ro_tg_cx_exists = True
            elif self.mode == "both":
                if self.wo_tg_profile.check_group_exists():
                    self.wo_tg_exists = True
                    if len(self.wo_tg_profile.list_cxs()) > 0:
                        self.wo_tg_cx_exists = True
                if self.ro_tg_profile.check_group_exists():
                    self.ro_tg_exists = True
                    if len(self.ro_tg_profile.list_cxs()) > 0:
                        self.ro_tg_cx_exists = True

    def __compare_vals(self, val_list):
        passes = 0
        expected_passes = 0
        # print(val_list)
        for item in val_list:
            expected_passes += 1
            # print(item)
            if item[0] == 'r':
                # print("TEST", item,
                #       val_list[item]['read-bps'],
                #       self.ro_profile.min_read_rate_bps,
                #       val_list[item]['read-bps'] > self.ro_profile.min_read_rate_bps)

                if val_list[item]['read-bps'] > self.wo_profile.min_read_rate_bps:
                    passes += 1
            else:
                # print("TEST", item,
                #       val_list[item]['write-bps'],
                #       self.wo_profile.min_write_rate_bps,
                #       val_list[item]['write-bps'] > self.wo_profile.min_write_rate_bps)

                if val_list[item]['write-bps'] > self.wo_profile.min_write_rate_bps:
                    passes += 1
            if passes == expected_passes:
                return True
            else:
                return False
        else:
            return False

    def __get_values(self):
        time.sleep(3)
        if self.mode == "write":
            cx_list = self.json_get("fileio/%s?fields=write-bps,read-bps" % (
                                        ','.join(self.wo_profile.created_cx.keys())), debug_=self.debug)
        elif self.mode == "read":
            cx_list = self.json_get("fileio/%s?fields=write-bps,read-bps" % (
                                        ','.join(self.ro_profile.created_cx.keys())), debug_=self.debug)
        else:
            cx_list = self.json_get("fileio/%s,%s?fields=write-bps,read-bps" % (
                                        ','.join(self.wo_profile.created_cx.keys()),
                                        ','.join(self.ro_profile.created_cx.keys())), debug_=self.debug)
        # print(cx_list)
        # print("==============\n", cx_list, "\n==============")
        cx_map = {}
        # pprint.pprint(cx_list)
        if cx_list is not None:
            cx_list = cx_list['endpoint']
            for i in cx_list:
                for item, value in i.items():
                    # print(item, value)
                    cx_map[self.name_to_eid(item)[2]] = {"read-bps": value['read-bps'], "write-bps": value['write-bps']}
        # print(cx_map)
        return cx_map

    def build(self):
        # Build stations
        if self.use_macvlans:
            print("Creating MACVLANs")
            self.mvlan_profile.create(admin_down=False, sleep_time=.5, debug=self.debug)
            self._pass("PASS: MACVLAN build finished")
            self.created_ports += self.mvlan_profile.created_macvlans
        elif not self.use_macvlans and self.ip_list is None:
            self.station_profile.use_security(self.security, self.ssid, self.password)
            self.station_profile.set_number_template(self.number_template)
            print("Creating stations")
            self.station_profile.set_command_flag("add_sta", "create_admin_down", 1)
            self.station_profile.set_command_param("set_port", "report_timer", 1500)
            self.station_profile.set_command_flag("set_port", "rpt_timer", 1)
            self.station_profile.create(radio=self.radio, sta_names_=self.port_list, debug=self.debug)
            self._pass("PASS: Station build finished")
            self.created_ports += self.station_profile.station_names

        if len(self.ip_list) > 0:
            # print("++++++++++++++++\n", self.ip_list, "++++++++++++++++\n")
            for num_port in range(len(self.port_list)):
                if self.ip_list[num_port] != 0:
                    if self.gateway is not None and self.netmask is not None:
                        shelf = self.name_to_eid(self.port_list[num_port])[0]
                        resource = self.name_to_eid(self.port_list[num_port])[1]
                        port = self.name_to_eid(self.port_list[num_port])[2]
                        req_url = "/cli-json/set_port"
                        data = {
                            "shelf": shelf,
                            "resource": resource,
                            "port": port,
                            "ip_addr": self.ip_list[num_port],
                            "netmask": self.netmask,
                            "gateway": self.gateway
                        }
                        self.json_post(req_url, data)
                        self.created_ports.append("%s.%s.%s" % (shelf, resource, port))
                    else:
                        raise ValueError("Netmask and gateway must be specified")


def main():
    parser = LFCliBase.create_bare_argparse(
        prog='create_macvlan.py',
        # formatter_class=argparse.RawDescriptionHelpFormatter,
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''Creates FileIO endpoints which can be NFS, CIFS or iSCSI endpoints.''',

        description='''\
create_macvlan.py:
--------------------
Generic command layout:
./create_macvlan.py --macvlan_parent <port> --num_ports <num ports> --use_macvlans
                 --first_mvlan_ip <first ip in series> --netmask <netmask to use> --gateway <gateway ip addr>

./create_macvlan.py --macvlan_parent eth2 --num_ports 3 --use_macvlans --first_mvlan_ip 192.168.92.13
                 --netmask 255.255.255.0 --gateway 192.168.92.1

./create_macvlan.py --radio 1.wiphy0 --test_duration 1m --macvlan_parent eth1 --num_ports 3 --use_macvlans
                 --use_ports eth1#0,eth1#1,eth1#2 --connections_per_port 2 --mode write

./create_macvlan.py --radio 1.wiphy0 --test_duration 1m --macvlan_parent eth1 --num_ports 3 --use_macvlans
                 --first_mvlan_ip 10.40.3.100 --netmask 255.255.240.0 --gateway 10.40.0.1
                 --use_test_groups --write_only_test_group test_wo --read_only_test_group test_ro
                 --add_to_group test_wo

./create_macvlan.py --radio 1.wiphy0 --test_duration 1m --macvlan_parent eth1 --num_ports 3 --use_macvlans
                 --use_ports eth1#0=10.40.3.103,eth1#1,eth1#2 --connections_per_port 2
                 --netmask 255.255.240.0 --gateway 10.40.0.1

''')
    parser.add_argument('--num_stations', help='Number of stations to create', default=0)
    parser.add_argument('--radio', help='radio EID, e.g: 1.wiphy2')
    parser.add_argument('--ssid', help='SSID for stations to associate to')
    parser.add_argument('--passwd', '--password', '--key', help='WiFi passphrase/password/key')
    parser.add_argument('--security', help='security type to use for ssid { wep | wpa | wpa2 | wpa3 | open }')
    parser.add_argument('-u', '--upstream_port',
                  help='non-station port that generates traffic: <resource>.<port>, e.g: 1.eth1',
                  default='1.eth1')
    parser.add_argument('--test_duration', help='sets the duration of the test', default="5m")
    parser.add_argument('--server_mount', help='--server_mount The server to mount, ex: 192.168.100.5/exports/test1',
                        default="10.40.0.1:/var/tmp/test")

    parser.add_argument('--macvlan_parent', help='specifies parent port for macvlan creation', default=None)
    parser.add_argument('--first_port', help='specifies name of first port to be used', default=None)
    parser.add_argument('--num_ports', help='number of ports to create', default=1)
    parser.add_argument('--connections_per_port', help='specifies number of connections to be used per port', default=1,
                        type=int)
    parser.add_argument('--use_ports', help='list of comma separated ports to use with ips, \'=\' separates name and ip'
                                            '{ port_name1=ip_addr1,port_name1=ip_addr2 }. '
                                            'Ports without ips will be left alone', default=None)
    parser.add_argument('--use_macvlans', help='will create macvlans', action='store_true', default=False)
    parser.add_argument('--first_mvlan_ip', help='specifies first static ip address to be used or dhcp', default=None)
    parser.add_argument('--netmask', help='specifies netmask to be used with static ip addresses', default=None)
    parser.add_argument('--gateway', help='specifies default gateway to be used with static addressing', default=None)
    parser.add_argument('--use_test_groups', help='will use test groups to start/stop instead of single endps/cxs',
                        action='store_true', default=False)
    parser.add_argument('--read_only_test_group', help='specifies name to use for read only test group', default=None)
    parser.add_argument('--write_only_test_group', help='specifies name to use for write only test group', default=None)
    parser.add_argument('--mode', help='write,read,both', default='both', type=str)
    tg_group = parser.add_mutually_exclusive_group()
    tg_group.add_argument('--add_to_group', help='name of test group to add cxs to', default=None)
    tg_group.add_argument('--del_from_group', help='name of test group to delete cxs from', default=None)
    parser.add_argument('--cxs', help='list of cxs to add/remove depending on use of --add_to_group or --del_from_group'
                        , default=None)
    args = parser.parse_args()

    update_group_args = {
        "name": None,
        "action": None,
        "cxs": None
        }
    if args.add_to_group is not None and args.cxs is not None:
        update_group_args['name'] = args.add_to_group
        update_group_args['action'] = "add"
        update_group_args['cxs'] = args.cxs
    elif args.del_from_group is not None and args.cxs is not None:
        update_group_args['name'] = args.del_from_group
        update_group_args['action'] = "del"
        update_group_args['cxs'] = args.cxs

    port_list = []
    ip_list = []
    if args.first_port is not None and args.use_ports is not None:
        if args.first_port.startswith("sta"):
            if (args.num_ports is not None) and (int(args.num_ports) > 0):
                start_num = int(args.first_port[3:])
                num_ports = int(args.num_ports)
                port_list = LFUtils.port_name_series(prefix="sta", start_id=start_num, end_id=start_num+num_ports-1,
                                                   padding_number=10000,
                                                   radio=args.radio)
        else:
            if (args.num_ports is not None) and args.macvlan_parent is not None and (int(args.num_ports) > 0) \
                                            and args.macvlan_parent in args.first_port:
                start_num = int(args.first_port[args.first_port.index('#')+1:])
                num_ports = int(args.num_ports)
                port_list = LFUtils.port_name_series(prefix=args.macvlan_parent+"#", start_id=start_num,
                                                   end_id=start_num+num_ports-1, padding_number=100000,
                                                   radio=args.radio)
            else:
                raise ValueError("Invalid values for num_ports [%s], macvlan_parent [%s], and/or first_port [%s].\n"
                                 "first_port must contain parent port and num_ports must be greater than 0"
                                 % (args.num_ports, args.macvlan_parent, args.first_port))
    else:
        if args.use_ports is None:
            num_ports = int(args.num_ports)
            if not args.use_macvlans:
                port_list = LFUtils.port_name_series(prefix="sta", start_id=0, end_id=num_ports - 1,
                                                   padding_number=10000,
                                                   radio=args.radio)
            else:
                port_list = LFUtils.port_name_series(prefix=args.macvlan_parent + "#", start_id=0,
                                               end_id=num_ports - 1, padding_number=100000,
                                               radio=args.radio)
        else:
            temp_list = args.use_ports.split(',')
            for port in temp_list:
                port_list.append(port.split('=')[0])
                if '=' in port:
                    ip_list.append(port.split('=')[1])
                else:
                    ip_list.append(0)

            if len(port_list) != len(ip_list):
                raise ValueError(temp_list, " ports must have matching ip addresses!")

    if args.first_mvlan_ip is not None:
        if args.first_mvlan_ip.lower() == "dhcp":
            dhcp = True
        else:
            dhcp = False
    else:
        dhcp = True
    # print(port_list)

    # exit(1)
    ip_test = FileIOTest(args.mgr,
                         args.mgr_port,
                         ssid=args.ssid,
                         password=args.passwd,
                         security=args.security,
                         port_list=port_list,
                         ip_list=ip_list,
                         test_duration=args.test_duration,
                         upstream_port=args.upstream_port,
                         _debug_on=args.debug,

                         macvlan_parent=args.macvlan_parent,
                         use_macvlans=args.use_macvlans,
                         first_mvlan_ip=args.first_mvlan_ip,
                         netmask=args.netmask,
                         gateway=args.gateway,
                         dhcp=dhcp,
                         num_ports=args.num_ports,
                         use_test_groups=args.use_test_groups,
                         write_only_test_group=args.write_only_test_group,
                         read_only_test_group=args.read_only_test_group,
                         update_group_args = update_group_args,
                         connections_per_port=args.connections_per_port,
                         mode=args.mode
                         # want a mount options param
                         )

    ip_test.build()

if __name__ == "__main__":
    main()