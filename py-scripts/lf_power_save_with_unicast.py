#!/usr/bin/env python3
import sys
import os
import importlib
import time
import datetime
import argparse
import allure
from pprint import pprint

if sys.version_info[0] != 3:
    print("This script requires Python 3")
    exit(1)

sys.path.append(os.path.join(os.path.abspath(__file__ + "../../../")))

LFUtils = importlib.import_module("py-json.LANforge.LFUtils")
realm = importlib.import_module("py-json.realm")
Realm = realm.Realm
l3_cxprofile = importlib.import_module("py-json.l3_cxprofile")
multicast_profile = importlib.import_module("py-json.multicast_profile")
station_profile = importlib.import_module("py-json.station_profile")
wifi_monitor = importlib.import_module("py-json.wifi_monitor_profile")
cv_test_reports = importlib.import_module("py-json.cv_test_reports")
from lf_sniff_radio import SniffRadio
lf_rpt = cv_test_reports.lanforge_reports

import pyshark as ps

'''
Usage: python3 lf_power_save_with_unicast.py --mgr 192.168.200.229 --ssid Endurance1 --radio wiphy0 
       --upstream_port 1.1.eth1 --monitor_radio wiphy0 
       --report_path /home/mahesh/Desktop/lanforge-scripts/lanforge-scripts/py-scripts
'''


class UnicastPowersaveTraffic(Realm):

    def __init__(self, host, port, ssid, security, password, station_list, min_rate_multi_cast=56,
                 max_rate_multi_cast=56,
                 side_a_unicast_min_rate=56, side_b_unicast_min_rate=56, side_a_unicast_max_rate=0,
                 side_b_unicast_max_rate=0, pdu_size=1000,band="sixg",
                 upstream="1.1.eth1", interface_to_capture=None,
                 prefix="00000", test_duration="5m", report_path="",
                 station_radio="wiphy0", monitor_radio="wiphy0", remote_host_cap_ip=None,
                 output_file_for_cap="",
                 remote_host_cap_interface=None,
                 _debug_on=False, _exit_on_error=False, _exit_on_fail=False):
        super().__init__(lfclient_host=host, lfclient_port=port, debug_=_debug_on)
        self.host = host
        self.port = port
        self.ssid = ssid
        self.security = security
        self.password = password
        self.sta_list = station_list
        self.prefix = prefix
        self.station_radio = station_radio
        self.monitor_radio = monitor_radio
        self.debug = _debug_on
        self.upstream = upstream
        self.min_rate = min_rate_multi_cast
        self.max_rate = max_rate_multi_cast
        self.output_file = output_file_for_cap
        self.enable_multicast_testing = False
        self.enable_unicast_testing = False
        self.filter = ""
        self.report_dir = report_path
        self.captured_file_name = ""
        self.sta_mac = ""
        self.ap_mac = ""
        self.upstream_mac = ""
        self.band = band
        if interface_to_capture is not None:
            self.live_cap_timeout = interface_to_capture
        else:
            self.live_cap_timeout = station_radio
        if remote_host_cap_ip and remote_host_cap_interface is not None:
            self.remote_cap_host = remote_host_cap_ip
            self.remote_cap_interface = remote_host_cap_interface

        self.new_monitor = self.new_wifi_monitor_profile()
        self.test_duration = test_duration
        # upload
        self.cx_prof_upload = l3_cxprofile.L3CXProfile(self.host, self.port, local_realm=self,
                                                       side_a_min_bps=side_a_unicast_min_rate, side_b_min_bps=0,
                                                       side_a_max_bps=side_a_unicast_max_rate, side_b_max_bps=0,
                                                       side_a_min_pdu=pdu_size, side_a_max_pdu=pdu_size,
                                                       side_b_min_pdu=0, side_b_max_pdu=0, debug_=self.debug)

        # download
        self.cx_prof_download = l3_cxprofile.L3CXProfile(self.host, self.port, local_realm=self,
                                                         side_a_min_bps=0, side_b_min_bps=side_b_unicast_min_rate,
                                                         side_a_max_bps=0, side_b_max_bps=side_b_unicast_max_rate,
                                                         side_a_min_pdu=0, side_a_max_pdu=0,
                                                         side_b_min_pdu=pdu_size, side_b_max_pdu=pdu_size,
                                                         debug_=self.debug)
        self.multi_cast_profile = multicast_profile.MULTICASTProfile(self.host, self.port, local_realm=self)

        self.station_profile = station_profile.StationProfile(self.lfclient_url, local_realm=self, ssid=self.ssid,
                                                              ssid_pass=self.password,
                                                              security=self.security, number_template_=self.prefix,
                                                              mode=0,
                                                              up=True,
                                                              dhcp=True,
                                                              debug_=self.debug)
        self.new_monitor = wifi_monitor.WifiMonitor(self.lfclient_url, local_realm=self, debug_=self.debug)

    def build_station_profile(self):
        print("Station radio..in 108 lanfo-py-scri",self.station_radio)
        self.station_profile.use_security(self.security, ssid=self.ssid, passwd=self.password)
        self.station_profile.set_number_template(self.prefix)
        self.station_profile.set_command_flag("add_sta", "create_admin_down", 1)
        self.station_profile.set_command_param("set_port", "report_timer", 1500)
        self.station_profile.set_command_flag("set_port", "rpt_timer", 1)
        self.station_profile.set_command_flag("add_sta", "power_save_enable", 1)
        self.station_profile.create(radio=self.station_radio, sta_names_=self.sta_list)
        self._pass("PASS: Station builds finished")

    def build_monitor(self, channel):
        self.new_monitor.create(resource_=1, channel=channel, radio_=self.monitor_radio, name_="moni0")

    def build_multi_cast_profile(self):
        self.multi_cast_profile.create_mc_tx("mc_udp", self.upstream, min_rate=self.min_rate, max_rate=self.max_rate)
        self.multi_cast_profile.create_mc_rx("mc_udp", self.sta_list)

    def build_layer3_upload(self):
        self.cx_prof_upload.name_prefix = "UDP_up"
        print("Creating upload cx profile ")
        self.cx_prof_upload.create(endp_type="lf_tcp", side_a=self.station_profile.station_names, side_b=self.upstream,
                                   sleep_time=.05)

    def build_layer3_download(self):
        self.cx_prof_download.name_prefix = "TCP_down"
        print("Creating download cx profile")
        self.cx_prof_download.create(endp_type="lf_tcp", side_a=self.station_profile.station_names,
                                     side_b=self.upstream,
                                     sleep_time=.05)

        # channel = self.json_get("/port/1/%s/%s/"%(1,"wiphy0"))
        # rint("The channel name is...")

        # station_channel = self.json_get("/port/1/%s/%s")
        # pprint.pprint(station_channel)

    def get_channel(self):
        self.station_profile.admin_up()
        # self.new_monitor.set_flag()
        # print(self.station_profile.station_names)
        print("Querying for channel from station created to create monitor interface on that particular channel")
        if self.wait_for_ip(self.station_profile.station_names):
            self._pass("All stations got IPs")
        else:
            self._fail("Stations failed to get IPs")
            exit(1)
        channel_info = self.json_get(f"port/1/1/{self.sta_list[0]}?fields=channel")
        print(channel_info)
        if channel_info is not None:
            if 'interfaces' in channel_info:
                for item in channel_info['interfaces']:
                    for k, v in item.items():
                        print("sta_name %s" % v['alias'])
                        print("mac      %s" % v['mac'])
                        print("ap       %s\n" % v['ap'])
            elif 'interface' in channel_info:
                print("channel %s" % channel_info['interface']['channel'])
                self.station_profile.admin_down()
                time.sleep(0.5)
        return int(channel_info['interface']['channel'])

    def get_captured_file_and_location(self):
        return self.captured_file_name, self.report_dir, self.filter

    def start(self,channel_info):
        # start one test, measure
        # start second test, measure
        cur_time = datetime.datetime.now()
        allure.attach(name="Test Start Time:", body=str(f"{cur_time}"))
        end_time = self.parse_time(self.test_duration) + cur_time
        allure.attach(name="Test End Time:", body=str(f"{end_time}"))
        # admin up on new monitor
        self.new_monitor.admin_up()
        now = datetime.datetime.now()
        date_time = now.strftime("%Y-%m-%d-%H%M%S")
        curr_mon_name = self.new_monitor.monitor_name
        # ("date and time: ",date_time)
        duration_to_sec = 120
        if self.test_duration[-1] == 'm':
            duration_to_sec = int(self.test_duration.strip('m')) * 60
        elif self.test_duration[-1] == 'h':
            duration_to_sec = int(self.test_duration.strip('h')) * 60 * 60
        elif self.test_duration[-1] == 's':
            duration_to_sec = int(self.test_duration.strip('s'))
        print(duration_to_sec)

        self.captured_file_name = curr_mon_name + "-" + date_time + ".pcap"
        if self.band == "sixg":
           print("enterted into sixg")
           lf_sniff_radio_obj = SniffRadio(lfclient_host=self.host,channel=channel_info,monitor_name="moni0")
           print("frequency...",lf_sniff_radio_obj.freq)
           lf_sniff_radio_obj.set_freq(self.host,"lanforge", freq=lf_sniff_radio_obj.freq)
        print("Starting sniffing")
        self.new_monitor.start_sniff(capname=curr_mon_name + "-" + date_time + ".pcap",
                                     duration_sec=duration_to_sec)
        print(f"Sniffer started will continue for {duration_to_sec} seconds")
        # admin up on station

        print("station profile got admin up")
        self.station_profile.admin_up()
        # self.new_monitor.set_flag()
        # print(self.station_profile.station_names)
        if self.wait_for_ip(self.station_profile.station_names):
            self._pass("All stations got IPs")
        else:
            self._fail("Stations failed to get IPs")
            print("Stations didn't received ip")
            allure.attach(name="FAILED", body="Stations didn't connected to AP")
            exit(1)

        if self.enable_multicast_testing:
            print("started multicast traffic")
            self.multi_cast_profile.start_mc()
        elif self.enable_unicast_testing:
            print("started unicast traffic")
            self.start_layer3()

        # print station + MAC, AP
        temp = []
        for station in self.station_profile.station_names:
            temp.append(self.name_to_eid(station)[2])
        port_info = self.json_get("port/1/1/%s?fields=alias,ap,mac" % ','.join(temp))
        print("port_info.........", port_info)
        if port_info is not None:
            if 'interfaces' in port_info:
                for item in port_info['interfaces']:
                    for k, v in item.items():
                        print("sta_name %s" % v['alias'])
                        print("mac      %s" % v['mac'])
                        print("ap       %s\n" % v['ap'])
            elif 'interface' in port_info:
                print("sta_name %s" % port_info['interface']['alias'])
                print("mac      %s" % port_info['interface']['mac'])
                print("ap       %s\n" % port_info['interface']['ap'])
                self.filter = "wlan.addr==" + port_info['interface']['mac'] + " || " + "wlan.addr==" + \
                              port_info['interface']['ap']
                self.sta_mac = str(port_info['interface']['mac'])
                self.ap_mac = str(port_info['interface']['ap'])
                allure.attach(name="AP MAC", body=str(port_info['interface']['ap']))
                allure.attach(name="Station MAC", body=str(port_info['interface']['mac']))
                print("filter=", self.filter)
                print("filter=", self.filter)
            else:
                print('interfaces and interface not in port_mgr_response')
                allure.attach(name="FAILED", body=str("station data is not in response"))
                exit(1)
        temp_1 = []
        temp_1.append(self.name_to_eid(self.upstream)[2])
        upstream_info = self.json_get("port/1/1/%s?fields=alias,mac" % ','.join(temp_1))
        print("upstream_info.........", upstream_info)
        if upstream_info is not None:
            if 'interfaces' in upstream_info:
                for item in upstream_info['interfaces']:
                    for k, v in item.items():
                        print("upstream_name %s" % v['alias'])
                        print("mac      %s" % v['mac'])
            elif 'interface' in upstream_info:
                print("sta_name %s" % upstream_info['interface']['alias'])
                print("mac      %s" % upstream_info['interface']['mac'])
                self.upstream_mac = str(upstream_info['interface']['mac'])
                allure.attach(name="Upstream Port MAC", body=str(upstream_info['interface']['mac']))
            else:
                print('interfaces and interface not in port_mgr_upstream_response')
                exit(1)
                exit(1)

        while cur_time < end_time:
            # DOUBLE CHECK
            interval_time = cur_time + datetime.timedelta(minutes=1)
            while cur_time < interval_time:
                cur_time = datetime.datetime.now()
                time.sleep(1)

        # pulls report from lanforge to specified location in self.report_dir
        lf_rpt.pull_reports(hostname=self.host, port=22, username="lanforge", password="lanforge",
                            report_location="/home/lanforge/" + curr_mon_name + "-" + date_time + ".pcap",
                            report_dir=self.report_dir)
        # allure.attach.file(source=self.report_dir + "/" + self.captured_file_name, name="pcap_file",
        #                    attachment_type=allure.attachment_type.PCAP)

    '''
    def capture_live_pcap(self):
        try:
            self.live_pcap = ps.LiveCapture(interface=self.live_pcap_interface, output_file=self.output_file)
            self.live_pcap.sniff(timeout=300)
        except ValueError:
            raise "Capture Error"
        return self.live_pcap

    def capture_remote_pcap(self):
        try:
            self.remote_pcap = ps.RemoteCapture(remote_host=self.remote_cap_host,
                                                remote_interface=self.remote_cap_interface)
        except ValueError:
            raise "Host error"
        return self.remote_pcap
    '''

    def verify_unicast_pcap(self, pcap_file, apply_filter=None):
        self.pcap_file = self.report_dir + "/" + pcap_file
        # self.ap_mac = "10:f9:20:fd:e2:0b"
        # self.sta_mac = "a8:93:4a:df:b0:3b"

        if apply_filter is not None:
            self.apply_filter = apply_filter
        try:
            pcap = ps.FileCapture(input_file=self.pcap_file, display_filter=self.apply_filter)
        except Exception as error:
            raise error
        check_unicast = False
        traffic_awaiting = False
        block_ack = False
        data_packet = False
        result_data = False
        QOS_data_pkt_count = False
        for pkt in pcap:  # traversing through all packets one by one
            # print(str(pkt.wlan.fc_type_subtype))
            # print(str(pkt.wlan.fc_pwrmgt))
            if str(pkt.wlan.fc_type_subtype) == "0x002c" and str(pkt.wlan.fc_pwrmgt) == '1':
                check_unicast = True
                continue

            if check_unicast:
                if str(pkt.wlan.fc_type_subtype) == "0x0008":
                    if "wlan.mgt" in pkt and str(pkt["wlan.mgt"].wlan_tim_partial_virtual_bitmap) != '00':
                        traffic_awaiting = True
                        # print(f"PASSED:Beacon with Traffic buffered is seen {pkt.number}")
                        # allure.attach(name="Beacon",body=str(f"PASSED:Beacon with Traffic buffered is seen {pkt.number}"))
                        # print("found", pkt.number)
                        continue

                if traffic_awaiting:
                    if str(pkt.wlan.fc_type_subtype) == "0x002c" and str(pkt.wlan.fc_pwrmgt) == '0':
                        # print(f"PASSED:QOS Null Function frame with pwr mgt 0 is seen {pkt.number}")
                        # allure.attach(name="QOS Null Function",body=str(f"PASSED:QOS Null Function frame with pwr mgt 0 is seen {pkt.number}"))
                        data_packet = True
                        continue

                if str(pkt.wlan.fc_type_subtype) == "0x002c" and str(pkt.wlan.fc_pwrmgt) == '1':
                    # print("WARNING:QOS Null function with pwr mgt bit 1 without QOS data being transmitted ")
                    check_unicast = False
                    traffic_awaiting = False
                    data_packet = False
                    continue

                if str(pkt.wlan.fc_type_subtype) == "0x002c" and str(pkt.wlan.fc_pwrmgt) == '0':
                    # print("WARNING:QOS Null function with pwr mgt bit 0 without QOS data being transmitted ")
                    check_unicast = False
                    traffic_awaiting = False
                    data_packet = False
                    continue

                if data_packet:
                    if str(pkt.wlan.fc_type_subtype) == "0x0028":
                        if str(pkt.wlan.ta) == self.ap_mac and str(pkt.wlan.da) == self.sta_mac:
                            QOS_data_pkt_count=True
                            if str(pkt.wlan.fc_moredata) == "1":
                                data_packet=True
                            elif str(pkt.wlan.fc_moredata) == "0":
                                check_unicast = False
                                traffic_awaiting = False
                                data_packet = False
                                continue
                            # print(f"PASSED:Unicast Packet Transmitted after client came from powersave {pkt.number}")
                            # allure.attach(name="PASSED", body=str(
                            #     f"Unicast Packet Transmitted after client came from powersave,packet Number {pkt.number}"))
                            # break

                elif str(pkt.wlan.fc_type_subtype) == "0x0028":
                    if str(pkt.wlan.ta) == self.ap_mac and str(pkt.wlan.da) == self.sta_mac:
                        QOS_data_pkt_count=True
                        print(f"FAILED:Unexpected unicast data packet in {pkt.number}")
                        result_data = True
                        # pass
                        # print(f"FAILED:Unexpected unicast data packet in {pkt.number}")
                        allure.attach(name="FAILED",
                                      body=str(f"Unexpected unicast data packet in capture, packet number {pkt.number}"))

        if not QOS_data_pkt_count:
           result_data=True
           allure.attach(name="FAILED",body="QOS Data packets sent by the AP are not found in the capture for unicast traffic validation")

        allure.attach.file(source=self.pcap_file, name="pcap_file", attachment_type=allure.attachment_type.PCAP)
        return result_data

    def start_station_profile(self):
        self.station_profile.admin_up()

    def stop_station_profile(self):
        self.station_profile.admin_down()

    def stop_monitor(self):
        # switch off new monitor
        self.new_monitor.admin_down()

    def start_layer3(self):
        # self.cx_prof_upload.start_cx()
        self.cx_prof_download.start_cx()

    def stop_layer3(self):
        # self.cx_prof_upload.stop_cx()
        self.cx_prof_download.stop_cx()

    def cleanup_station_profile(self):
        self.station_profile.cleanup(desired_stations=self.sta_list)

    def cleanup_layer3(self):
        self.cx_prof_download.cleanup()
        self.cx_prof_upload.cleanup()

    def cleanup_monitor(self):
        self.new_monitor.cleanup()

    def unicast_download_testing(self,cleanup=True):
        self.enable_unicast_testing = True
        self.station_profile.cleanup(desired_stations=self.sta_list)
        self.station_profile.local_realm.remove_all_cxs(remove_all_endpoints=True)
        self.build_station_profile()  # function to build station profile
        channel_info = self.get_channel()
        self.build_monitor(channel_info)  # function to create monitor
        self.build_layer3_download()  # function to build unicast download traffic

        self.start(channel_info)  # function to start sniff by admin up station followed by /
        # starting the unicast traffic with desired pdu size for some duration
        if cleanup:
           self.unicast_testing_stop_and_cleanup()

    def unicast_testing_stop_and_cleanup(self):
        self.new_monitor.admin_down()
        self.cx_prof_download.stop_cx()
        self.station_profile.admin_down()

        self.new_monitor.cleanup()
        self.cx_prof_download.cleanup()
        self.station_profile.cleanup(desired_stations=self.sta_list)


def main():
    # Realm.create_basic_argparse defined in lanforge-scripts/py-json/LANforge/lfcli_base.py
    parser = Realm.create_basic_argparse(
        prog='lf_power_save_test_cases_cisco.py',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''\
        lf_power_save_test_cases_cisco.py

            ''',
        description='''\
Example of creating traffic on an l3 connection
        ''')

    parser.add_argument('--monitor_radio', help="--monitor_radio radio to be used in monitor creation",
                        default="wiphy1")
    parser.add_argument('--report_path', help="desired path to save your pcap file fetched from lanforge through ssh",
                        default="/home/mahesh/Desktop/lanforge-scripts/lanforge-scripts/py-scripts")
    parser.add_argument('--mcast_min_rate', help="value for multicast minimum rate in kbps", type=int, default=9000)
    parser.add_argument('--mcast_max_rate', help="value for multicast maximum rate in kbps", type=int, default=128000)

    parser.add_argument('--side_a_unicast_min_rate', help="value for multicast maximum rate in kbps", type=int,
                        default=9000)
    parser.add_argument('--side_b_unicast_min_rate', help="value for multicast maximum rate in kbps", type=int,
                        default=9000)
    parser.add_argument('--side_a_unicast_max_rate', help="value for multicast maximum rate in kbps", type=int,
                        default=128000)
    parser.add_argument('--side_b_unicast_max_rate', help="value for multicast maximum rate in kbps", type=int,
                        default=128000)
    parser.add_argument('--test_duration', help='duration of the test eg: 30s, 2m, 4h', default="5m")

    parser.add_argument('--pdu_size', help="pdu size in bytes", type=int, default=1400)

    args = parser.parse_args()

    lfjson_host = args.mgr
    lfjson_port = 8080
    station_list = LFUtils.portNameSeries(prefix_="sta", start_id_=0, end_id_=0, padding_number_=10000)
    ip_powersave_test = UnicastPowersaveTraffic(lfjson_host, lfjson_port, ssid=args.ssid,
                                                            security=args.security,
                                                            password=args.passwd, station_list=station_list,
                                                            min_rate_multi_cast=args.mcast_min_rate,
                                                            max_rate_multi_cast=args.mcast_max_rate,
                                                            side_a_unicast_min_rate=args.side_a_unicast_min_rate,
                                                            side_b_unicast_min_rate=args.side_b_unicast_min_rate,
                                                            side_a_unicast_max_rate=args.side_a_unicast_max_rate,
                                                            side_b_unicast_max_rate=args.side_b_unicast_max_rate,
                                                            pdu_size=args.pdu_size,
                                                            station_radio=args.radio,
                                                            upstream=args.upstream_port,
                                                            monitor_radio=args.monitor_radio,
                                                            test_duration=args.test_duration,
                                                            interface_to_capture=None,
                                                            _debug_on=args.debug, remote_host_cap_ip=None,
                                                            remote_host_cap_interface=None,
                                                            report_path=args.report_path,
                                                            output_file_for_cap="/home/lanforge",
                                                            _exit_on_error=True, _exit_on_fail=True)

    #ip_powersave_test.unicast_download_testing()  # function to run unicast test

    #captured_file_name, local_dir, filter = ip_powersave_test.get_captured_file_and_location()  # function returns captured_file_name along \
    # with location of local directory where the \
    # captured file is pulled

    # below function should be executed along with multicast_testing or unicast_testing if we wish to disect captured file.
    #ip_powersave_test.verify_unicast_pcap(local_dir + '/' + captured_file_name,
    #                                      apply_filter=filter)

    # below function can be run solely without calling above functions to disect multicast packets \
    # if we have ready packet captured file to test dtim_multicast

    # ip_powersave_test.verify_dtim_multicast_pcap("/home/mahesh/Documents/moni0-2022-02-17-170018.pcap",
    #                                              apply_filter="wlan.addr==04:f0:21:94:1e:4d || wlan.addr==3C:37:86:13:81:60")

    # ''' UNICAST TEST FUNCTIONS'''
    # ip_powersave_test.verify_unicast_pcap(
    #     "/home/mahesh/Desktop/powersave_unicast_sta_wiphy1_sniff_wiphy3_AX210_tb1_36.pcapng",
    #     apply_filter="wlan.addr == 04:f0:21:ad:82:8f || wlan.addr == 68:7d:b4:60:04:be")

    ip_powersave_test.verify_unicast_pcap(
        "unicast_test_1.pcapng",
        apply_filter="wlan.addr==10:f9:20:fd:e2:0b||wlan.addr==a8:93:4a:df:b0:3b")

    # wlan.fc.type_subtype != 5 to avoid probe responses which is not having TIM which might gonna break script


if __name__ == "__main__":
    main()
