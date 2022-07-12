#!/usr/bin/env python3
"""
NAME: lf_pcap.py

PURPOSE:
Common Library for reading pcap files and check packet information for specific filters

SETUP: This script requires pyshark and tshark to be installed before

EXAMPLE:
see: /py-scritps/lf_pcap_test.py for example

COPYRIGHT:
    Copyright 2021 Candela Technologies Inc
    License: Free to distribute and modify. LANforge systems must be licensed.

INCLUDE_IN_README
"""
import os
import sys
import argparse
import pyshark as ps
import importlib
from datetime import datetime

sys.path.append(os.path.join(os.path.abspath(__file__ + "../../../")))

wifi_monitor = importlib.import_module("py-json.wifi_monitor_profile")
WiFiMonitor = wifi_monitor.WifiMonitor
lfcli_base = importlib.import_module("py-json.LANforge.lfcli_base")
LFCliBase = lfcli_base.LFCliBase
realm = importlib.import_module("py-json.realm")
Realm = realm.Realm
cv_test_reports = importlib.import_module("py-json.cv_test_reports")
lf_report = cv_test_reports.lanforge_reports


class LfPcap(Realm):
    def __init__(self,
                 host="localhost", port=8080,
                 _read_pcap_file=None,
                 _apply_filter=None,
                 _live_pcap_interface=None,
                 _live_cap_timeout=None,
                 _live_filter=None,
                 _live_remote_cap_host=None,
                 _live_remote_cap_interface=None,
                 _debug_on=False
                 ):
        # uncomment the follwoing line to use wifi monitor functions
        # super().__init__(lfclient_host=host, lfclient_port=port, debug_=_debug_on)
        self.host = host,
        self.port = port
        self.debug = _debug_on
        self.pcap = None
        self.live_pcap = None
        self.remote_pcap = None
        self.pcap_file = _read_pcap_file
        self.apply_filter = _apply_filter
        self.live_filter = _live_filter
        self.live_pcap_interface = _live_pcap_interface
        self.live_cap_timeout = _live_cap_timeout
        self.remote_cap_host = _live_remote_cap_host
        self.remote_cap_interface = _live_remote_cap_interface
        # uncomment the follwoing line to use wifi monitor functions
        # self.wifi_monitor = WiFiMonitor(self.lfclient_url, local_realm=self, debug_=self.debug)

    def read_pcap(self, pcap_file, apply_filter=None):
        self.pcap_file = pcap_file
        if apply_filter is not None:
            self.apply_filter = apply_filter
        try:
            self.pcap = ps.FileCapture(input_file=self.pcap_file, display_filter=self.apply_filter, use_json=False)
        except Exception as error:
            raise error
        return self.pcap

    def read_time(self, pcap_file,
                  filter='(wlan.fixed.auth.alg == 2 && wlan.fixed.status_code == 0x0000 && wlan.fixed.auth_seq == 0x0001)'):
        try:
            if pcap_file is not None:
                cap = self.read_pcap(pcap_file=pcap_file, apply_filter=filter)
                packet_count = 0
                data = []
                for pkt in cap:
                    x = pkt.frame_info.time_relative
                    y = float(x)
                    z = round(y, 4)
                    m = z * 1000
                    data.append(m)
                    packet_count += 1
                print("Total Packets: ", packet_count)
                # print(data)
                if packet_count != 0:
                    return data
                else:
                    return data
        except ValueError:
            raise "pcap file is required"

    def capture_live_pcap(self):
        try:
            self.live_pcap = ps.LiveCapture(interface=self.live_pcap_interface, output_file='captured.pcap')
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

    def get_packet_info(self, pcap_file, filter='wlan.fc.type_subtype==3 && wlan.tag.number==55'):
        """get packet info from each packet from the pcap file"""
        print("pcap file path:  %s" % pcap_file)
        try:
            if pcap_file is not None:
                cap = self.read_pcap(pcap_file=pcap_file, apply_filter=filter)
                packet_count = 0
                data = []
                for pkt in cap:
                    data.append(str(pkt))
                    packet_count += 1
                print("Total Packets: ", packet_count)
                print(data)
                data = "\n".join(data)
                if packet_count != 0:
                    return data
                else:
                    return data
        except ValueError:
            raise "pcap file is required"

    def get_wlan_mgt_status_code(self, pcap_file, filter='wlan.fc.type_subtype==3 && wlan.tag.number==55'):
        """ To get status code of each packet in WLAN MGT Layer """
        print("pcap file path:  %s" % pcap_file)
        try:
            if pcap_file is not None:
                cap = self.read_pcap(pcap_file=pcap_file, apply_filter=filter)
                packet_count = 0
                value, data = '', []
                for pkt in cap:
                    # print(pkt)
                    if 'wlan.mgt' in pkt:
                        value = pkt['wlan.mgt'].get_field_value('wlan_fixed_status_code')
                        if value == '0x0000' or value == '0':
                            data.append('Successful')
                        else:
                            data.append('failed')
                        packet_count += 1
                print("Total Packets: ", packet_count)
                if packet_count != 0:
                    return data
                else:
                    return data
        except ValueError:
            raise "pcap file is required"

    def check_group_id_mgmt(self, pcap_file):
        print("pcap file path:  %s" % pcap_file)
        try:
            if pcap_file is not None:
                print("Checking for Group ID Management Actions Frame...")
                cap = self.read_pcap(pcap_file=pcap_file, apply_filter='wlan.mgt && wlan.vht.group_id_management')
                packet_count = 0
                value = "Frame Not Found"
                for pkt in cap:
                    if 'wlan.mgt' in pkt:
                        value = pkt['wlan.mgt'].get_field_value('wlan_vht_group_id_management')
                        if value is not None:
                            print("Group ID Management: ", value)
                            packet_count += 1
                        if packet_count == 1:
                            break
                if packet_count >= 1:
                    return {"Wireless Management - Group ID Management": str(value)}
                else:
                    return {"Wireless Management - Group ID Management": str(value)}
        except ValueError:
            raise "pcap file is required"

    def check_beamformee_association_request(self, pcap_file):
        print("pcap file path:  %s" % pcap_file)
        try:
            if pcap_file is not None:
                cap = self.read_pcap(pcap_file=pcap_file, apply_filter='wlan.vht.capabilities.mubeamformee == 1 &&  '
                                                                       'wlan.fc.type_subtype == 0')
                packet_count = 0
                value = "Frame Not Found"
                for pkt in cap:
                    if 'wlan.mgt' in pkt:
                        value = pkt['wlan.mgt'].get_field_value('wlan_vht_capabilities_mubeamformee')
                        if value is not None:
                            print(value)
                            packet_count += 1
                            if value == 0:
                                value = "Not Supported"
                            if value == 1:
                                value = "Supported"
                            if packet_count == 1:
                                break
                print(packet_count)
                if packet_count >= 1:
                    return {"Association Request - MU Beamformee Capable": value}
                else:
                    return {"Association Request - MU Beamformee Capable": value}
        except ValueError:
            raise "pcap file is required"

    def check_beamformer_association_response(self, pcap_file):
        try:
            if pcap_file is not None:
                cap = self.read_pcap(pcap_file=pcap_file, apply_filter='wlan.vht.capabilities.mubeamformer == 1 &&  '
                                                                       'wlan.fc.type_subtype == 1')
                packet_count = 0
                value = "Frame Not Found"
                for pkt in cap:
                    if 'wlan.mgt' in pkt:
                        value = pkt['wlan.mgt'].get_field_value('wlan_vht_capabilities_mubeamformer')
                        if value is not None:
                            print(value)
                            packet_count += 1
                            if value == 0:
                                value = "Not Supported"
                            if value == 1:
                                value = "Supported"
                            if packet_count == 1:
                                break
                if packet_count >= 1:
                    return {"Association Response -MU Beamformer Capable": value}
                else:
                    return {"Association Response -MU Beamformer Capable": value}
        except ValueError:
            raise "pcap file is required"

    def check_beamformer_beacon_frame(self, pcap_file):
        try:
            if pcap_file is not None:
                cap = self.read_pcap(pcap_file=pcap_file, apply_filter='wlan.fc.type_subtype == 8')
                packet_count = 0
                value = "Frame Not Found"
                for pkt in cap:
                    if 'wlan.mgt' in pkt:
                        value = pkt['wlan.mgt'].get_field_value('wlan_vht_capabilities_mubeamformer')
                        if value is not None:
                            print(value)
                            packet_count += 1
                            if value == 0:
                                value = "Not Supported"
                            if value == 1:
                                value = "Supported"
                            if packet_count == 1:
                                break
                if packet_count >= 1:
                    return {"Beacon Frame - MU Beamformer Capable": value}
                else:
                    return {"Beacon Frame - MU Beamformer Capable": value}
        except ValueError:
            raise "pcap file is required."

    def check_beamformer_report_poll(self, pcap_file):
        try:
            if pcap_file is not None:
                cap = self.read_pcap(pcap_file=pcap_file, apply_filter='wlan.fc.type_subtype == 20')
                packet_count = 0
                value = "Frame Not Found"
                for pkt in cap:
                    if 'wlan' in pkt:
                        value = pkt['wlan'].get_field_value('fc_type_subtype')
                        if value is not None:
                            print(value)
                            packet_count += 1
                            if packet_count == 1:
                                break
                if packet_count >= 1:
                    return {"Beamforming Report Poll ": value}
                else:
                    return {"Beamforming Report Poll ": value}
        except ValueError:
            raise "pcap file is required."

    def check_he_capability(self, pcap_file):
        try:
            if pcap_file is not None:
                cap = self.read_pcap(pcap_file=pcap_file, apply_filter='radiotap.he.data_1.ppdu_format')
                packet_count = 0
                for pkt in cap:
                    packet_count += 1
                if packet_count >= 1:
                    return True
                else:
                    return False
        except ValueError:
            raise "pcap file is required."

    def check_probe_request(self, pcap_file):
        try:
            if pcap_file is not None:
                cap = self.read_pcap(pcap_file=pcap_file, apply_filter='wlan.fc.type_subtype == 4')
                packet_count = 0
                for pkt in cap:
                    packet_count += 1
                if packet_count >= 1:
                    return True
                else:
                    return False
        except ValueError:
            raise "pcap file is required."

    def check_probe_response(self, pcap_file):
        try:
            if pcap_file is not None:
                cap = self.read_pcap(pcap_file=pcap_file, apply_filter='wlan.fc.type_subtype == 5')
                packet_count = 0
                for pkt in cap:
                    packet_count += 1
                if packet_count >= 1:
                    return True
                else:
                    return False
        except ValueError:
            raise "pcap file is required."

    def sniff_packets(self, interface_name="wiphy1", test_name="mu-mimo", channel=-1, sniff_duration=180):
        pcap_name = test_name + str(datetime.now().strftime("%Y-%m-%d-%H-%M")).replace(':', '-') + ".pcap"
        self.wifi_monitor.create(resource_=1, channel=channel, mode="AUTO", radio_=interface_name, name_="moni0")
        self.wifi_monitor.start_sniff(capname=pcap_name, duration_sec=sniff_duration)
        self.wifi_monitor.cleanup()
        return pcap_name

    def move_pcap(self, current_path, updated_path):
        lf_report.pull_reports(hostname=self.host, port=22, username="lanforge", password="lanforge",
                     report_location=current_path,
                     report_dir=updated_path)


def main():
    parser = argparse.ArgumentParser(
        prog='lf_pcap.py',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='Common Library for reading pcap files and check packet information for specific filters',
        description='''\
    """
-----------------------
NAME: lf_pcap.py

PURPOSE:
Common Library for reading pcap files and check packet information for specific filters

SETUP:
This script requires pyshark to be installed before,you can install it by running "pip install pyshark"

EXAMPLE:
see: /py-scritps/lf_pcap.py 
---------------------
''')
    parser.add_argument('--pcap_file', '-p', help='provide the pcap file path', dest="pcap_file",  default=None)
    parser.add_argument('--apply_filter', '-f', help='apply the filter you want to', dest='apply_filter', default=None)
    args = parser.parse_args()
    pcap_obj = LfPcap(
        host="192.168.100.131",
        port=8080,
        _read_pcap_file=args.pcap_file,
        _apply_filter=args.apply_filter,
        _live_filter=None,
        _live_pcap_interface=None,
        _live_remote_cap_host=None,
        _live_cap_timeout=None,
        _live_remote_cap_interface=None
    )
    # pcap_obj.check_group_id_mgmt(pcap_file=pcap_obj.pcap_file)
    # pcap_obj.check_beamformer_association_request(pcap_file=pcap_obj.pcap_file)
    # pcap_obj.check_beamformer_association_response(pcap_file=pcap_obj.pcap_file)
    # pcap_obj.check_beamformer_beacon_frame(pcap_file=pcap_obj.pcap_file)
    # pcap_obj.get_wlan_mgt_status_code(pcap_file=pcap_obj.pcap_file)
    # pcap_obj.get_packet_info(pcap_obj.pcap_file)
    pcap_obj.read_time(pcap_file="roam_11r_ota_iteration_0_2022-05-05-22-20.pcap")

if __name__ == "__main__":
    main()
