import importlib
import logging
import os
import sys
import time

import allure
import paramiko
import pytest
from scp import SCPClient
from tabulate import tabulate

sys.path.append(os.path.join(os.path.abspath(__file__ + "../../../")))
lfcli_base = importlib.import_module("py-json.LANforge.lfcli_base")
LFCliBase = lfcli_base.LFCliBase
realm = importlib.import_module("py-json.realm")
cv_test_manager = importlib.import_module("py-json.cv_test_manager")
cv_test = cv_test_manager.cv_test
lf_cv_base = importlib.import_module("py-json.lf_cv_base")
ChamberViewBase = lf_cv_base.ChamberViewBase
create_chamberview_dut = importlib.import_module("py-scripts.create_chamberview_dut")
DUT = create_chamberview_dut.DUT
create_chamberview = importlib.import_module("py-scripts.create_chamberview")
CreateChamberview = create_chamberview.CreateChamberview
sta_connect2 = importlib.import_module("py-scripts.sta_connect2")
StaConnect2 = sta_connect2.StaConnect2
lf_library = importlib.import_module("lf_libs")
lf_libs = lf_library.lf_libs
Report = lf_library.Report
SCP_File = lf_library.SCP_File


class lf_tests(lf_libs):
    """
        lf_tools is needed in lf_tests to do various operations needed by various tests
    """
    lf_tools_obj = None

    def __init__(self, lf_data={}, dut_data={}, log_level=logging.DEBUG):
        super().__init__(lf_data, dut_data, log_level)
        pass

    def client_connectivity_test(self, ssid="[BLANK]", passkey="[BLANK]", security="open", extra_securities=[],
                                 station_name=[], mode="BRIDGE", vlan_id=1, band="twog", ssid_channel=None):
        self.staConnect = StaConnect2(self.manager_ip, self.manager_http_port, debug_=self.debug)

        self.staConnect.sta_mode = 0
        self.staConnect.upstream_resource = self.upstream_resource
        if mode == "BRIDGE":
            self.staConnect.upstream_port = self.upstream_port
        elif mode == "NAT":
            self.staConnect.upstream_port = self.upstream_port
        else:
            self.staConnect.upstream_port = self.upstream_port + "." + str(vlan_id)
        if band == "twog":
            if self.run_lf:
                ssid = self.ssid_data["2g-ssid"]
                passkey = self.ssid_data["2g-password"]
                security = self.ssid_data["2g-encryption"].lower()
                print(ssid)
            self.staConnect.radio = self.twog_radios[0]
            self.staConnect.admin_down(self.staConnect.radio)
            self.staConnect.admin_up(self.staConnect.radio)
            self.staConnect.sta_prefix = self.twog_prefix
        if band == "fiveg":
            if self.run_lf:
                ssid = self.ssid_data["5g-ssid"]
                passkey = self.ssid_data["5g-password"]
                security = self.ssid_data["5g-encryption"].lower()
            self.staConnect.radio = self.fiveg_radios[0]
            self.staConnect.reset_port(self.staConnect.radio)
            self.staConnect.sta_prefix = self.fiveg_prefix
        self.set_radio_channel(radio=self.staConnect.radio, channel=ssid_channel)
        print("scan ssid radio", self.staConnect.radio.split(".")[2])
        self.data_scan_ssid = self.scan_ssid(radio=self.staConnect.radio.split(".")[2])
        print("ssid scan data :- ", self.data_scan_ssid)
        result = self.check_ssid_available_scan_result(scan_ssid_data=self.data_scan_ssid, ssid=ssid)
        print("ssid available:-", result)
        if not result and ssid_channel:
            if not self.skip_pcap:
                print("sniff radio", self.ax_radios[0].split(".")[2])
                self.start_sniffer(radio_channel=ssid_channel, radio=self.ax_radios[0].split(".")[2], duration=30)
                time.sleep(30)
                self.stop_sniffer()
            print("ssid not available in scan result")
            return "FAIL", "ssid not available in scan result"
        self.staConnect.resource = 1
        self.staConnect.dut_ssid = ssid
        self.staConnect.dut_passwd = passkey
        self.staConnect.dut_security = security
        self.staConnect.station_names = station_name
        self.staConnect.runtime_secs = 40
        self.staConnect.bringup_time_sec = 80
        self.staConnect.cleanup_on_exit = True
        data_table = ""
        dict_table = {}
        self.staConnect.setup(extra_securities=extra_securities)
        for sta_name in self.staConnect.station_names:
            try:
                sta_url = self.staConnect.get_station_url(sta_name)
                station_info = self.staConnect.json_get(sta_url)
                dict_data = station_info["interface"]
                dict_table[""] = list(dict_data.keys())
                dict_table["Before"] = list(dict_data.values())
            except Exception as e:
                print(e)
        if ssid_channel:
            if not self.skip_pcap:
                print("sniff radio", self.ax_radios[0].split(".")[2])
                self.start_sniffer(radio_channel=ssid_channel, radio=self.ax_radios[0].split(".")[2], duration=30)
        self.staConnect.start()
        print("napping %f sec" % self.staConnect.runtime_secs)
        time.sleep(self.staConnect.runtime_secs)
        report_obj = Report()
        for sta_name in self.staConnect.station_names:
            try:
                sta_url = self.staConnect.get_station_url(sta_name)
                station_info = self.staConnect.json_get(sta_url)
                self.station_ip = station_info["interface"]["ip"]
                dict_data = station_info["interface"]
                dict_table["After"] = list(dict_data.values())
                try:
                    data_table = report_obj.table2(table=dict_table, headers='keys')
                except Exception as e:
                    print(e)
                allure.attach(name=str(sta_name), body=data_table)
            except Exception as e:
                print(e)
        self.staConnect.stop()
        run_results = self.staConnect.get_result_list()
        if not self.staConnect.passes():
            if self.debug:
                for result in run_results:
                    print("test result: " + result)
                pytest.exit("Test Failed: Debug True")
        self.staConnect.cleanup()
        try:
            supplicant = "/home/lanforge/wifi/wpa_supplicant_log_" + self.staConnect.radio.split(".")[2] + ".txt"
            obj = SCP_File(ip=self.manager_ip, port=self.manager_ssh_port, username="root", password="lanforge",
                           remote_path=supplicant,
                           local_path=".")
            obj.pull_file()
            allure.attach.file(source="wpa_supplicant_log_" + self.staConnect.radio.split(".")[2] + ".txt",
                               name="supplicant_log")
        except Exception as e:
            print(e)

        for result in run_results:
            print("test result: " + result)
        result = "PASS"
        description = "Unknown error"
        dict_table = {}
        print("Client Connectivity :", self.staConnect.passes)
        endp_data = []
        for i in self.staConnect.resulting_endpoints:
            endp_data.append(self.staConnect.resulting_endpoints[i]["endpoint"])
        dict_table["key"] = [i for s in [d.keys() for d in endp_data] for i in s]
        dict_table["value"] = [i for s in [d.values() for d in endp_data] for i in s]
        data_table = report_obj.table2(table=dict_table, headers='keys')
        allure.attach(name="cx_data", body=data_table)
        for i in range(len(run_results)):
            if i == 0:
                if "FAILED" in run_results[i]:
                    result = "FAIL"
                    description = "Station did not get an ip"
                    break
            else:
                if "FAILED" in run_results[i]:
                    result = "FAIL"
                    description = "did not report traffic"

        if self.staConnect.passes():
            print("client connection to", self.staConnect.dut_ssid, "successful. Test Passed")
            result = "PASS"
        else:
            print("client connection to", self.staConnect.dut_ssid, "unsuccessful. Test Failed")
            result = "FAIL"
        time.sleep(3)
        if ssid_channel:
            if not self.skip_pcap:
                self.stop_sniffer()
        self.set_radio_channel(radio=self.staConnect.radio, channel="AUTO")
        return result, description

    def enterprise_client_connectivity_test(self):
        pass

    def wifi_capacity_test(self):
        pass

    def dataplane_throughput_test(self):
        pass

    def rate_vs_range_test(self):
        pass

    def multiband_performance_test(self):
        pass

    def multi_psk_test(self):
        pass


if __name__ == '__main__':
    basic_1 = {
        "target": "tip_2x",
        "controller": {
            "url": "https://sec-qa01.cicd.lab.wlan.tip.build:16001",
            "username": "tip@ucentral.com",
            "password": "OpenWifi%123"
        },
        "device_under_tests": [{
            "model": "edgecore_eap101",
            "supported_bands": ["2G", "5G"],
            "supported_modes": ["BRIDGE", "NAT", "VLAN"],
            "mode": "wifi6",
            "identifier": "c44bd1005b30",
            "serial_port": True,
            "host_ip": "10.28.3.100",
            "host_username": "lanforge",
            "host_password": "pumpkin77",
            "host_ssh_port": 22,
            "serial_tty": "/dev/ttyAP8",
            "firmware_version": "next-latest"
        }],
        "traffic_generator": {
            "name": "lanforge",
            "testbed": "basic",
            "scenario": "dhcp-bridge",  # dhcp-bridge / dhcp-external
            "details": {
                "manager_ip": "192.168.52.89",
                "http_port": 8080,
                "ssh_port": 22,
                "setup": {"method": "build" , "DB": "Test_Scenario_Automation"},    # method: build/load,
                                                                                    # DB : Default database name
                "wan_ports": {
                    "1.1.eth3": {"addressing": "dhcp-server", "subnet": "172.16.0.1/16", "dhcp": {
                                    "lease-first": 10,
                                    "lease-count": 10000,
                                    "lease-time": "6h"
                                  }}
                },
                "lan_ports": {
                    "1.1.eth1": {"addressing": "dynamic"}  # dhcp-server/{"addressing": "dynamic"}/{"addressing":
                    # "static", "subnet": "10.28.2.6/16"}
                },
                "uplink_nat_ports": {
                    "1.1.eth2": {"addressing": "static", "subnet": "10.28.2.6/16"}   # dhcp-server/{"addressing":
                    # "dynamic"} /{"addressing": "static", "subnet": "10.28.2.6/16"}
                },
            }
        }
    }

    obj = lf_tests(lf_data=dict(basic_1["traffic_generator"]), dut_data=list(basic_1["device_under_tests"]),
                   log_level=logging.DEBUG)
    # obj.read_cv_scenario()
    # obj.setup_dut()
