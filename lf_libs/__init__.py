import importlib
import json
import logging
import os
import sys
import time

import allure
import click
import paramiko
import pytest
import requests
import urllib3
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


class lf_libs:
    """
    "traffic_generator": {
            "name": "lanforge",
            "scenario": "",
            "details": {
                "manager_ip": "<ip-address>",
                "http_port": 8080,
                "ssh_port": 22,
                "default_setup_DB": "Test_Scenario",
                "wan_ports": ["1.1.eth2"],
                "lan_ports": ["1.1.eth1"]
            }
        }
    """
    lanforge_data = dict()
    manager_ip = None
    testbed = None
    manager_http_port = None
    manager_ssh_port = None
    manager_default_db = None
    wan_ports = None
    lan_ports = None
    uplink_nat_ports = None
    dut_data = None
    dut_objects = []
    default_scenario_name = None
    default_scenario_test = None
    default_scenario_raw_lines = []
    chamberview_object = None
    """
    Scenario : dhcp-bridge / dhcp-external
    dhcp-bridge -   wan_ports will act as dhcp server for AP's and it will use uplink_nat_ports for uplink NAT
                    lan_ports will have IP Address from the AP 
                    
    dhcp-external - wan_ports will have IP Address from the dhcp server that will be hosted outside the lanforge
                    lan_ports will have IP Address from the AP 
                    In case of VLAN configurations, wan_ports will be tagged to get IP Address 
                    from VLANS that are outside LANforge
    """
    scenario = None
    """
    Scenario in chamberview which will be read by read_cv_scenario() and stored here
    This will be used to add additional stuff on scenario along with this
    """
    cv_scenario = None
    """
    Number of Resources available
    """
    resources = None

    """
    ax radio - supports (2.4G and 5gHz Band)
    Maximum 1 Station per radio
    """

    ax200_radios = []

    """
    6e radio - supports (2.4GHz, 5gHz and 6gHz Band)
    Maximum 1 Station per radio
    """
    ax210_radios = []

    """
    ax radio - supports (2.4G and 5gHz Band)
    Maximum 19 Station per radio
    """
    mtk_radios = []

    """
    ax radio - supports (2.4G Band)
    Maximum 64 Station per radio
    """
    wave1_2g_radios = []

    """
    ax radio - supports (5gHz Band)
    Maximum 64 Station per radio
    """
    wave1_5g_radios = []

    """
    ax radio - supports (2.4G and 5gHz Band)
    Maximum 64 Station per radio
    """
    wave2_radios = []

    """
        ax radio - supports (2.4G and 5gHz Band)
        Maximum 64 Station per radio
        """
    attenuator = []

    """
    Realm Object can be used to call various methods available
    """
    local_realm = None

    def __init__(self, lf_data={}, dut_data=[], log_level=logging.DEBUG):
        logging.basicConfig(format='%(asctime)s - %(message)s', level=log_level)
        lf_data = dict(lf_data)
        self.dut_data = dut_data
        try:
            self.lanforge_data = lf_data.get("details")
            self.testbed = lf_data.get("testbed")
            self.setup_lf_data()
        except Exception as e:
            logging.error("lf_data has bad values: " + str(lf_data))
            logging.error(e)

    def setup_lf_data(self):
        try:
            self.manager_ip = self.lanforge_data.get("manager_ip")
            self.manager_http_port = self.lanforge_data.get("http_port")
            self.manager_ssh_port = self.lanforge_data.get("ssh_port")
            self.manager_default_db = self.lanforge_data.get("default_setup_DB")
            self.wan_ports = self.lanforge_data.get("wan_ports")
            self.lan_ports = self.lanforge_data.get("lan_ports")
            self.local_realm = realm.Realm(lfclient_host=self.manager_ip, lfclient_port=self.manager_http_port)
            self.chamberview_object = CreateChamberview(self.manager_ip, self.manager_http_port)
        except Exception as e:
            logging.error("lf_data has bad values: " + str(self.lanforge_data))
            logging.error(e)

    def setup_dut(self):
        for index in range(0, len(self.dut_data)):
            dut_obj = DUT(lfmgr=self.manager_ip,
                          port=self.manager_http_port,
                          dut_name=self.testbed + "-" + str(index),
                          sw_version=self.dut_data[index]["version"],
                          hw_version=self.dut_data[index]["mode"],
                          model_num=self.dut_data[index]["model"],
                          serial_num=self.dut_data[index]["serial"])
            dut_obj.setup()
            dut_obj.add_ssids()
            time.sleep(5)
            self.dut_objects.append(dut_obj)

    def setup_metadata(self):
        data = self.json_get("/port/all")
        all_eth_ports = []
        for info in data["interfaces"]:
            if (info[list(info.keys())[0]]["port type"]) == "Ethernet":
                all_eth_ports.append(list(dict(info).keys())[0])
        logging.debug("Available Ports: " + str(all_eth_ports))
        for port in self.wan_ports:
            if port not in all_eth_ports:
                logging.error("LANforge system doesn't contains the expected WAN Port:  " + str(port))
                continue
            logging.debug("WAN Port is Available on LANforge Port Manager: " + str(port))
        for port in self.lan_ports:
            if port not in all_eth_ports:
                logging.error("LANforge system doesn't contains the expected LAN Port:  " + str(port))
                continue
            logging.debug("LAN Port is Available on LANforge Port Manager: " + str(port))
        data = self.json_get("/radiostatus/all")
        all_radios = []
        all_radio_eid = []
        max_possible_stations = 0
        max_2g_stations = 0
        max_5g_stations = 0
        max_6g_stations = 0
        max_ax_stations = 0
        max_ac_stations = 0
        phantom_radios = []
        for info in data:
            if info == "handler" or info == "uri" or info == "warnings":
                continue
            all_radio_eid.append(info)
            all_radios.append(data[info])
            if str(data[info]["phantom"]).__contains__("True"):
                phantom_radios.append(str(data[info]["entity id"]))
                logging.error("Radio is in phantom state: " + str(data[info]["entity id"]) +
                              " ,Please Contact: support@candelatech.com")
            if str(data[info]["driver"]).__contains__("AX210"):
                max_possible_stations += 1
                max_2g_stations += 1 * int(str(data[info]["max_vifs"]))
                max_5g_stations += 1 * int(str(data[info]["max_vifs"]))
                max_6g_stations += 1 * int(str(data[info]["max_vifs"]))
                max_ax_stations += 1 * int(str(data[info]["max_vifs"]))
                self.ax210_radios.append(info)
            if str(data[info]["driver"]).__contains__("AX200"):
                max_possible_stations += 1 * int(str(data[info]["max_vifs"]))
                max_2g_stations += 1 * int(str(data[info]["max_vifs"]))
                max_5g_stations += 1 * int(str(data[info]["max_vifs"]))
                max_ax_stations += 1 * int(str(data[info]["max_vifs"]))
                self.ax200_radios.append(info)
            if str(data[info]["driver"]).__contains__("ath10k(988x)"):
                max_possible_stations += 1 * int(str(data[info]["max_vifs"]))
                max_2g_stations += 1 * int(str(data[info]["max_vifs"]))
                max_5g_stations += 1 * int(str(data[info]["max_vifs"]))
                max_ac_stations += 1 * int(str(data[info]["max_vifs"]))
                self.wave2_radios.append(info)
            if str(data[info]["driver"]).__contains__("ath10k(9984)"):
                if str(data[info]["capabilities"]).__contains__("802.11bgn-AC"):
                    max_possible_stations += 1 * int(str(data[info]["max_vifs"]))
                    max_2g_stations += 1 * int(str(data[info]["max_vifs"]))
                    max_ac_stations += 1 * int(str(data[info]["max_vifs"]))
                    self.wave1_2g_radios.append(info)
                if str(data[info]["capabilities"]).__contains__("802.11an-AC"):
                    max_possible_stations += 1 * int(str(data[info]["max_vifs"]))
                    max_5g_stations += 1 * int(str(data[info]["max_vifs"]))
                    max_ac_stations += 1 * int(str(data[info]["max_vifs"]))
                    self.wave1_5g_radios.append(info)
            if str(data[info]["driver"]).__contains__("mt7915e"):
                max_possible_stations += 1 * int(str(data[info]["max_vifs"]))
                max_2g_stations += 1 * int(str(data[info]["max_vifs"]))
                max_5g_stations += 1 * int(str(data[info]["max_vifs"]))
                max_ax_stations += 1 * int(str(data[info]["max_vifs"]))
                self.mtk_radios.append(info)
        logging.debug("Radio Information is Extracted")
        logging.debug("Available Radios: " + str(all_radio_eid) + "  -  Phantom Radios: " + str(phantom_radios))
        logging.debug("max_possible_stations: " + str(max_possible_stations))
        logging.debug("max_2g_stations: " + str(max_2g_stations))
        logging.debug("max_5g_stations: " + str(max_5g_stations))
        logging.debug("max_6g_stations: " + str(max_6g_stations))
        logging.debug("max_ax_stations: " + str(max_ax_stations))
        logging.debug("max_ac_stations: " + str(max_ac_stations))

    def load_scenario(self):
        self.local_realm.load(self.manager_default_db)

    def json_get(self, _req_url="/"):
        cli_base = LFCliBase(_lfjson_host=self.manager_ip, _lfjson_port=self.manager_http_port)
        json_response = cli_base.json_get(_req_url=_req_url)
        return json_response

    def json_post(self, _req_url="/"):
        cli_base = LFCliBase(_lfjson_host=self.manager_ip, _lfjson_port=self.manager_http_port)
        json_response = cli_base.json_post(_req_url=_req_url)
        return json_response

    def read_cv_scenario(self):
        cv_obj = cv_test(lfclient_host=self.manager_ip, lfclient_port=self.manager_http_port)
        cv_obj.show_text_blob(type="Last-Built-Scenario")
        data = self.json_get("/text/Last-Built-Scenario.last_built")
        data = data['record']['text'].split("\n")
        for d in data:
            if "scenario-name" in d:
                self.default_scenario_name = d.split(":")[1][1:]
        cv_obj.apply_cv_scenario(self.default_scenario_name)
        time.sleep(2)
        cv_obj.show_text_blob(type="Network-Connectivity")
        data = self.json_get("/text/Network-Connectivity." + str(self.default_scenario_name))
        data = data["record"]["text"].split("\n")
        for d in data:
            if "profile_link" in d:
                self.default_scenario_raw_lines.append([d])
        logging.info("Saved default CV Scenario details: " + str(self.default_scenario_raw_lines))

    def setup_relevent_profiles(self):
        """ TODO
             Read all Profiles
             Create upstream-dhcp and uplink-nat profile if they don't exists
             Create VLAN Based profiles
             Create 2 Profiles for vlan
             vlan profile with dhcp server
             vlan profile without dhcp server
        """
        pass


class lf_tests(lf_libs):

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


class Report:
    def __init__(self, key1=None,
                 key2=None,
                 val1=None,
                 val2=None):
        self.key1 = key1
        self.key2 = key2
        self.val1 = val1
        self.val2 = val2

    def table1(self):
        table = {str(self.key1): self.val1, str(self.key2): self.val2}
        x = tabulate(table, headers="keys", tablefmt="fancy_grid")
        return x

    def table2(self, table=None, headers='firstrow', tablefmt='fancy_grid'):
        self.table = table
        x = tabulate(self.table, headers=headers, tablefmt=tablefmt)
        return x


class SCP_File:
    def __init__(self, ip="localhost", port=22, username="lanforge", password="lanforge", remote_path="/home/lanforge/",
                 local_path="."):
        self.ip = ip
        self.port = port
        self.remote_path = remote_path
        self.local_path = local_path
        self.username = username
        self.password = password

    def pull_file(self):
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=self.ip, username=self.username, password=self.password, port=self.port, allow_agent=False,
                    look_for_keys=False)
        # ssh.close()

        with SCPClient(ssh.get_transport()) as scp:
            scp.get(remote_path=self.remote_path, local_path=self.local_path, recursive=True)
            scp.close()


class lf_tools(lf_libs):

    def __init__(self, lf_data={}, dut_data={}, log_level=logging.DEBUG):
        super().__init__(lf_data, dut_data, log_level)
        pass

    def create_stations(self):
        pass

    def delete_stations(self):
        pass

    def modify_station(self):
        pass

    def read_stations(self):
        pass

    def start_sniffer(self):
        pass

    def pull_reports(self):
        pass

    def get_wifi_radios(self):
        pass

    def modify_wifi_radio(self):
        pass

    def load_scenario_db(self):
        pass

    def delete_dut(self):
        pass

    def read_dut(self):
        pass

    def update_dut(self):
        pass

    def get_ethernet_ports(self):
        pass

    def set_ethernet_port(self):
        pass

    def clean_port_manager(self):
        pass

    def clean_layer3cx(self):
        pass

    def add_vlan(self, vlan_ids=[]):
        data = self.json_get("/port/all")
        flag = 0
        temp_raw_lines = self.default_scenario_raw_lines
        for port in self.wan_ports:
            for vlans in vlan_ids:
                for i in data["interfaces"]:
                    if list(i.keys())[0] != port + "." + str(vlans):
                        flag = 1
            if flag == 1:
                for vlans in vlan_ids:
                    temp_raw_lines.append(["profile_link " + port + " vlan-100 1 " + port
                                           + " NA " + port.split(".")[2] + ",AUTO -1 " + str(vlans)])
                print(temp_raw_lines)
                exit()
                self.chamber_view(raw_lines=temp_raw_lines)

    def chamber_view(self, delete_old_scenario=True, raw_lines=[]):
        print(self.chamberview_object)
        if delete_old_scenario:
            self.chamberview_object.clean_cv_scenario(scenario_name=self.default_scenario_name)
        self.chamberview_object.setup(create_scenario=self.default_scenario_name,
                                      raw_line=self.default_scenario_raw_lines
                                      )
        self.chamberview_object.build(self.default_scenario_name)
        self.chamberview_object.sync_cv()
        time.sleep(2)
        self.chamberview_object.show_text_blob(None, None, True)  # Show changes on GUI
        self.chamberview_object.sync_cv()
        return self.chamberview_object, self.default_scenario_name


if __name__ == '__main__':
    basic_02 = {
        "controller": {
            "url": "https://sec-qa01.cicd.lab.wlan.tip.build:16001",
            "username": "tip@ucentral.com",
            "password": "OpenWifi%123"
        },
        "access_point": [
            {
                "model": "hfcl_ion4",
                "mode": "wifi5",
                "serial": "0006aee53b84",
                "jumphost": True,
                "ip": "10.28.3.100",
                "username": "lanforge",
                "password": "pumpkin77",
                "port": 22,
                "jumphost_tty": "/dev/ttyAP2",
                "version": "next-latest"
            }
        ],
        "traffic_generator": {
            "name": "lanforge",
            "testbed": "basic",
            "scenario": "dhcp-bridge",  # dhcp-bridge / dhcp-external
            "details": {
                "manager_ip": "192.168.52.89",
                "http_port": 8080,
                "ssh_port": 22,
                "default_setup_DB": "Test_Scenario",
                "wan_ports": ["1.1.eth3"],
                "lan_ports": ["1.1.eth1"],
                "uplink_nat_ports": ["1.1.eth2"]
            }
        }
    }

    obj = lf_tools(lf_data=dict(basic_02["traffic_generator"]), dut_data=list(basic_02["access_point"]))
    obj.setup_metadata()
    obj.load_scenario()
    obj.read_cv_scenario()
    obj.setup_dut()
