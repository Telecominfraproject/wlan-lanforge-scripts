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
profile_utility = importlib.import_module("py-json.profile_utility")
ProfileUtility = profile_utility.ProfileUtility


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
    raw_line = None
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
            self.scenario = lf_data.get("scenario")
            self.setup_lf_data()
            self.load_scenario()
            self.setup_metadata()
            self.setup_dut()
        except Exception as e:
            logging.error("lf_data has bad values: " + str(lf_data))
            logging.error(e)

    """
        setup_lf_data : used to set object variables that are passed from lab_info.json
                        It also creates object for realm and CreateChamberview class object
                         which can be used further
    """

    def setup_lf_data(self):
        try:
            self.manager_ip = self.lanforge_data.get("manager_ip")
            self.manager_http_port = self.lanforge_data.get("http_port")
            self.manager_ssh_port = self.lanforge_data.get("ssh_port")
            self.manager_default_db = self.lanforge_data.get("default_setup_DB")
            self.wan_ports = self.lanforge_data.get("wan_ports")
            self.lan_ports = self.lanforge_data.get("lan_ports")
            self.uplink_nat_ports = self.lanforge_data.get("uplink_nat_ports")
            self.local_realm = realm.Realm(lfclient_host=self.manager_ip, lfclient_port=self.manager_http_port)
            self.chamberview_object = CreateChamberview(self.manager_ip, self.manager_http_port)
        except Exception as e:
            logging.error("lf_data has bad values: " + str(self.lanforge_data))
            logging.error(e)

    """
        setup_dut : It read the dut data and creates the dut with relevent data
    """

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
        logging.info("Available Ports: " + str(all_eth_ports))
        for port in self.wan_ports:
            if port not in all_eth_ports:
                logging.error("LANforge system doesn't contains the expected WAN Port:  " + str(port))
                continue
            logging.info("WAN Port is Available on LANforge Port Manager: " + str(port))
        for port in self.lan_ports:
            if port not in all_eth_ports:
                logging.error("LANforge system doesn't contains the expected LAN Port:  " + str(port))
                continue
            logging.info("LAN Port is Available on LANforge Port Manager: " + str(port))
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
        logging.info("Radio Information is Extracted")
        logging.info("Available Radios: " + str(all_radio_eid) + "  -  Phantom Radios: " + str(phantom_radios))
        logging.info("max_possible_stations: " + str(max_possible_stations))
        logging.info("max_2g_stations: " + str(max_2g_stations))
        logging.info("max_5g_stations: " + str(max_5g_stations))
        logging.info("max_6g_stations: " + str(max_6g_stations))
        logging.info("max_ax_stations: " + str(max_ax_stations))
        logging.info("max_ac_stations: " + str(max_ac_stations))

    def load_scenario(self):
        self.local_realm.load(self.manager_default_db)

    def create_dhcp_bridge(self):
        """ create chamber view scenario"""
        #testing is pending
        upstream_port = self.uplink_nat_ports
        upstream_resources = upstream_port.split(".")[0] + "." + upstream_port.split(".")[1]
        uplink_port = self.wan_ports
        uplink_resources = uplink_port.split(".")[0] + "." + uplink_port.split(".")[1]
        self.raw_line = [
            ["profile_link " + upstream_resources + " upstream-dhcp 1 NA NA " + upstream_port.split(".")[2]
             + ",AUTO -1 NA"],
            ["profile_link " + uplink_resources + " uplink-nat 1 'DUT: upstream LAN " + upstream_subnet
             + "' NA " + uplink_port.split(".")[2] + "," + upstream_port.split(".")[2] + " -1 NA"]
        ]
        self.chamber_view(delete_old_scenario=True, raw_lines=self.raw_line)
        pass

    def create_dhcp_external(self):
        pass

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
        profile_utility_obj = ProfileUtility(lfclient_host=self.manager_ip, lfclient_port=self.manager_http_port)
        # Read all Profiles
        all_profiles = profile_utility_obj.show_profile()
        print(all_profiles)
        logging.info("Profiles: " + str(all_profiles))

        # Create upstream-dhcp and uplink-nat profile if they don't exists
        # Checking availability of upstream-dhcp profile
        upstream_dhcp = profile_utility_obj.check_profile(profile_name="upstream-dhcp")
        # Checking availability of uplink-nat profile
        uplink_nat = profile_utility_obj.check_profile(profile_name="uplink-nat")
        if upstream_dhcp:
            logging.info("upstream_dhcp profile: Available")
            profile_utility_obj.remove_profile(name="upstream-dhcp")
            profile_utility_obj.add_profile(profile_name="upstream-dhcp", profile_type="upstream",
                                            profile_flags="DHCP-SERVER")
        else:
            profile_utility_obj.add_profile(profile_name="upstream-dhcp", profile_type="upstream",
                                            profile_flags="DHCP-SERVER")
        if uplink_nat:
            profile_utility_obj.remove_profile(name="uplink-nat")
            profile_utility_obj.add_profile(profile_name="uplink-nat", profile_type="uplink", profile_flags=None)
        else:
            profile_utility_obj.add_profile(profile_name="uplink-nat", profile_type="uplink", profile_flags=None)

        # Create VLAN Based profiles
        if self.scenario == "dhcp-bridge":
            vlan_dhcp_profile = profile_utility_obj.check_profile(profile_name="vlan_dhcp_profile")
            if vlan_dhcp_profile:
                profile_utility_obj.remove_profile(name="vlan_dhcp_profile")
                profile_utility_obj.add_profile(profile_name="vlan_dhcp_profile", profile_type="vlan",
                                                profile_flags="DHCP-SERVER")
            else:
                profile_utility_obj.add_profile(profile_name="vlan_dhcp_profile", profile_type="vlan",
                                                profile_flags="DHCP-SERVER")

        elif self.scenario == "dhcp-external":
            vlan_profile = profile_utility_obj.check_profile(profile_name="vlan_profile")
            if vlan_profile:
                profile_utility_obj.remove_profile(name="vlan_profile")
                profile_utility_obj.add_profile(profile_name="vlan_profile", profile_type="vlan", profile_flags=None)
            else:
                profile_utility_obj.add_profile(profile_name="vlan_profile", profile_type="vlan", profile_flags=None)

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
        profile_name = ""
        temp_raw_lines = self.default_scenario_raw_lines
        for port in self.wan_ports:
            for vlans in vlan_ids:
                for i in data["interfaces"]:
                    print(i)
                    if list(i.keys())[0] != port + "." + str(vlans):
                        flag = 1
            if flag == 1:
                for vlans in vlan_ids:
                    if self.scenario == "dhcp-bridge":
                        profile_name = "vlan_dhcp_profile"
                    elif self.scenario == "dhcp-external":
                        profile_name = "vlan_profile"
                    temp_raw_lines.append(["profile_link " + port + " " + profile_name + " 1 " + port
                                           + " NA " + port.split(".")[2] + ",AUTO -1 " + str(vlans)])
                print(temp_raw_lines)
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

    def setup_radius_server(self, user=""):
        """
            TODO:
                setup freeradius server on lanforge and return the radius server data
                setup the radius server for basic EAP-TLS and EAP-TTLS encryptions
            Special Radius configurations can be done in later implementations
            Radius server should be working properly on WAN Interface of AP
        """
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
                "manager_ip": "10.28.3.12",
                "http_port": 8080,
                "ssh_port": 22,
                "default_setup_DB": "Test_Scenario",
                "wan_ports": ["1.1.eth3"],
                "lan_ports": ["1.1.eth1"],
                "uplink_nat_ports": ["1.1.eth2"]
            }
        }
    }

    obj = lf_libs(lf_data=dict(basic_02["traffic_generator"]), dut_data=list(basic_02["access_point"]),
                  log_level=logging.DEBUG)
    # x = obj.chamber_view()
    # print(x)
    # obj.add_vlan(vlan_ids=[100,200])
    # # obj.setup_dut()
    # obj.setup_relevent_profiles()
    # obj.add_vlan(vlan_ids=[200])
    # obj.chamber_view()
