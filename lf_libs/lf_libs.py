import importlib
import logging
import os
import sys
import time
from datetime import datetime
import allure
import paramiko
import pytest
from scp import SCPClient
from tabulate import tabulate
from itertools import islice
import csv

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
createstation = importlib.import_module("py-scripts.create_station")
CreateStation = createstation.CreateStation
sniffradio = importlib.import_module("py-scripts.lf_sniff_radio")
SniffRadio = sniffradio.SniffRadio
stascan = importlib.import_module("py-scripts.sta_scan_test")
StaScan = stascan.StaScan
cv_test_reports = importlib.import_module("py-json.cv_test_reports")
lf_report = cv_test_reports.lanforge_reports

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
    max_possible_stations = None
    max_2g_stations = None
    max_5g_stations = None
    max_6g_stations = None
    max_ax_stations = None
    max_ac_stations = None
    twog_prefix = "ath10k_2g0"
    fiveg_prefix = "ath10k_5g0"
    sixg_prefix = "AX210_0"
    ax_prefix = "AX200_0"
    pcap_obj = None
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
    wave2_2g_radios = []

    """
    ax radio - supports (5gHz Band)
    Maximum 64 Station per radio
    """
    wave2_5g_radios = []

    """
    ax radio - supports (2.4G and 5gHz Band)
    Maximum 64 Station per radio
    """
    wave1_radios = []

    """lf_tests
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
        # try:
        self.lanforge_data = lf_data.get("details")
        self.testbed = lf_data.get("testbed")
        self.scenario = lf_data.get("scenario")
        self.setup_lf_data()
        self.setup_relevent_profiles()
        # self.load_scenario()
        self.setup_metadata()
        if self.scenario == "dhcp-bridge":
            logging.info("Scenario name: " + str(self.scenario))
            # creating default  raw lines for chamberview
            self.create_dhcp_bridge()
        elif self.scenario == "dhcp-external":
            logging.info("Scenario name: " + str(self.scenario))
            self.create_dhcp_external()
        self.chamber_view(raw_lines=self.default_scenario_raw_lines)
        self.setup_dut()

        # except Exception as e:
        logging.error("lf_data has bad values: " + str(lf_data))
        # logging.error(e)

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
            self.default_scenario_raw_lines = []
        except Exception as e:

            logging.error(e)

    """
        setup_dut : It read the dut data and creates the dut with relevent data
    """

    def setup_dut(self):
        for index in range(0, len(self.dut_data)):
            dut_obj = DUT(lfmgr=self.manager_ip,
                          port=self.manager_http_port,
                          dut_name=self.testbed + "-" + str(index),
                          sw_version=self.dut_data[index]["firmware_version"],
                          hw_version=self.dut_data[index]["mode"],
                          model_num=self.dut_data[index]["model"],
                          serial_num=self.dut_data[index]["identifier"])
            dut_obj.setup()
            dut_obj.add_ssids()
            logging.info("Creating DUT")

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
        self.max_possible_stations = 0
        self.max_2g_stations = 0
        self.max_5g_stations = 0
        self.max_6g_stations = 0
        self.max_ax_stations = 0
        self.max_ac_stations = 0
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
                self.max_possible_stations += 1
                self.max_2g_stations += 1 * int(str(data[info]["max_vifs"]))
                self.max_5g_stations += 1 * int(str(data[info]["max_vifs"]))
                self.max_6g_stations += 1 * int(str(data[info]["max_vifs"]))
                self.max_ax_stations += 1 * int(str(data[info]["max_vifs"]))
                self.ax210_radios.append(info)
            if str(data[info]["driver"]).__contains__("AX200"):
                self.max_possible_stations += 1 * int(str(data[info]["max_vifs"]))
                self.max_2g_stations += 1 * int(str(data[info]["max_vifs"]))
                self.max_5g_stations += 1 * int(str(data[info]["max_vifs"]))
                self.max_ax_stations += 1 * int(str(data[info]["max_vifs"]))
                self.ax200_radios.append(info)
            if str(data[info]["driver"]).__contains__("ath10k(988x)"):
                self.max_possible_stations += 1 * int(str(data[info]["max_vifs"]))
                self.max_2g_stations += 1 * int(str(data[info]["max_vifs"]))
                self.max_5g_stations += 1 * int(str(data[info]["max_vifs"]))
                self.max_ac_stations += 1 * int(str(data[info]["max_vifs"]))
                self.wave1_radios.append(info)
            if str(data[info]["driver"]).__contains__("ath10k(9984)"):
                if str(data[info]["capabilities"]).__contains__("802.11bgn-AC"):
                    self.max_possible_stations += 1 * int(str(data[info]["max_vifs"]))
                    self.max_2g_stations += 1 * int(str(data[info]["max_vifs"]))
                    self.max_ac_stations += 1 * int(str(data[info]["max_vifs"]))
                    self.wave2_2g_radios.append(info)
                if str(data[info]["capabilities"]).__contains__("802.11an-AC"):
                    self.max_possible_stations += 1 * int(str(data[info]["max_vifs"]))
                    self.max_5g_stations += 1 * int(str(data[info]["max_vifs"]))
                    self.max_ac_stations += 1 * int(str(data[info]["max_vifs"]))
                    self.wave2_5g_radios.append(info)
            if str(data[info]["driver"]).__contains__("mt7915e"):
                self.max_possible_stations += 1 * int(str(data[info]["max_vifs"]))
                self.max_2g_stations += 1 * int(str(data[info]["max_vifs"]))
                self.max_5g_stations += 1 * int(str(data[info]["max_vifs"]))
                self.max_ax_stations += 1 * int(str(data[info]["max_vifs"]))
                self.mtk_radios.append(info)
        logging.info("Radio Information is Extracted")
        logging.info("Available Radios: " + str(all_radio_eid) + "  -  Phantom Radios: " + str(phantom_radios))
        logging.info("max_possible_stations: " + str(self.max_possible_stations))
        logging.info("max_2g_stations: " + str(self.max_2g_stations))
        logging.info("max_5g_stations: " + str(self.max_5g_stations))
        logging.info("max_6g_stations: " + str(self.max_6g_stations))
        logging.info("max_ax_stations: " + str(self.max_ax_stations))
        logging.info("max_ac_stations: " + str(self.max_ac_stations))

    def load_scenario(self):
        self.local_realm.load(self.manager_default_db)

    def setup_connectivity_port(self, data=None):
        """setting up ethernet port"""
        if len(data) == 0:
            return
        for eth_port in data:
            if data[eth_port]["addressing"] == "dhcp-server":
                return
            elif data[eth_port]["addressing"] == "static":
                try:
                    data = {
                        "shelf": eth_port.split(".")[0],
                        "resource": eth_port.split(".")[1],
                        "port": eth_port.split(".")[2],
                        "ip_addr": data[eth_port]["ip"].split("/")[0],
                        "netmask": data[eth_port]["ip_mask"],
                        "gateway": data[eth_port]["gateway_ip"].split("/")[0],
                        "dns_servers": data[eth_port]["dns_servers"],
                        "current_flags": 562949953421312,
                        "interest": 0x401e

                    }
                    self.json_post("/cli-json/set_port", data)
                    time.sleep(1)
                except Exception as e:
                    logging.error(e)
            elif data[eth_port]["addressing"] == "dynamic":
                try:
                    data = {
                        "shelf": eth_port.split(".")[0],
                        "resource": eth_port.split(".")[1],
                        "port": eth_port.split(".")[2],
                        "current_flags": 2147483648,
                        "interest": 16384
                    }
                    self.json_post("/cli-json/set_port", data)
                    time.sleep(1)
                except Exception as e:
                    logging.error(e)

    def create_dhcp_bridge(self):
        """ create chamber view scenario for DHCP-Bridge"""
        self.setup_connectivity_port(data=self.wan_ports)
        self.setup_connectivity_port(data=self.lan_ports)
        self.setup_connectivity_port(data=self.uplink_nat_ports)
        for wan_ports, uplink_nat_ports in zip(self.wan_ports, self.uplink_nat_ports):
            upstream_port = wan_ports
            upstream_resources = upstream_port.split(".")[0] + "." + upstream_port.split(".")[1]
            uplink_port = uplink_nat_ports
            uplink_resources = uplink_port.split(".")[0] + "." + uplink_port.split(".")[1]
            uplink_subnet = self.uplink_nat_ports[uplink_nat_ports]["ip"]
            gateway_ip = self.uplink_nat_ports[uplink_nat_ports]["gateway_ip"]
            dut_obj = DUT(lfmgr=self.manager_ip,
                          port=self.manager_http_port,
                          dut_name="upstream",
                          lan_port=gateway_ip)
            dut_obj.setup()
            dut_obj.add_ssids()
            # dut_obj.show_text_blob(None, None, True)  # Show changes on GUI
            # dut_obj.sync_cv()
            # time.sleep(2)
            # dut_obj.sync_cv()
            self.default_scenario_raw_lines.append(["profile_link " + upstream_resources + " upstream-dhcp 1 NA NA " +
                                                    upstream_port.split(".")[2] + ",AUTO -1 NA"])
            self.default_scenario_raw_lines.append(
                ["profile_link " + uplink_resources + " uplink-nat 1 'DUT: upstream LAN "
                 + gateway_ip
                 + "' NA " + uplink_port.split(".")[2] + "," + upstream_port.split(".")[2] + " -1 NA"])
        return self.default_scenario_raw_lines

    def create_dhcp_external(self):
        self.setup_connectivity_port(data=self.wan_ports)
        self.setup_connectivity_port(data=self.lan_ports)
        for wan_port in self.wan_ports:
            upstream_port = wan_port
            upstream_resources = upstream_port.split(".")[0] + "." + upstream_port.split(".")[1]
            self.default_scenario_raw_lines.append(["profile_link " + upstream_resources + " upstream 1 NA NA " +
                                                    upstream_port.split(".")[2] + ",AUTO -1 NA"])
        return self.default_scenario_raw_lines

    def json_get(self, _req_url="/"):
        cli_base = LFCliBase(_lfjson_host=self.manager_ip, _lfjson_port=self.manager_http_port)
        json_response = cli_base.json_get(_req_url=_req_url)
        return json_response

    def json_post(self, _req_url="/", data=None):
        cli_base = LFCliBase(_lfjson_host=self.manager_ip, _lfjson_port=self.manager_http_port)
        json_response = cli_base.json_post(_req_url=_req_url, _data=data)
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
            temp_raw_lines = self.default_scenario_raw_lines.copy()
            if "profile_link" in d:
                temp_raw_lines.append([d])
        logging.info("Saved default CV Scenario details: " + str(temp_raw_lines))

    def setup_interfaces(self, band=None, vlan_id=None, mode=None, num_sta=None):
        if band is None:
            logging.error("Band value is not available.")
            pytest.exit("Band value is not available.")
        if mode is None:
            logging.error("mode value is not available")
            pytest.exit("mode value is not available")
        if num_sta is None:
            logging.error("Number of stations are not available")
            pytest.exit("Number of stations are not available")
        if mode == "BRIDGE":
            upstream_port = self.wan_upstream_port()
        elif mode == "NAT-WAN":
            upstream_port = self.wan_upstream_port()
        elif mode == "NAT-LAN":
            upstream_port = self.lan_upstream_port()
        elif mode == "VLAN":
            # for vlan mode vlan id should be available
            if vlan_id is not None:
                upstream_port = self.wan_upstream_port() + "." + str(vlan_id)
            else:
                logging.error("Vlan id is not available for vlan")
                pytest.exit("Vlan id is not available for vlan")
        else:
            logging.error("Mode value is wrong.Value e.g. BRIDGE or NAT or VLAN")
            pytest.exit("Mode value is wrong.Value e.g. BRIDGE or NAT or VLAN")
        radio_data = {}
        sta_prefix = ""
        sniff_radio = ""
        data_dict = {}
        # deleting existing stations and layer 3
        self.pre_cleanup()
        max_station_per_radio = {"wave2_2g_radios": 64, "wave2_5g_radios": 64, "wave1_radios": 64, "mtk_radios": 19,
                                 "ax200_radios": 1, "ax210_radios": 1}
        if band == "twog":
            if self.run_lf:
                for i in self.dut_data:
                    ssid = i["ssid"]["2g-ssid"]
                    passkey = i["ssid"]["2g-password"]
                    security = i["ssid"]["2g-encryption"].lower()
            sta_prefix = self.twog_prefix
            # checking station compitality of lanforge
            if int(num_sta) > int(self.max_2g_stations):
                logging.error("Can't create %s stations on lanforge" % num_sta)
                pytest.skip("Can't create %s stations on lanforge" % num_sta)
            # checking atleast one 2g radio is available or not
            elif len(self.wave2_2g_radios) == 0 and len(self.wave1_radios) and len(self.ax210_radios) == 0 and len(
                    self.ax200_radios) == 0 and len(self.mtk_radios) == 0:
                logging.error("Twog radio is not available")
                pytest.skip("Twog radio is not available")

            dict_all_radios_2g = {"wave2_2g_radios": self.wave2_2g_radios,
                                  "wave1_radios": self.wave1_radios, "mtk_radios": self.mtk_radios,
                                  "ax200_radios": self.ax200_radios,
                                  "ax210_radios": self.ax210_radios}

            # radio and station selection
            stations = num_sta
            for j in dict_all_radios_2g:
                max_station = max_station_per_radio[j]
                if stations > 0:
                    if len(dict_all_radios_2g[j]) > 0:
                        diff = max_station - stations
                        for i in dict_all_radios_2g[j]:
                            if diff >= 0:
                                radio_data[i] = stations
                                stations = 0
                                break
                            elif diff < 0:
                                radio_data[i] = max_station
                                stations = stations - max_station
                                diff = max_station - stations
            # setup sniffer
            sniff_radio = self.setup_sniffer(band=band, station_radio_data=radio_data)
            data_dict["sniff_radio_2g"] = sniff_radio
        if band == "fiveg":
            if self.run_lf:
                for i in self.dut_data:
                    ssid = i["ssid"]["2g-ssid"]
                    passkey = i["ssid"]["2g-password"]
                    security = i["ssid"]["2g-encryption"].lower()

            sta_prefix = self.fiveg_prefix
            # checking station compitality of lanforge
            if int(num_sta) > int(self.max_5g_stations):
                logging.error("Can't create %s stations on lanforge" % num_sta)
                pytest.skip("Can't create %s stations on lanforge" % num_sta)
            # checking atleast one 5g radio is available or not
            elif len(self.wave2_5g_radios) == 0 and len(self.wave1_radios) and len(self.ax210_radios) == 0 and len(
                    self.ax200_radios) == 0 and len(self.mtk_radios) == 0:
                logging.error("fiveg radio is not available")
                pytest.skip("fiveg radio is not available")

            dict_all_radios_5g = {"wave2_5g_radios": self.wave2_5g_radios,
                                  "wave1_radios": self.wave1_radios, "mtk_radios": self.mtk_radios,
                                  "ax200_radios": self.ax200_radios,
                                  "ax210_radios": self.ax210_radios}

            # radio and station selection
            stations = num_sta
            for j in dict_all_radios_5g:
                max_station = max_station_per_radio[j]
                if stations > 0:
                    if len(dict_all_radios_5g[j]) > 0:
                        diff = max_station - stations
                        for i in dict_all_radios_5g[j]:
                            if diff >= 0:
                                radio_data[i] = stations
                                stations = 0
                                break
                            elif diff < 0:
                                radio_data[i] = max_station
                                stations = stations - max_station
                                diff = max_station - stations
            # setup sniffer
            sniff_radio = self.setup_sniffer(band=band, station_radio_data=radio_data)
            data_dict["sniff_radio_5g"] = sniff_radio
        if band == "sixg":
            if self.run_lf:
                for i in self.dut_data:
                    ssid = i["ssid"]["6g-ssid"]
                    passkey = i["ssid"]["6g-password"]
                    security = i["ssid"]["6g-encryption"].lower()

            sta_prefix = self.sixg_prefix
            # checking station compitality of lanforge
            if int(num_sta) > int(self.max_6g_stations):
                logging.error("Can't create %s stations on lanforge" % num_sta)
                pytest.skip("Can't create %s stations on lanforge" % num_sta)
            # checking atleast one 6g radio is available or not
            elif len(self.ax210_radios) == 0:
                logging.error("sixg radio is not available")
                pytest.skip("sixg radio is not available")

            dict_all_radios_6g = {"ax210_radios": self.ax210_radios}

            # radio and station selection
            stations = num_sta
            for j in dict_all_radios_6g:
                max_station = max_station_per_radio[j]
                if stations > 0:
                    if len(dict_all_radios_6g[j]) > 0:
                        diff = max_station - stations
                        for i in dict_all_radios_6g[j]:
                            if diff >= 0:
                                radio_data[i] = stations
                                stations = 0
                                break
                            elif diff < 0:
                                radio_data[i] = max_station
                                stations = stations - max_station
                                diff = max_station - stations

            sniff_radio = self.setup_sniffer(band=band, station_radio_data=radio_data)
            data_dict["sniff_radio_6g"] = sniff_radio
        # creating dict of radio and station_list
        dict_radio_sta_list = {}
        # list of per radio station
        length_to_split = list(radio_data.values())
        # station list of per radio
        sta_list = self.get_station_list(num_sta=num_sta, band=band)
        sta_list = iter(sta_list)
        sta_list_ = [list(islice(sta_list, elem))
                     for elem in length_to_split]
        # Checking station lists according to radios
        if len(sta_list_) == len(length_to_split):
            dict_radio_sta_list = dict(zip(list(radio_data.keys()), sta_list_))
        for i in dict_radio_sta_list:
            temp_list = []
            shelf_resource = str(i.split(".")[0] + "." + i.split(".")[1] + ".")
            for j in dict_radio_sta_list[i]:
                temp_list.append(shelf_resource + j)
            dict_radio_sta_list[i] = temp_list

        if self.run_lf:
            data_dict["radios"] = dict_radio_sta_list
            data_dict["upstream_port"] = upstream_port
            data_dict["ssid"] = ssid
            data_dict["passkey"] = passkey
            data_dict["security"] = security
            data_dict["sta_prefix"] = sta_prefix
            # data_dict["sniff_radio"] = sniff_radio
            return data_dict
        else:
            data_dict["radios"] = dict_radio_sta_list
            data_dict["upstream_port"] = upstream_port
            data_dict["sta_prefix"] = sta_prefix
            # data_dict["sniff_radio"] = sniff_radio
            return data_dict

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
        logging.info("Profiles: " + str(all_profiles))

        # Create upstream-dhcp and uplink-nat profile if they don't exists
        # Checking availability of upstream-dhcp profile
        try:
            upstream_dhcp = profile_utility_obj.check_profile(profile_name="upstream-dhcp")
            # Checking availability of uplink-nat profile
            uplink_nat = profile_utility_obj.check_profile(profile_name="uplink-nat")
        except Exception as e:
            upstream_dhcp = True
            uplink_nat = True
            pass
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
            profile_utility_obj.add_profile(profile_name="uplink-nat", profile_type="uplink", profile_flags="NAT")
        else:
            profile_utility_obj.add_profile(profile_name="uplink-nat", profile_type="uplink", profile_flags="NAT")

        # Create VLAN Based profiles
        if self.scenario == "dhcp-bridge":
            try:
                vlan_dhcp_profile = profile_utility_obj.check_profile(profile_name="vlan_dhcp_profile")
            except Exception as e:
                vlan_dhcp_profile = True

            if vlan_dhcp_profile:
                profile_utility_obj.remove_profile(name="vlan_dhcp_profile")
                profile_utility_obj.add_profile(profile_name="vlan_dhcp_profile", profile_type="vlan",
                                                profile_flags="DHCP-SERVER")
            else:
                profile_utility_obj.add_profile(profile_name="vlan_dhcp_profile", profile_type="vlan",
                                                profile_flags="DHCP-SERVER")

        elif self.scenario == "dhcp-external":
            try:
                vlan_profile = profile_utility_obj.check_profile(profile_name="vlan_profile")
            except Exception as e:
                vlan_profile = True
            if vlan_profile:
                profile_utility_obj.remove_profile(name="vlan_profile")
                profile_utility_obj.add_profile(profile_name="vlan_profile", profile_type="vlan", profile_flags=None)
            else:
                profile_utility_obj.add_profile(profile_name="vlan_profile", profile_type="vlan", profile_flags=None)

    def pre_cleanup(self):
        """ deleting existing stations and layer 3 connections """
        logging.info("Checking existing stations and layer3 connections...")
        exist_sta = []
        for u in self.json_get("/port/?fields=port+type,alias")['interfaces']:
            if list(u.values())[0]['port type'] not in ['Ethernet', 'WIFI-Radio', 'NA']:
                exist_sta.append(list(u.values())[0]['alias'])
        if len(exist_sta) == 0:
            logging.info("Existing stations are not available")
        else:
            for port_eid in exist_sta:
                self.staConnect.rm_port(port_eid, check_exists=True)
                time.sleep(0.3)
            logging.warning("Deleting existing stations")
            logging.info("Deleted %s Stations" % exist_sta)

        # deleting the previously created traffic
        try:
            exist_l3 = list(filter(lambda cx_name: cx_name if (cx_name != 'handler' and cx_name != 'uri') else False,
                                   self.json_get("/cx/?fields=name")))
            if len(exist_l3) == 0 or exist_l3[0] == "empty":
                logging.info("Existing layer3 and endp  are not available")
            else:
                list(map(lambda i: self.staConnect.rm_cx(cx_name=i), exist_l3))
                list(map(lambda cx_name: [self.staConnect.rm_endp(ename=i) for i in [f"{cx_name}-A", f"{cx_name}-B"]],
                         exist_l3))
        except Exception as e:
            logging.error(e)

    def nametoresource(self, name=None):
        """Returns resource number"""
        if name is not None:
            resource = name.split(".")[1]
            return resource
        else:
            logging.error("Name is not provided")

    def wan_upstream_port(self):
        """finding upstream port"""
        upstream_port = ""
        for i in self.dut_data:
            if dict(i).keys().__contains__("wan_port"):
                upstream_port = i["wan_port"]
        return upstream_port

    def lan_upstream_port(self):
        """finding upstream port"""
        upstream_port = ""
        for i in self.dut_data:
            if dict(i).keys().__contains__("lan_port"):
                upstream_port = i["lan_port"]
        return upstream_port

    def setup_sniffer(self, band=None, station_radio_data=None):
        """Setup sniff radio"""
        sniff_radio = None
        if band == "twog":
            all_radio_2g = self.wave2_2g_radios + self.wave1_radios + self.mtk_radios + self.ax200_radios + self.ax210_radios
            logging.info("All 2g radios" + str(all_radio_2g))
            left_radio = list(set(all_radio_2g) - set(list(station_radio_data.keys())))
            if len(left_radio) == 0:
                sniff_radio = None
                logging.error("Radios are not available for sniffing")
            else:
                sniff_radio = left_radio[0]
        elif band == "fiveg":
            all_radio_5g = self.wave2_5g_radios + self.wave1_radios + self.mtk_radios + self.ax200_radios + self.ax210_radios
            logging.info("All 5g radios" + str(all_radio_5g))
            left_radio = list(set(all_radio_5g) - set(list(station_radio_data.keys())))
            if len(left_radio) == 0:
                sniff_radio = None
                logging.error("Radios are not available for sniffing")
            else:
                sniff_radio = left_radio[0]
        elif band == "sixg":
            all_radio_6g = self.ax210_radios
            logging.info("All 6g radios" + str(all_radio_6g))
            left_radio = list(set(all_radio_6g) - set(list(station_radio_data.keys())))
            if len(left_radio) == 0:
                sniff_radio = None
                logging.error("Radios are not available for sniffing")
            else:
                sniff_radio = left_radio[0]
        return sniff_radio

    def scan_ssid(self, radio="", retry=1, allure_attach=True, scan_time=15, ssid=None, ssid_channel=None):
        '''This method for scan ssid data'''
        count = 0
        sta_list = []
        sta_name = str(radio.split(".")[0]) + "." + str(radio.split(".")[1]) + "." + "sta00100"
        sta_list.append(sta_name)
        logging.info("scan station: " + str(sta_list))
        for i in range(retry + 1):
            list_data = []
            obj_scan = StaScan(host=self.manager_ip, port=self.manager_http_port, ssid="fake ssid", security="open",
                               password="[BLANK]", radio=radio, sta_list=sta_list, csv_output="scan_ssid.csv",
                               scan_time=scan_time)
            # obj_scan.pre_cleanup()
            time1 = datetime.now()
            first = time.mktime(time1.timetuple()) * 1000
            obj_scan.build()
            obj_scan.start()
            time2 = datetime.now()
            second = time.mktime(time2.timetuple()) * 1000
            diff = int(second - first)
            try:
                with open(obj_scan.csv_output, 'r') as file:
                    reader = csv.reader(file)
                    for row in reader:
                        if row[1] == "age":
                            list_data.append(row)
                            continue
                        elif int(row[1]) < diff:
                            list_data.append(row)
            except Exception as e:
                logging.error(e)
            report_obj = Report()
            csv_data_table = report_obj.table2(list_data)
            # allure.attach(name="scan_ssid_data", body=csv_data_table)
            if allure_attach:
                if i == 0:
                    allure.attach(name="scan_ssid_data", body=csv_data_table)
                else:
                    allure.attach(name="scan_ssid_data_retry", body=csv_data_table)
            obj_scan.cleanup()
            if self.check_ssid_available_scan_result(scan_ssid_data=list_data, ssid=ssid):
                count = count + 1
                return list_data
        if count == 0:
            return False

    def start_sniffer(self, radio_channel=None, radio=None, test_name="sniff_radio", duration=60):
        self.pcap_name = test_name + ".pcap"
        self.pcap_obj = SniffRadio(lfclient_host=self.manager_ip, lfclient_port=self.manager_http_port, radio=radio,
                                   channel=radio_channel, monitor_name="moni3a")
        self.pcap_obj.setup(0, 0, 0)
        time.sleep(5)
        self.pcap_obj.monitor.admin_up()
        time.sleep(5)
        self.pcap_obj.monitor.start_sniff(capname=self.pcap_name, duration_sec=duration)

    def stop_sniffer(self):
        self.pcap_obj.monitor.admin_down()
        time.sleep(2)
        self.pcap_obj.cleanup()
        lf_report.pull_reports(hostname=self.manager_ip, port=self.manager_ssh_port, username="lanforge",
                               password="lanforge",
                               report_location="/home/lanforge/" + self.pcap_name,
                               report_dir=".")
        allure.attach.file(source=self.pcap_name,
                           name="pcap_file", attachment_type=allure.attachment_type.PCAP)
        logging.info("pcap file name: " + str(self.pcap_name))
        return self.pcap_name

    def check_ssid_available_scan_result(self, scan_ssid_data=None, ssid=None):
        """This method will check ssid available or not in scan ssid data"""
        try:
            flag = False
            for i in scan_ssid_data:
                if ssid in i:
                    flag = True
            if flag:
                return True
            else:
                return False
        except Exception as e:
            logging.error(e)

    def set_radio_channel(self, radio="1.1.wiphy0", channel="AUTO"):
        try:
            radio = radio.split(".")
            shelf = radio[0]
            resource = radio[1]
            radio_ = radio[2]
            local_realm_obj = realm.Realm(lfclient_host=self.manager_ip, lfclient_port=self.manager_http_port)
            data = {
                "shelf": shelf,
                "resource": resource,
                "radio": radio_,
                "mode": "NA",
                "channel": channel
            }
            local_realm_obj.json_post("/cli-json/set_wifi_radio", _data=data)
            time.sleep(2)
        except Exception as e:
            logging.error(e)

    def get_station_data(self, rows=[], sta_name=[], allure_attach=True):
        """
        Attach station data to allure
        e.g. rows = ["ip", "signal"] , sta_names = ["1.1.wlan0000", "1.1.wlan0001"]
        """
        # dict for station data
        sta_dict = {}
        try:
            for sta in sta_name:
                sta_url = "port/" + str(sta.split(".")[0]) + "/" + str(sta.split(".")[1]) + "/" + str(sta.split(".")[2])
                station_info = self.staConnect.json_get(sta_url)
                dict_data = station_info["interface"]
                temp_dict = {}
                for i in rows:
                    temp_dict[i] = dict_data[i]
                sta_dict[sta] = temp_dict
        except Exception as e:
            logging.error(e)
        logging.info("station info: " + str(sta_dict))
        # Creating dict for allure table
        station_table_dict = {}
        station_table_dict["station name"] = list(sta_dict.keys())
        for i in rows:
            temp_list = []
            for j in sta_name:
                temp_list.append(sta_dict[j][i])
            station_table_dict[i] = temp_list
        if allure_attach:
            self.attach_table_allure(data=station_table_dict, allure_name="station data")
        return sta_dict

    def get_cx_data(self, cx_name=[], cx_data=[], allure_attach=True):
        """Attach cx data to allure"""
        url = "cx/all"
        # cx_data.append("type")
        dict_cx_data = {}
        cx_json_data = self.json_get(url)
        try:
            for sta_ in cx_name:
                temp_dict = {}
                for i in cx_data:
                    temp_dict[i] = cx_json_data[sta_][i]
                dict_cx_data[sta_] = temp_dict
        except Exception as e:
            logging.error(e)
        cx_table_dict = {}
        cx_table_dict["cx name"] = list(dict_cx_data.keys())
        for i in cx_data:
            temp_list = []
            for j in cx_name:
                temp_list.append(dict_cx_data[j][i])
            if i == "bps rx a":
                cx_table_dict["Download"] = temp_list
            elif i == "bps rx b":
                cx_table_dict["Upload"] = temp_list
            elif i == "type":
                cx_table_dict["cx type"] = temp_list
        if allure_attach:
            self.attach_table_allure(data=cx_table_dict, allure_name="cx data")
        return dict_cx_data

    def get_station_list(self, num_sta=1, band="twog"):
        """Create station list"""
        sta_list = []
        for i in range(num_sta):
            if band == "twog":
                sta_list.append(self.twog_prefix + str(i))
            elif band == "fiveg":
                sta_list.append(self.fiveg_prefix + str(i))
            elif band == "sixg":
                sta_list.append(self.sixg_prefix + str(i))
            else:
                logging.error("band is wrong")
        return sta_list

    def attach_table_allure(self, data=None, allure_name=None):
        """Attach table to allure.data should be dict."""
        try:
            report_obj = Report()
            data_table = report_obj.table2(table=data, headers='keys')
            allure.attach(name=allure_name, body=data_table)
        except Exception as e:
            logging.error(e)

    def create_stations(self):
        pass

    def delete_stations(self):
        pass

    def modify_station(self):
        pass

    def read_stations(self):
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
        port_list = []
        temp_raw_lines = self.default_scenario_raw_lines.copy()
        for port in self.wan_ports:
            for vlans in vlan_ids:
                for i in data["interfaces"]:
                    if list(i.keys())[0] != port + "." + str(vlans):
                        flag = 1
            if flag == 1:
                for vlans in vlan_ids:
                    if self.scenario == "dhcp-bridge":
                        profile_name = "vlan_dhcp_profile"
                    elif self.scenario == "dhcp-external":
                        profile_name = "vlan_profile"
                    port_list.append(str(port) + "." + str(vlans))
                    temp_raw_lines.append(["profile_link " + port + " " + profile_name + " 1 " + port
                                           + " NA " + port.split(".")[2] + ",AUTO -1 " + str(vlans)])

        self.chamber_view(raw_lines=temp_raw_lines)
        if self.scenario == "dhcp-external":
            for port in port_list:
                data = {
                    "shelf": port.split(".")[0],
                    "resource": port.split(".")[1],
                    "port": port.split(".")[2] + "." + port.split(".")[3],
                    "current_flags": 2147483648,
                    "interest": 16384
                }
                self.json_post("/cli-json/set_port", data)
                time.sleep(2)

    def chamber_view(self, delete_old_scenario=True, raw_lines=[]):
        if delete_old_scenario:
            self.chamberview_object.clean_cv_scenario(scenario_name=self.scenario)
        # if self.scenario == "dhcp-bridge":
        #     self.create_dhcp_bridge()
        #     logging.info("Scenario name: " + str(self.scenario))
        # elif self.scenario == "dhcp-external":
        #     self.create_dhcp_external()
        #     logging.info("Scenario name: " + str(self.scenario))
        self.chamberview_object.setup(create_scenario=self.scenario,
                                      raw_line=raw_lines
                                      )
        logging.info("Raw Lines: " + str(raw_lines))
        self.chamberview_object.build(self.scenario)
        self.chamberview_object.sync_cv()
        time.sleep(2)
        self.chamberview_object.show_text_blob(None, None, True)  # Show changes on GUI
        self.chamberview_object.sync_cv()
        return self.chamberview_object, self.scenario

    def setup_radius_server(self, user=""):
        """
            TODO:
                setup freeradius server on lanforge and return the radius server data
                setup the radius server for basic EAP-TLS and EAP-TTLS encryptions
            Special Radius configurations can be done in later implementations
            Radius server should be working properly on WAN Interface of AP
        """
        pass

    def enable_verbose_debug(self, radio=None, enable=True):
        """Increase debug info in wpa-supplicant and hostapd logs"""
        # radio e.g 1.1wiphy0
        if radio is not None:
            shelf = radio.split(".")[0]
            resource = radio.split(".")[1]
            radio_name = radio.split(".")[2]
            if enable:
                flag_value = "0x10000"
            else:
                flag_value = "0x00000"
            data = {
                "shelf": shelf,
                "resource": resource,
                "radio": radio_name,
                "flags": flag_value
            }
            self.json_post("/cli-json/set_wifi_radio", data=data)
        else:
            logging.error("Radio name is wrong")


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

    def save_current_scenario(self):
        pass
