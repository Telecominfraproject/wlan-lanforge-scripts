import importlib
import logging
import os
import sys

sys.path.append(os.path.join(os.path.abspath(__file__ + "../../../")))
lfcli_base = importlib.import_module("py-json.LANforge.lfcli_base")
LFCliBase = lfcli_base.LFCliBase
realm = importlib.import_module("py-json.realm")


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
    manager_http_port = None
    manager_ssh_port = None
    manager_default_db = None
    wan_ports = None
    lan_ports = None
    uplink_nat_ports = None
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

    def __init__(self, lf_data, log_level=logging.DEBUG):
        logging.basicConfig(format='%(asctime)s - %(message)s', level=log_level)
        lf_data = dict(lf_data)
        try:
            self.lanforge_data = lf_data.get("details")
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
        except Exception as e:
            logging.error("lf_data has bad values: " + str(self.lanforge_data))
            logging.error(e)

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


class lf_tests(lf_libs):

    def __init__(self, lf_data, log_level=logging.DEBUG):
        super().__init__(lf_data, log_level)
        pass

    def client_connectivity_test(self):
        pass

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


class lf_tools(lf_libs):

    def __init__(self, lf_data, log_level=logging.DEBUG):
        super().__init__(lf_data, log_level)
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

    def read_cv_scenario(self):
        pass

    def add_dut(self):
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

    obj = lf_tools(lf_data=basic_02["traffic_generator"])
    obj.setup_metadata()
    # obj.load_scenario()
    # obj = lf_tests(lf_data="")
    # obj.json_get(_req_url="/port/all")
