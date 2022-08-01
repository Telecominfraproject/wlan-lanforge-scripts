import importlib
import logging
import os
import sys
import time
from datetime import datetime
import allure
import paramiko
import pytest
import csv
from itertools import islice
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
sniffradio = importlib.import_module("py-scripts.lf_sniff_radio")
SniffRadio = sniffradio.SniffRadio
stascan = importlib.import_module("py-scripts.sta_scan_test")
StaScan = stascan.StaScan
cv_test_reports = importlib.import_module("py-json.cv_test_reports")
lf_report = cv_test_reports.lanforge_reports


class lf_tests(lf_libs):
    """
        lf_tools is needed in lf_tests to do various operations needed by various tests
    """
    twog_prefix = "ath10k_2g0"
    fiveg_prefix = "ath10k_5g0"
    sixg_prefix = "AX210_0"
    ax_prefix = "AX200_0"
    pcap_obj = None

    def __init__(self, lf_data={}, dut_data={}, log_level=logging.DEBUG, run_lf=False, influx_params=None,
                 skip_pcap=False):
        super().__init__(lf_data, dut_data, log_level)
        self.run_lf = run_lf
        self.upstream_port = list(self.uplink_nat_ports.keys())[0]
        self.skip_pcap = skip_pcap
        self.staConnect = StaConnect2(self.manager_ip, self.manager_http_port)
        pass

    def setup_interfaces(self, band=None, vlan_id=None, mode=None, num_sta=None):
        if band is None:
            logging.error("Band value is not available.")
            pytest.exit()
        if mode is None:
            logging.error("mode value is not available")
            pytest.exit()
        if num_sta is None:
            logging.error("Number of stations are not available")
            pytest.exit()
        if mode == "BRIDGE":
            upstream_port = self.upstream_port
        elif mode == "NAT":
            upstream_port = self.upstream_port
        elif mode == "VLAN":
            # for vlan mode vlan id should be available
            if vlan_id is None:
                upstream_port = self.upstream_port + str(vlan_id)
            else:
                logging.error("Vlan id is not available for vlan")
                pytest.exit()
        else:
            logging.error("Mode value is wrong.Value e.g. BRIDGE or NAT or VLAN")
            pytest.exit()
        radio_data = {}
        sta_prefix = ""
        sniff_radio = ""
        print(self.dut_data)
        # deleting existing stations and layer 3
        self.pre_cleanup()
        max_station_per_radio = {"wave2_2g_radios": 64, "wave2_5g_radios": 64, "wave1_radios": 64, "mtk_radios": 19,
                                 "ax200_radios": 1, "ax210_radios": 1}
        if band == "twog":
            if self.run_lf:
                ssid = self.dut_data[0]["ssid"]["2g-ssid"]
                passkey = self.dut_data[0]["ssid"]["2g-password"]
                security = self.dut_data[0]["ssid"]["2g-encryption"].lower()
            sta_prefix = self.twog_prefix

            # checking station compitality of lanforge
            if int(num_sta) > int(self.max_2g_stations):
                logging.error("Can't create %s stations on lanforge" % num_sta)
                pytest.exit()
            # checking atleast one 2g radio is available or not
            elif len(self.wave2_2g_radios) == 0 and len(self.wave1_radios) and len(self.ax210_radios) == 0 and len(
                    self.ax200_radios) == 0 and len(self.mtk_radios) == 0:
                logging.error("Twog radio is not available")
                pytest.exit()

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
            if not self.skip_pcap:
                sniff_radio = self.setup_sniffer(band=band, station_radio_data=radio_data)
        if band == "fiveg":
            if self.run_lf:
                ssid = self.dut_data["ssid"]["5g-ssid"]
                passkey = self.dut_data["ssid"]["5g-password"]
                security = self.dut_data["ssid"]["5g-encryption"].lower()

            sta_prefix = self.fiveg_prefix
            # checking station compitality of lanforge
            if int(num_sta) > int(self.max_5g_stations):
                logging.error("Can't create %s stations on lanforge" % num_sta)
                pytest.exit()
            # checking atleast one 5g radio is available or not
            elif len(self.wave2_5g_radios) == 0 and len(self.wave1_radios) and len(self.ax210_radios) == 0 and len(
                    self.ax200_radios) == 0 and len(self.mtk_radios) == 0:
                logging.error("fiveg radio is not available")
                pytest.exit()

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

        if not self.skip_pcap:
            sniff_radio = self.setup_sniffer(band=band, station_radio_data=radio_data)
        data_dict = {}
        if self.run_lf:
            data_dict["radios"] = radio_data
            data_dict["upstream_port"] = upstream_port
            data_dict["ssid"] = ssid
            data_dict["passkey"] = passkey
            data_dict["security"] = security
            data_dict["sta_prefix"] = sta_prefix
            if not self.skip_pcap:
                data_dict["sniff_radio"] = sniff_radio
            return data_dict
        else:
            data_dict["radios"] = radio_data
            data_dict["upstream_port"] = upstream_port
            data_dict["sta_prefix"] = sta_prefix
            if not self.skip_pcap:
                data_dict["sniff_radio"] = sniff_radio
            return data_dict


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
            print(exist_l3)
            if len(exist_l3) == 0 or exist_l3[0] == "empty":
                logging.info("Existing layer3 and endp  are not available")
            else:
                list(map(lambda i: self.staConnect.rm_cx(cx_name=i), exist_l3))
                list(map(lambda cx_name: [self.rm_endp(ename=i) for i in [f"{cx_name}-A", f"{cx_name}-B"]], exist_l3))
        except Exception as e:
            logging.error(e)

    def setup_sniffer(self, band=None, station_radio_data=None):
        """Setup sniff radio"""
        sniff_radio = None
        if band == "twog":
            all_radio_2g = self.wave2_2g_radios + self.wave1_radios + self.mtk_radios + self.ax200_radios + self.ax210_radios
            logging.info("All 2g radios" + str(all_radio_2g))
            left_radio = list(set(all_radio_2g) - set(list(station_radio_data.keys())))
            if len(left_radio) == 0:
                logging.error("Radios are not available for sniffing")
                pytest.exit()
            else:
                sniff_radio = left_radio[0]
        elif band == "fiveg":
            all_radio_5g = self.wave2_5g_radios + self.wave1_radios + self.mtk_radios + self.ax200_radios + self.ax210_radios
            logging.info("All 5g radios" + str(all_radio_5g))
            left_radio = list(set(all_radio_5g) - set(list(station_radio_data.keys())))
            if len(left_radio) == 0:
                logging.error("Radios are not available for sniffing")
                pytest.exit()
            else:
                sniff_radio = left_radio[0]
        return sniff_radio



    def client_connectivity_test(self, ssid="[BLANK]", passkey="[BLANK]", security="open", extra_securities=[],
                                 station_name=[], mode="BRIDGE", vlan_id=1, band="twog", ssid_channel=None):
        # self.staConnect = StaConnect2(self.manager_ip, self.manager_http_port, debug_=self.debug)
        # setup_interfaces() interface selection return radio name along no of station on each radio, upstream port
        #
        data = self.setup_interfaces(band=band, vlan_id=vlan_id, mode=mode, num_sta=len(station_name))
        logging.info("Setup interface data" + str(data))
        if self.run_lf:
            ssid = data["ssid"]
            passkey = data["passkey"]
            security = data["security"]

        self.staConnect.sta_mode = 0
        self.staConnect.upstream_resource = data["upstream_port"].split(".")[1]
        self.staConnect.upstream_port = data["upstream_port"].split(".")[2]
        #creating dict of radio and station_list
        dict_radio_sta_list = {}
        # list of per radio station
        length_to_split = list(data["radios"].values())
        print(length_to_split)
        sta_list = iter(station_name)
        # station list of per radio station list
        sta_list_ = [list(islice(sta_list, elem))
          for elem in length_to_split]
        # Checking station lists according to radios
        if len(sta_list_) == len(length_to_split):
            dict_radio_sta_list = dict(zip(list(data["radios"].keys()), sta_list_))
        else:
            logging.error("Stations per radios are wrong")
            pytest.exit()
        print("dict_radio_sta_list", dict_radio_sta_list)
        for radio in data["radios"]:

            self.staConnect.radio = radio
            self.staConnect.admin_down(self.staConnect.radio)
            self.staConnect.admin_up(self.staConnect.radio)
            self.staConnect.sta_prefix = data["sta_prefix"]
            self.set_radio_channel(radio=radio, channel=ssid_channel)
            print("scan ssid radio", radio.split(".")[2])
            self.data_scan_ssid = self.scan_ssid(radio=radio.split(".")[2])
            print("ssid scan data :- ", self.data_scan_ssid)
            result = self.check_ssid_available_scan_result(scan_ssid_data=self.data_scan_ssid, ssid=ssid)
            print("ssid available:-", result)
            if not result and ssid_channel:
                if not self.skip_pcap:
                    print("sniff radio", data["sniff_radio"].split(".")[2])
                    self.start_sniffer(radio_channel=ssid_channel, radio=data["sniff_radio"].split(".")[2], duration=30)
                    time.sleep(30)
                    self.stop_sniffer()
                print("ssid not available in scan result")
                return "FAIL", "ssid not available in scan result"
            self.staConnect.resource = 1
            self.staConnect.dut_ssid = ssid
            self.staConnect.dut_passwd = passkey
            self.staConnect.dut_security = security
            self.staConnect.station_names = dict_radio_sta_list[radio]
            self.staConnect.runtime_secs = 40
            self.staConnect.bringup_time_sec = 80
            self.staConnect.cleanup_on_exit = True
            self.staConnect.download_bps = 128000
            self.staConnect.upload_bps = 128000
            self.staConnect.side_a_pdu = 1200
            self.staConnect.side_b_pdu = 1500
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
                    print("sniff radio", data["sniff_radio"].split(".")[2])
                    self.start_sniffer(radio_channel=ssid_channel, radio=data["sniff_radio"].split(".")[2], duration=30)
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
            # try:
            #     supplicant = "/home/lanforge/wifi/wpa_supplicant_log_" + radio.split(".")[2] + ".txt"
            #     obj = SCP_File(ip=self.manager_ip, port=self.manager_ssh_port, username="root", password="lanforge",
            #                    remote_path=supplicant,
            #                    local_path=".")
            #     obj.pull_file()
            #     allure.attach.file(source="wpa_supplicant_log_" + radio.split(".")[2] + ".txt",
            #                        name="supplicant_log")
            # except Exception as e:
            #     print(e)
            #
            # for result in run_results:
            #     print("test result: " + result)
            # result = "PASS"
            # description = "Unknown error"
            # dict_table = {}
            # print("Client Connectivity :", self.staConnect.passes)
            # endp_data = []
            # for i in self.staConnect.resulting_endpoints:
            #     endp_data.append(self.staConnect.resulting_endpoints[i]["endpoint"])
            # dict_table["key"] = [i for s in [d.keys() for d in endp_data] for i in s]
            # dict_table["value"] = [i for s in [d.values() for d in endp_data] for i in s]
            # data_table = report_obj.table2(table=dict_table, headers='keys')
            # allure.attach(name="cx_data", body=data_table)
            # for i in range(len(run_results)):
            #     if i == 0:
            #         if "FAILED" in run_results[i]:
            #             result = "FAIL"
            #             description = "Station did not get an ip"
            #             break
            #     else:
            #         if "FAILED" in run_results[i]:
            #             result = "FAIL"
            #             description = "did not report traffic"
            #
            # if self.staConnect.passes():
            #     print("client connection to", self.staConnect.dut_ssid, "successful. Test Passed")
            #     result = "PASS"
            # else:
            #     print("client connection to", self.staConnect.dut_ssid, "unsuccessful. Test Failed")
            #     result = "FAIL"
            # time.sleep(3)
            if ssid_channel:
                if not self.skip_pcap:
                    self.stop_sniffer()
            self.set_radio_channel(radio=radio, channel="AUTO")
            # return result, description

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

    def scan_ssid(self, radio=""):
        '''This method for scan ssid data'''
        list_data = []
        obj_scan = StaScan(host=self.manager_ip, port=self.manager_http_port, ssid="fake ssid", security="open",
                           password="[BLANK]", radio=radio, sta_list=["sta00100"], csv_output="scan_ssid.csv")
        #obj_scan.pre_cleanup()
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
            print(e)
        report_obj = Report()
        csv_data_table = report_obj.table2(list_data)
        allure.attach(name="scan_ssid_data", body=csv_data_table)
        obj_scan.cleanup()
        return list_data

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
        lf_report.pull_reports(hostname=self.manager_ip, port=self.manager_http_port, username="lanforge",
                               password="lanforge",
                               report_location="/home/lanforge/" + self.pcap_name,
                               report_dir=".")
        allure.attach.file(source=self.pcap_name,
                           name="pcap_file", attachment_type=allure.attachment_type.PCAP)
        print("pcap file name : ", self.pcap_name)
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
            print(e)

    def set_radio_channel(self, radio="1.1.wiphy0", channel="AUTO"):
        try:
            radio = radio.split(".")
            shelf = radio[0]
            resource = radio[1]
            radio_ = radio[2]
            print("radio %s channel %s" % (radio, channel))
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
            print(e)


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
            "ssid": {
                "2g-ssid": "OpenWifi",
                "5g-ssid": "OpenWifi",
                "6g-ssid": "candela6ghz",
                "2g-password": "OpenWifi",
                "5g-password": "OpenWifi",
                "6g-password": "hello123",
                "2g-encryption": "WPA2",
                "5g-encryption": "open",
                "6g-encryption": "WPA3",
                "2g-bssid": "68:7d:b4:5f:5c:31 ",
                "5g-bssid": "68:7d:b4:5f:5c:3c",
                "6g-bssid": "68:7d:b4:5f:5c:38"
            },
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
                "manager_ip": "10.28.3.34",
                "http_port": 8080,
                "ssh_port": 22,
                "setup": {"method": "build", "DB": "Test_Scenario_Automation"},  # method: build/load,
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
                    "1.1.eth2": {"addressing": "static", "subnet": "10.28.2.1/24", "gateway_ip": "10.28.2.1"}
                    # dhcp-server/{"addressing":
                    # "dynamic"} /{"addressing": "static", "subnet": "10.28.2.6/16"}
                },
            }
        }
    }

    obj = lf_tests(lf_data=dict(basic_1["traffic_generator"]), dut_data=list(basic_1["device_under_tests"]),
                   log_level=logging.DEBUG, run_lf=True)
    obj.client_connectivity_test(ssid="OpenWifi", passkey="OpenWifi", security="wpa2", extra_securities=[],
                                station_name=["ath10k_2g000"], mode="BRIDGE", vlan_id=1, band="twog", ssid_channel=11)
    # obj.chamber_view()
