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
createstation = importlib.import_module("py-scripts.create_station")
CreateStation = createstation.CreateStation


class lf_tests(lf_libs):
    """
        lf_tools is needed in lf_tests to do various operations needed by various tests
    """

    def __init__(self, lf_data={}, dut_data={}, log_level=logging.DEBUG, run_lf=False, influx_params=None):
        super().__init__(lf_data, dut_data, log_level)
        self.run_lf = run_lf
        # self.upstream_port = list(self.uplink_nat_ports.keys())[0]
        # self.skip_pcap = skip_pcap
        # self.wan_upstream = list(self.wan_ports.keys())
        # self.lan_upstream =
        self.staConnect = StaConnect2(self.manager_ip, self.manager_http_port, outfile="shivam", _cleanup_on_exit=False)

    def client_connectivity_test(self, ssid="[BLANK]", passkey="[BLANK]", dut_data={},
                                 security="open", extra_securities=[],
                                 num_sta=1, mode="BRIDGE", vlan_id=1, band="twog", ssid_channel=None,
                                 allure_attach=True, runtime_secs=40):
        # self.staConnect = StaConnect2(self.manager_ip, self.manager_http_port, debug_=self.debug)
        # setup_interfaces() interface selection return radio name along no of station on each radio, upstream port
        #

        data = self.setup_interfaces(band=band, vlan_id=vlan_id[0], mode=mode, num_sta=num_sta)
        self.add_vlan(vlan_ids=vlan_id)
        logging.info("Setup interface data" + str(data))
        if self.run_lf:
            ssid = data["ssid"]
            passkey = data["passkey"]
            security = data["security"]
        sta_connect_obj = []
        for radio in data["radios"]:
            obj_sta_connect = StaConnect2(self.manager_ip, self.manager_http_port, outfile="shivam",
                                          _cleanup_on_exit=False)
            obj_sta_connect.sta_mode = 0
            obj_sta_connect.upstream_resource = data["upstream_port"].split(".")[1]
            obj_sta_connect.upstream_port = data["upstream_port"].split(".")[2]
            self.enable_verbose_debug(radio=radio, enable=False)
            obj_sta_connect.radio = radio
            obj_sta_connect.admin_down(obj_sta_connect.radio)
            obj_sta_connect.admin_up(obj_sta_connect.radio)
            obj_sta_connect.sta_prefix = data["sta_prefix"]
            # changed to auto channel
            self.set_radio_channel(radio=radio, channel="AUTO")
            logging.info("scan ssid radio: " + str(radio.split(".")[2]))
            result = self.scan_ssid(radio=radio, ssid=ssid, ssid_channel=ssid_channel)
            logging.info("ssid scan data : " + str(result))
            if not result and ssid_channel:
                # Sniffer required
                # print("sniff radio", data["sniff_radio"].split(".")[2])
                for dut in self.dut_data:
                    identifier = dut["identifier"]
                    if dut_data.keys().__contains__(identifier):
                        if band == "twog":
                            if dict(dut_data.get(identifier)[-1]).keys().__contains__("2G") and \
                                    dict(dut_data.get(identifier)[-1])["2G"] is not None:
                                channel = dict(dut_data.get(identifier)[-1])["2G"][0]
                                if data["sniff_radio_2g"] is not None:
                                    self.start_sniffer(radio_channel=channel,
                                                       radio=data["sniff_radio_2g"].split(".")[2],
                                                       duration=10)
                                    time.sleep(10)
                                    self.stop_sniffer()
                        elif band == "fiveg":
                            if dict(dut_data.get(identifier)[-1]).keys().__contains__("5G") and \
                                    dict(dut_data.get(identifier)[-1])["5G"] is not None:
                                channel = dict(dut_data.get(identifier)[-1])["5G"][0]
                                if data["sniff_radio_5g"] is not None:
                                    self.start_sniffer(radio_channel=channel,
                                                       radio=data["sniff_radio_5g"].split(".")[2],
                                                       duration=10)
                                    time.sleep(10)
                                    self.stop_sniffer()
                        elif band == "sixg":
                            if dict(dut_data.get(identifier)[-1]).keys().__contains__("6G") and \
                                    dict(dut_data.get(identifier)[-1])["6G"] is not None:
                                channel = dict(dut_data.get(identifier)[-1])["6G"][0]
                                if data["sniff_radio_6g"] is not None:
                                    self.start_sniffer(radio_channel=channel,
                                                       radio=data["sniff_radio_6g"].split(".")[2],
                                                       duration=10)
                                    time.sleep(10)
                                    self.stop_sniffer()

                # print("ssid not available in scan result")
                # return "FAIL", "ssid not available in scan result"
                pass
            obj_sta_connect.resource = radio.split(".")[1]
            obj_sta_connect.dut_ssid = ssid
            obj_sta_connect.dut_passwd = passkey
            obj_sta_connect.dut_security = security
            obj_sta_connect.station_names = data["radios"][radio]
            obj_sta_connect.runtime_secs = runtime_secs
            obj_sta_connect.bringup_time_sec = 80
            obj_sta_connect.cleanup_on_exit = True
            obj_sta_connect.download_bps = 128000
            obj_sta_connect.upload_bps = 128000
            obj_sta_connect.side_a_pdu = 1200
            obj_sta_connect.side_b_pdu = 1500
            obj_sta_connect.setup(extra_securities=extra_securities)
            if ssid_channel:
                pass
                # Need to start sniffer
                # print("sniff radio", data["sniff_radio"].split(".")[2])
                # self.start_sniffer(radio_channel=ssid_channel, radio=data["sniff_radio"].split(".")[2], duration=30)
            sta_connect_obj.append(obj_sta_connect)
        for dut in self.dut_data:
            identifier = dut["identifier"]
            if dut_data.keys().__contains__(identifier):
                if band == "twog":
                    if dict(dut_data.get(identifier)[-1]).keys().__contains__("2G") and \
                            dict(dut_data.get(identifier)[-1])["2G"] is not None:
                        channel = dict(dut_data.get(identifier)[-1])["2G"][0]
                        self.start_sniffer(radio_channel=channel, radio=data["sniff_radio"].split(".")[2],
                                           duration=runtime_secs)
                        logging.info("started-sniffer")
                        for obj in sta_connect_obj:
                            obj.start()
                        logging.info("napping %f sec" % runtime_secs)
                        time.sleep(runtime_secs)
                        logging.info("stopping-sniffer")
                        self.stop_sniffer()
                elif band == "fiveg":
                    if dict(dut_data.get(identifier)[-1]).keys().__contains__("5G") and \
                            dict(dut_data.get(identifier)[-1])["5G"] is not None:
                        channel = dict(dut_data.get(identifier)[-1])["5G"][0]
                        self.start_sniffer(radio_channel=channel, radio=data["sniff_radio"].split(".")[2],
                                           duration=runtime_secs)
                        for obj in sta_connect_obj:
                            obj.start()
                        logging.info("napping %f sec" % runtime_secs)
                        time.sleep(runtime_secs)
                        self.stop_sniffer()
                elif band == "sixg":
                    if dict(dut_data.get(identifier)[-1]).keys().__contains__("6G") and \
                            dict(dut_data.get(identifier)[-1])["6G"] is not None:
                        channel = dict(dut_data.get(identifier)[-1])["6G"][0]
                        self.start_sniffer(radio_channel=channel, radio=data["sniff_radio"].split(".")[2],
                                           duration=runtime_secs)
                        for obj in sta_connect_obj:
                            obj.start()
                        logging.info("napping %f sec" % runtime_secs)
                        time.sleep(runtime_secs)
                        self.stop_sniffer()
        pass_fail_result = []
        for obj in sta_connect_obj:
            sta_rows = ["4way time (us)", "channel", "cx time (us)", "dhcp (ms)", "ip", "signal"]
            station_data = self.get_station_data(sta_name=obj.station_names, rows=sta_rows,
                                                 allure_attach=False)
            sta_table_dict = {}
            sta_table_dict["station name"] = list(station_data.keys())
            for i in sta_rows:
                temp_list = []
                for j in obj.station_names:
                    temp_list.append(station_data[j][i])
                sta_table_dict[i] = temp_list
            # pass fail
            pass_fail_sta = []
            for i in sta_table_dict["ip"]:
                if i == "0.0.0.0":
                    pass_fail_sta.append("Fail")
                else:
                    pass_fail_sta.append("Pass")
            sta_table_dict["Pass/Fail"] = pass_fail_sta
            if allure_attach:
                self.attach_table_allure(data=sta_table_dict, allure_name="station data")
            obj.stop()
            cx_name = list(obj.l3_udp_profile.get_cx_names()) + list(
                obj.l3_tcp_profile.get_cx_names())
            cx_row = ["type", "bps rx a", "bps rx b"]
            cx_data = self.get_cx_data(cx_name=cx_name, cx_data=cx_row, allure_attach=False)
            cx_table_dict = {}
            upstream = []
            for i in range(len(obj.station_names)):
                upstream.append(data["upstream_port"])
            cx_table_dict["Upstream"] = upstream
            cx_table_dict["Downstream"] = obj.station_names
            cx_tcp_ul = []
            cx_tcp_dl = []
            cx_udp_ul = []
            cx_udp_dl = []
            for sta in obj.station_names:
                for i in cx_data:
                    if sta.split(".")[2] in i:
                        if cx_data[i]["type"] == "LF/UDP":
                            cx_udp_dl.append(cx_data[i]["bps rx a"])
                            cx_udp_ul.append(cx_data[i]["bps rx b"])
                        elif cx_data[i]["type"] == "LF/TCP":
                            cx_tcp_dl.append(cx_data[i]["bps rx a"])
                            cx_tcp_ul.append(cx_data[i]["bps rx b"])
            cx_table_dict["TCP DL"] = cx_tcp_dl
            cx_table_dict["TCP UL"] = cx_tcp_ul
            cx_table_dict["UDP DL"] = cx_udp_dl
            cx_table_dict["UDP UL"] = cx_udp_ul
            pass_fail_cx = []
            for i, j, k, l in zip(cx_tcp_dl, cx_tcp_ul, cx_udp_dl, cx_udp_ul):
                if i == 0 or j == 0 or k == 0 or l == 0:
                    pass_fail_cx.append("Fail")
                else:
                    pass_fail_cx.append("Pass")
            cx_table_dict["Pass/Fail"] = pass_fail_cx
            if allure_attach:
                self.attach_table_allure(data=cx_table_dict, allure_name="cx data")
            obj.cleanup()
            result = "PASS"
            description = "Unknown error"
            count = 0
            temp_dict = {}
            if "Fail" in pass_fail_sta:
                count = count + 1
                result = "FAIL"
                description = "Station did not get an ip"
                temp_dict[result] = description
                pass_fail_result.append(temp_dict)
            if count == 0:
                if "Fail" in pass_fail_cx:
                    result = "FAIL"
                    description = "did not report traffic"
                    temp_dict[result] = description
                    pass_fail_result.append(temp_dict)
            if obj.passes():
                logging.info("client connection to" + str(obj.dut_ssid) + "successful. Test Passed")
                result = "PASS"
                temp_dict[result] = ""
                pass_fail_result.append(temp_dict)
            else:
                logging.info("client connection to" + str(obj.dut_ssid) + "unsuccessful. Test Failed")
                result = "FAIL"

            if ssid_channel:
                # need to stop sniffer
                pass
        result = "PASS"
        description = ""
        for i in pass_fail_result:
            if list(i.keys())[0] == "FAIL":
                result = "FAIL"
                description = i["FAIL"]
                break

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

    def client_connect(self, ssid="[BLANK]", passkey="[BLANK]", security="wpa2", mode="BRIDGE", band="twog",
                       vlan_id=100, num_sta=None, scan_ssid=True,
                       station_data=["4way time (us)", "channel", "cx time (us)", "dhcp (ms)", "ip", "signal"],
                       allure_attach=True):
        data = self.setup_interfaces(band=band, vlan_id=vlan_id, mode=mode, num_sta=num_sta)
        logging.info("Setup interface data" + str(data))
        if self.run_lf:
            ssid = data["ssid"]
            passkey = data["passkey"]
            security = data["security"]
        client_connect_obj = []
        station_data_all = {}
        for radio in data["radios"]:
            client_connect = CreateStation(_host=self.manager_ip, _port=self.manager_http_port,
                                           _sta_list=data["radios"][radio], _password=passkey, _ssid=ssid,
                                           _security=security)
            client_connect.station_profile.sta_mode = 0
            client_connect.upstream_resource = data["upstream_port"].split(".")[1]
            client_connect.upstream_port = data["upstream_port"].split(".")[2]
            client_connect.radio = radio
        logging.info("scan ssid radio: " + str(client_connect.radio))
        if scan_ssid:
            self.data_scan_ssid = self.scan_ssid(radio=client_connect.radio, ssid=ssid)
        logging.info("ssid scan data: " + str(self.data_scan_ssid))
        client_connect_obj.append(client_connect)
        pass_fail = []
        for obj in client_connect_obj:
            obj.build()
            result = obj.wait_for_ip(station_list=obj.sta_list, timeout_sec=50)
            # print(self.client_connect.wait_for_ip(station_name))
            pass_fail.append(result)
            station_data_ = self.get_station_data(sta_name=obj.sta_list, rows=station_data,
                                                  allure_attach=False)
            station_data_all.update(station_data_)
            sta_table_dict = {}
            sta_table_dict["station name"] = list(station_data_.keys())
            for i in station_data:
                temp_list = []
                for j in obj.sta_list:
                    temp_list.append(station_data_[j][i])
                sta_table_dict[i] = temp_list
            # pass fail
            pass_fail_sta = []
            for i in sta_table_dict["ip"]:
                if i == "0.0.0.0":
                    pass_fail_sta.append("Fail")
                else:
                    pass_fail_sta.append("Pass")
            sta_table_dict["Pass/Fail"] = pass_fail_sta
            if allure_attach:
                self.attach_table_allure(data=sta_table_dict, allure_name="station data")

        logging.info("pass_fail result: " + str(pass_fail))
        if False in pass_fail:
            logging.info("Station did not get an ip")
            pytest.fail("Station did not get an ip")
        else:
            logging.info("ALL Stations got IP's")
            return station_data_all


if __name__ == '__main__':
    basic_05 = {
        "target": "tip_2x",
        "controller": {
            "url": "https://sec-qa01.cicd.lab.wlan.tip.build:16001",
            "username": "tip@ucentral.com",
            "password": "OpenWifi%123"
        },
        "device_under_tests": [{
            "model": "cig_wf188n",
            "supported_bands": ["2G", "5G"],
            "supported_modes": ["BRIDGE", "NAT", "VLAN"],
            "wan_port": "1.1.eth2",
            "ssid": {
                "2g-ssid": "OpenWifi",
                "5g-ssid": "OpenWifi",
                "6g-ssid": "OpenWifi",
                "2g-password": "OpenWifi",
                "5g-password": "OpenWifi",
                "6g-password": "OpenWifi",
                "2g-encryption": "WPA2",
                "5g-encryption": "WPA2",
                "6g-encryption": "WPA3",
                "2g-bssid": "68:7d:b4:5f:5c:31",
                "5g-bssid": "68:7d:b4:5f:5c:3c",
                "6g-bssid": "68:7d:b4:5f:5c:38"
            },
            "mode": "wifi6",
            "identifier": "0000c1018812",
            "method": "serial",
            "host_ip": "10.28.3.103",
            "host_username": "lanforge",
            "host_password": "pumpkin77",
            "host_ssh_port": 22,
            "serial_tty": "/dev/ttyAP1",
            "firmware_version": "next-latest"
        }],
        "traffic_generator": {
            "name": "lanforge",
            "testbed": "basic",
            "scenario": "dhcp-bridge",
            "details": {
                "manager_ip": "10.28.3.28",
                "http_port": 8080,
                "ssh_port": 22,
                "setup": {"method": "build", "DB": "Test_Scenario_Automation"},
                "wan_ports": {
                    "1.1.eth2": {"addressing": "dhcp-server", "subnet": "172.16.0.1/16", "dhcp": {
                        "lease-first": 10,
                        "lease-count": 10000,
                        "lease-time": "6h"
                    }
                                 }
                },
                "lan_ports": {

                },
                "uplink_nat_ports": {
                    "1.1.eth1": {
                        "addressing": "static",
                        "ip": "10.28.2.16",
                        "gateway_ip": "10.28.2.1/24",
                        "ip_mask": "255.255.255.0",
                        "dns_servers": "BLANK"
                    }
                }
            }
        }
    }

    obj = lf_tests(lf_data=dict(basic_05["traffic_generator"]), dut_data=list(basic_05["device_under_tests"]),
                   log_level=logging.DEBUG, run_lf=True)
    # obj.setup_relevent_profiles()
    # obj.Client_Connect(ssid="OpenWifi", passkey="OpenWifi", security="wpa2", mode="BRIDGE", band="twog",
    #                    vlan_id=100, num_sta=5, scan_ssid=True,
    #                    station_data=["4way time (us)", "channel", "cx time (us)", "dhcp (ms)", "ip", "signal"],
    #                    allure_attach=True)
    # obj.add_vlan(vlan_ids=[100])
    # obj.create_dhcp_external()obj.add_vlan(vlan_ids=[100, 200, 300, 400, 500, 600])
    # obj.get_cx_data()
    # obj.chamber_view()
    # c = obj.client_connectivity_test(ssid="OpenWifi", passkey="OpenWifi", security="wpa2", extra_securities=[],
                                     # num_sta=1, mode="BRIDGE", vlan_id=[100],
                                     # band="twog", ssid_channel=11)
    # obj.start_sniffer(radio_channel=1, radio="wiphy7", test_name="sniff_radio", duration=30)
    # print("started")
    # time.sleep(30)
    # obj.stop_sniffer()
    # lf_report.pull_reports(hostname="10.28.3.28", port=22, username="lanforge",
    #                        password="lanforge",
    #                        report_location="/home/lanforge/" + "sniff_radio.pcap",
    #                        report_dir=".")
    #     def start_sniffer(self, radio_channel=None, radio=None, test_name="sniff_radio", duration=60):
    #
    # obj.get_cx_data()
    # obj.chamber_view()
    # obj.client_connectivity_test(ssid="wpa2_5g", passkey="something", security="wpa2", extra_securities=[],
    #                              num_sta=1, mode="BRIDGE", vlan_id=1,
    # #                              band="fiveg", ssid_channel=36)
    # obj.chamber_view()
    # obj.setup_relevent_profiles()
    # obj.add_vlan(vlan_ids=[100, 200, 300])
    # # obj.chamber_view()
    # obj.setup_relevent_profiles()
