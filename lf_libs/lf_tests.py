import csv
import importlib
import json
import logging
import os
import sys
import time
import string
import random
from itertools import islice
import paramiko
from datetime import datetime

import allure
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
wificapacitytest = importlib.import_module("py-scripts.lf_wifi_capacity_test")
WiFiCapacityTest = wificapacitytest.WiFiCapacityTest
csvtoinflux = importlib.import_module("py-scripts.csv_to_influx")
CSVtoInflux = csvtoinflux.CSVtoInflux


class lf_tests(lf_libs):
    """
        lf_tools is needed in lf_tests to do various operations needed by various tests
    """

    def __init__(self, lf_data={}, dut_data={}, log_level=logging.DEBUG, run_lf=False, influx_params=None,
                 local_report_path="../reports/"):
        super().__init__(lf_data, dut_data, run_lf, log_level)
        self.local_report_path = local_report_path

    def client_connectivity_test(self, ssid="[BLANK]", passkey="[BLANK]", bssid="[BLANK]", dut_data={},
                                 security="open", extra_securities=[], sta_mode=0,
                                 num_sta=1, mode="BRIDGE", vlan_id=[None], band="twog",
                                 allure_attach=True, runtime_secs=40):

        logging.info("DUT Data:\n" + json.dumps(str(dut_data), indent=2))
        allure.attach(name="DUT Data:\n", body=json.dumps(str(dut_data), indent=2),
                      attachment_type=allure.attachment_type.JSON)

        data = self.setup_interfaces(ssid=ssid, bssid=bssid, passkey=passkey, encryption=security,
                                     band=band, vlan_id=vlan_id[0], mode=mode, num_sta=num_sta)

        logging.info("Setup interface data:\n" + json.dumps(str(data), indent=2))
        allure.attach(name="Interface Info: \n", body=json.dumps(str(data), indent=2),
                      attachment_type=allure.attachment_type.JSON)
        if data == {}:
            pytest.skip("Skipping This Test")
        sta_connect_obj = []
        for dut in data:
            for radio in data[dut]["station_data"]:
                obj_sta_connect = StaConnect2(self.manager_ip, self.manager_http_port, outfile="shivam",
                                              _cleanup_on_exit=False)

                obj_sta_connect.sta_mode = sta_mode
                obj_sta_connect.upstream_resource = data[dut]["upstream_resource"]
                obj_sta_connect.upstream_port = data[dut]["upstream"]
                self.enable_verbose_debug(radio=radio, enable=True)
                obj_sta_connect.radio = radio
                obj_sta_connect.admin_down(obj_sta_connect.radio)
                obj_sta_connect.admin_up(obj_sta_connect.radio)
                obj_sta_connect.sta_prefix = data[dut]["sta_prefix"]
                obj_sta_connect.resource = radio.split(".")[1]
                obj_sta_connect.dut_ssid = ssid
                obj_sta_connect.dut_ssid = ssid
                obj_sta_connect.dut_passwd = passkey
                obj_sta_connect.dut_security = security
                obj_sta_connect.station_names = data[dut]["station_data"][radio]
                obj_sta_connect.runtime_secs = runtime_secs
                obj_sta_connect.bringup_time_sec = 80
                obj_sta_connect.cleanup_on_exit = True
                obj_sta_connect.download_bps = 128000
                obj_sta_connect.upload_bps = 128000
                obj_sta_connect.side_a_pdu = 1200
                obj_sta_connect.side_b_pdu = 1500

                # changed to auto channel
                self.set_radio_channel(radio=radio, channel="AUTO")
                logging.info("scan ssid radio: " + str(radio.split(".")[2]))
                result = self.scan_ssid(radio=radio, ssid=ssid)
                logging.info("ssid scan data : " + str(result))
                if not result:
                    # Sniffer required
                    for duts in self.dut_data:
                        identifier = duts["identifier"]
                        if dut_data.keys().__contains__(identifier):
                            if band == "twog":
                                if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("2G") and \
                                        dict(dut_data.get(identifier)["radio_data"])["2G"] is not None:
                                    channel = dict(dut_data.get(identifier)["radio_data"])["2G"]["channel"]
                                    if data[dut]["sniff_radio_2g"] is not None:
                                        self.start_sniffer(radio_channel=channel,
                                                           radio=data[dut]["sniff_radio_2g"].split(".")[2],
                                                           duration=10)
                                        time.sleep(10)
                                        self.stop_sniffer()
                            elif band == "fiveg":
                                if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("5G") and \
                                        dict(dut_data.get(identifier)["radio_data"])["5G"] is not None:
                                    channel = dict(dut_data.get(identifier)["radio_data"])["5G"]["channel"]
                                    if data[dut]["sniff_radio_5g"] is not None:
                                        self.start_sniffer(radio_channel=channel,
                                                           radio=data[dut]["sniff_radio_5g"].split(".")[2],
                                                           duration=10)
                                        time.sleep(10)
                                        self.stop_sniffer()
                            elif band == "sixg":
                                if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("6G") and \
                                        dict(dut_data.get(identifier)["radio_data"])["6G"] is not None:
                                    channel = dict(dut_data.get(identifier)["radio_data"])["6G"]["channel"]
                                    if data[dut]["sniff_radio_6g"] is not None:
                                        self.start_sniffer(radio_channel=channel,
                                                           radio=data[dut]["sniff_radio_6g"].split(".")[2],
                                                           duration=10)
                                        time.sleep(10)
                                        self.stop_sniffer()
                if not result:
                    pytest.fail("SSID is not Available in Scan Result")
                obj_sta_connect.setup(extra_securities=extra_securities)
            sta_connect_obj.append(obj_sta_connect)
            for dut_ in self.dut_data:
                identifier = dut_["identifier"]
                if dut_data.keys().__contains__(identifier):
                    if band == "twog":
                        if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("2G") and \
                                dict(dut_data.get(identifier)["radio_data"])["2G"] is not None:
                            channel = dict(dut_data.get(identifier)["radio_data"])["2G"]["channel"]
                            self.start_sniffer(radio_channel=channel, radio=data[dut]["sniff_radio_2g"].split(".")[2],
                                               duration=runtime_secs)
                            logging.info("started-sniffer")
                            for obj in sta_connect_obj:
                                obj.start()
                            logging.info("napping %f sec" % runtime_secs)
                            time.sleep(runtime_secs)
                            logging.info("stopping-sniffer")
                            self.stop_sniffer()
                    elif band == "fiveg":
                        if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("5G") and \
                                dict(dut_data.get(identifier)["radio_data"])["5G"] is not None:
                            channel = dict(dut_data.get(identifier)["radio_data"])["5G"]["channel"]
                            self.start_sniffer(radio_channel=channel, radio=data[dut]["sniff_radio_5g"].split(".")[2],
                                               duration=runtime_secs)
                            for obj in sta_connect_obj:
                                obj.start()
                            logging.info("napping %f sec" % runtime_secs)
                            time.sleep(runtime_secs)
                            self.stop_sniffer()
                    elif band == "sixg":
                        if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("6G") and \
                                dict(dut_data.get(identifier)["radio_data"])["6G"] is not None:
                            channel = dict(dut_data.get(identifier)["radio_data"])["6G"]["channel"]
                            self.start_sniffer(radio_channel=channel, radio=data[dut]["sniff_radio_6g"].split(".")[2],
                                               duration=runtime_secs)
                            for obj in sta_connect_obj:
                                obj.start()
                            logging.info("napping %f sec" % runtime_secs)
                            time.sleep(runtime_secs)
                            self.stop_sniffer()
                else:
                    for obj in sta_connect_obj:
                        obj.start()
                    logging.info("napping %f sec" % runtime_secs)
                    time.sleep(runtime_secs)
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
                upstream.append(data[dut]["upstream_port"])
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
        for obj in sta_connect_obj:
            try:
                print("1." + str(obj.resource) + "." + str(obj.radio))
                self.get_supplicant_logs(radio=str(obj.radio))
            except Exception as e:
                logging.error("client_cpnnectivity_tests() -- Error in getting Supplicant Logs:" + str(e))
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
                       vlan_id=[None], num_sta=None, scan_ssid=True, sta_mode=0,
                       station_data=["4way time (us)", "channel", "cx time (us)", "dhcp (ms)", "ip", "signal"],
                       allure_attach=True, identifier=None, allure_name="station data"):
        if identifier is None:
            identifier = self.dut_data[0]["identifier"]
            logging.info("Identifier: " + str(identifier))
        else:
            all_identifier_list = []
            for dut in self.dut_data:
                all_identifier_list.append(self.dut_data[dut]["indentifier"])
            print(all_identifier_list)
            if identifier not in all_identifier_list:
                logging.error("Identifier is missinhg")
                pytest.fail("Identifier is missinhg")

        data = self.setup_interfaces(ssid=ssid, passkey=passkey, encryption=security,
                                     band=band, vlan_id=vlan_id[0], mode=mode, num_sta=num_sta)

        logging.info("Setup interface data:\n" + json.dumps(str(data), indent=2))
        allure.attach(name="Interface Info: \n", body=json.dumps(str(data), indent=2),
                      attachment_type=allure.attachment_type.JSON)
        if data == {}:
            pytest.skip("Skipping This Test")
        client_connect_obj = []
        station_data_all = {}
        for radio in data[identifier]["station_data"]:
            client_connect = CreateStation(_host=self.manager_ip, _port=self.manager_http_port,
                                           _sta_list=data[identifier]["station_data"][radio], _password=data[identifier]["passkey"],
                                           _ssid=data[identifier]["ssid"],
                                           _security=data[identifier]["encryption"])
            client_connect.station_profile.sta_mode = sta_mode
            client_connect.upstream_resource = data[identifier]["upstream_resource"]
            client_connect.upstream_port = data[identifier]["upstream"]
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
                self.attach_table_allure(data=sta_table_dict, allure_name=allure_name)

        logging.info("pass_fail result: " + str(pass_fail))
        if False in pass_fail:
            logging.info("Station did not get an ip")
            pytest.fail("Station did not get an ip")
        else:
            logging.info("ALL Stations got IP's")
            return station_data_all

    # def dfs_test(self, ssid=None, security=None, passkey=None, mode=None,
    #              band=None, num_sta=1, vlan_id=[None], dut_data={}):
    #     """DFS test"""
    #     if len(dut_data) == 0:
    #         logging.error("DUT data is empty")
    #         pytest.fail("DUT data is empty")
    #     for identifier in dut_data:
    #         station_data = self.client_connect(ssid=ssid, security=security, passkey=passkey, mode=mode,
    #                                            band=band, num_sta=num_sta, vlan_id=vlan_id,
    #                                            allure_name="Data before simulate radar", identifier=identifier)
    #         station_list = list(station_data.kyes())
    #         pass_fail = []
    #         logging.info("AP channel: " + str(ap_channel))
    #
    #         #run the simulate radar command






    def add_stations(self, band="2G", num_stations=9, ssid_name="", dut_data={}, identifier=None):

        dut_name = []
        # for index in range(0, len(self.dut_data)):
        #     dut_name.append(self.dut_data[index]["identifier"])
        if num_stations == 0:
            logging.warning("0 Stations")
            return
        r_val = dict()
        for dut in self.dut_data:
            r_val[dut["identifier"]] = None
        idx = None
        # updating ssids on all APS
        if self.run_lf:
            for dut in self.dut_data:
                ssid_data = []
                if r_val.keys().__contains__(dut["identifier"]):
                    if dut.keys().__contains__("ssid"):
                        if band == "2G":
                            if str(dut["ssid"]["2g-encryption"]).upper() == "OPEN":
                                ssid_data.append(['ssid_idx=0 ssid=' + dut["ssid"]["2g-ssid"] +
                                                  ' bssid=' + dut["ssid"]["2g-bssid"]])
                                print(ssid_data)
                            else:
                                ssid_data.append(['ssid_idx=0 ssid=' + dut["ssid"]["2g-ssid"] +
                                                  ' security=' + str(dut["ssid"]["2g-encryption"]).upper() +
                                                  ' password=' + dut["ssid"]["2g-password"] +
                                                  ' bssid=' + dut["ssid"]["2g-bssid"]])
                            self.update_duts(identifier=dut["identifier"], ssid_data=ssid_data)
                        if band == "5G":
                            if str(dut["ssid"]["5g-encryption"]).upper() == "OPEN":
                                ssid_data.append(['ssid_idx=1 ssid=' + dut["ssid"]["5g-ssid"] +
                                                  ' bssid=' + dut["ssid"]["5g-bssid"]])
                            else:
                                ssid_data.append(['ssid_idx=1 ssid=' + dut["ssid"]["5g-ssid"] +
                                                  ' security=' + str(dut["ssid"]["5g-encryption"]).upper() +
                                                  ' password=' + dut["ssid"]["5g-password"] +
                                                  ' bssid=' + dut["ssid"]["5g-bssid"]])
                            self.update_duts(identifier=dut["identifier"], ssid_data=ssid_data)
                        if band == "6G":
                            if str(dut["ssid"]["6g-encryption"]).upper() == "OPEN":
                                ssid_data.append(['ssid_idx=2 ssid=' + dut["ssid"]["6g-ssid"] +
                                                  ' bssid=' + dut["ssid"]["6g-bssid"]])
                            else:
                                ssid_data.append(['ssid_idx=2 ssid=' + dut["ssid"]["6g-ssid"] +
                                                  ' security=' + str(dut["ssid"]["6g-encryption"]).upper() +
                                                  ' password=' + dut["ssid"]["6g-password"] +
                                                  ' bssid=' + dut["ssid"]["6g-bssid"]])
                            self.update_duts(identifier=dut["identifier"], ssid_data=ssid_data)
        else:
            for dut in self.dut_data:
                ssid_data = []
                identifier = dut["identifier"]
                if r_val.keys().__contains__(identifier):
                    for idx_ in dut_data[identifier]["ssid_data"]:

                        if str(dut_data[identifier]["ssid_data"][idx_]["encryption"]).upper() == "OPEN":
                            ssid_data.append(
                                ['ssid_idx=' + str(idx_) + ' ssid=' + dut_data[identifier]["ssid_data"][idx_]["ssid"]
                                 +
                                 ' bssid=' + str(dut_data[identifier]["ssid_data"][idx_]["bssid"]).upper()])
                        else:
                            ssid_data.append(
                                ['ssid_idx=' + str(idx_) + ' ssid=' + dut_data[identifier]["ssid_data"][idx_]["ssid"] +
                                 ' security=' + str(dut_data[identifier]["ssid_data"][idx_]["encryption"]).upper() +
                                 ' password=' + dut_data[identifier]["ssid_data"][idx_]["password"] +
                                 ' bssid=' + str(dut_data[identifier]["ssid_data"][idx_]["bssid"]).upper()])

                        if str(dut_data[identifier]["ssid_data"][idx_]["encryption"]).upper() in ["OPEN", "WPA", "WPA2",
                                                                                                  "WPA3", "WEP"]:
                            self.update_duts(identifier=identifier, ssid_data=ssid_data)

        dict_all_radios_2g = {"wave2_2g_radios": self.wave2_2g_radios,
                              "wave1_radios": self.wave1_radios, "mtk_radios": self.mtk_radios,
                              "ax200_radios": self.ax200_radios,
                              "ax210_radios": self.ax210_radios}

        dict_all_radios_5g = {"wave2_5g_radios": self.wave2_5g_radios,
                              "wave1_radios": self.wave1_radios, "mtk_radios": self.mtk_radios,
                              "ax200_radios": self.ax200_radios,
                              "ax210_radios": self.ax210_radios}

        dict_all_radios_6g = {"ax210_radios": self.ax210_radios}

        max_station_per_radio = {"wave2_2g_radios": 64, "wave2_5g_radios": 64, "wave1_radios": 64, "mtk_radios": 19,
                                 "ax200_radios": 1, "ax210_radios": 1}
        radio_data = {}
        sniff_radio = ""
        if self.run_lf or self.cc_1:
            if band == "2G":
                idx = 0
            if band == "5G":
                idx = 1
            if band == "6g":
                idx = 2
        else:
            for dut in dut_name:
                for idx_ in self.dut_data[dut]["ssid_data"]:
                    if band == self.dut_data[dut]["ssid_data"][idx_]["band"] and ssid_name == \
                            self.dut_data[dut]["ssid_data"][idx_]["ssid"]:
                        idx = idx_
        print("*********idx***********", idx)
        if band == "2G":
            stations = None
            if num_stations != "max":
                if num_stations <= int(self.max_2g_stations):
                    stations = num_stations
                else:
                    stations = int(self.max_2g_stations)
            if num_stations == "max":
                stations = int(self.max_2g_stations)
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
        if band == "5G":
            stations = None
            if num_stations != "max":
                if num_stations <= int(self.max_5g_stations):
                    stations = num_stations
                else:
                    stations = int(self.max_5g_stations)
            if num_stations == "max":
                stations = int(self.max_5g_stations)
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

        if band == "6G":
            stations = None
            if num_stations != "max":
                if num_stations <= int(self.max_6g_stations):
                    stations = num_stations
                else:
                    stations = int(self.max_6g_stations)
            if num_stations == "max":
                stations = int(self.max_6g_stations)

            # radio and station selection
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

        print(radio_data)
        for radio in radio_data:
            if identifier is None:
                logging.error("Identifier is None")
                pytest.fail("Identifier is None")
            station_data = ["profile_link " + radio.split(".")[0] + "." + radio.split(".")[1] +
                            " STA-AUTO " + str(radio_data[radio]) + " 'DUT: " + identifier + " Radio-" +
                            str(int(idx) + 1) + "'" + " NA " + radio.split(".")[2]]
            self.temp_raw_lines.append(station_data)
            print(self.temp_raw_lines)

    def wifi_capacity(self, mode="BRIDGE", vlan_id=100, batch_size="1,5,10,20,40,64,128",
                      instance_name="wct_instance", download_rate="1Gbps", influx_tags="",
                      upload_rate="1Gbps", protocol="TCP-IPv4", duration="60000", stations="", create_stations=True,
                      sort="interleave", raw_lines=[], move_to_influx=False, dut_data={}, ssid_name=None,
                      num_stations={}):
        wificapacity_obj_list = []
        for dut in self.dut_data:
            sets = [["DUT_NAME", dut["model"]]]
            identifier = dut["identifier"]
            print("sets", sets)
            instance_name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
            if mode == "BRIDGE":
                ret = self.get_wan_upstream_ports()
                upstream_port = ret[identifier]

            if mode == "NAT-WAN":
                ret = self.get_wan_upstream_ports()
                upstream_port = ret[identifier]

            if mode == "NAT-LAN":
                ret = self.get_lan_upstream_ports()
                upstream_port = ret[identifier]
            if mode == "VLAN":
                if vlan_id is None:
                    logging.error("VLAN ID is Unspecified in the VLAN Case")
                    pytest.skip("VLAN ID is Unspecified in the VLAN Case")
                else:
                    self.add_vlan(vlan_ids=[vlan_id])
                    ret = self.get_wan_upstream_ports()
                    upstream_port = ret[identifier] + "." + str(vlan_id)
            logging.info("Upstream data: " + str(upstream_port))
            sets = [["DUT_NAME", dut]]
            '''SINGLE WIFI CAPACITY using lf_wifi_capacity.py'''
            for band_ in num_stations:
                if band_ not in ["2G", "5G", "6G"]:
                    logging.error("Band is missing")
                    pytest.fail("band is missing")

                if not isinstance(num_stations[band_], int) or num_stations[band_] == "max":
                    logging.error("Number of stations are wrong")
                    pytest.fail("Number of stations are wrong")
                if ssid_name is None:
                    logging.error("ssid name is missing")
                    pytest.fail("ssid name is missing")
                self.add_stations(band=band_, num_stations=num_stations[band_], ssid_name=ssid_name, dut_data=dut_data,
                                  identifier=identifier)
            self.chamber_view(raw_lines="custom")
            wificapacity_obj = WiFiCapacityTest(lfclient_host=self.manager_ip,
                                                lf_port=self.manager_http_port,
                                                ssh_port=self.manager_ssh_port,
                                                lf_user="lanforge",
                                                lf_password="lanforge",
                                                local_lf_report_dir=self.local_report_path,
                                                instance_name=instance_name,
                                                config_name="wifi_config",
                                                upstream=upstream_port,
                                                batch_size=batch_size,
                                                loop_iter="1",
                                                protocol=protocol,
                                                duration=duration,
                                                pull_report=True,
                                                load_old_cfg=False,
                                                upload_rate=upload_rate,
                                                download_rate=download_rate,
                                                sort=sort,
                                                stations=stations,
                                                create_stations=create_stations,
                                                radio=None,
                                                security=None,
                                                paswd=None,
                                                ssid=None,
                                                enables=[],
                                                disables=[],
                                                raw_lines=raw_lines,
                                                raw_lines_file="",
                                                test_tag=influx_tags,
                                                sets=sets)
            wificapacity_obj.setup()
            wificapacity_obj.run()
            if move_to_influx:
                try:
                    report_name = "../reports/" + \
                                  wificapacity_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1] + "/"
                    influx = CSVtoInflux(influx_host=self.influx_params["influx_host"],
                                         influx_port=self.influx_params["influx_port"],
                                         influx_org=self.influx_params["influx_org"],
                                         influx_token=self.influx_params["influx_token"],
                                         influx_bucket=self.influx_params["influx_bucket"],
                                         path=report_name)

                    influx.glob()
                except Exception as e:
                    print(e)
                    pass
            report_name = wificapacity_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1] + "/"

            self.attach_report_graphs(report_name=report_name)
            self.attach_report_kpi(report_name=report_name)
            wificapacity_obj_list.append(wificapacity_obj)
        return wificapacity_obj_list

        # for dut in dut_name:
        #     logging.info("Adding Stations:" + band + " band, Number of Stations: " + str(num_stations) +
        #                  " DUT: " + str(dut) + " SSID: " + str(ssid_name) + " idx: " + str(idx))
        #     idx = idx
        #     if self.run_lf or self.cc_1:
        #         if band == "2G":
        #             idx = 0
        #         if band == "5G":
        #             idx = 1
        #         if band == "6g":
        #             idx = 2
        #
        #     for i in self.dut_idx_mapping:
        #         if self.dut_idx_mapping[i][0] == ssid_name and self.dut_idx_mapping[i][3] == band:
        #             idx = i
        #     if band == "2G":
        #         all_radio_2g = self.wave2_2g_radios + self.wave1_radios + self.mtk_radios + self.ax200_radios + \
        #                        self.ax210_radios
        #         print("all_2g_rdio", all_radio_2g)
        #         if num_stations != "max":
        #             logging.info("Total 2G Radios Available in Testbed: " + str(len(all_radio_2g)))
        #             total_sta = num_stations
        #             max_possible = 0
        #             for radio in all_radio_2g:
        #                 max_possible = max_possible + int(self.get_max_sta(radio))
        #             if total_sta <= max_possible:
        #                 per_radio_sta = int(total_sta / len(all_radio_2g))
        #                 rem = total_sta % len(all_radio_2g)
        #             else:
        #                 total_sta = max_possible
        #                 per_radio_sta = int(total_sta / len(all_radio_2g))
        #                 rem = total_sta % len(all_radio_2g)
        #             if rem != 0 and per_radio_sta == 0:
        #                 per_radio_sta = rem / len(all_radio_2g)
        #             logging.info("Total stations per radio: " + str(per_radio_sta))
        #             for radio in all_radio_2g:
        #                 max_possible = int(self.get_max_sta(radio))
        #                 if total_sta == 0:
        #                     return
        #                 num_stations = per_radio_sta
        #                 if rem == 0 and num_stations == 0:
        #                     return
        #                 if max_possible - num_stations >= rem:
        #                     num_stations = num_stations + rem
        #                     rem = 0
        #                 elif max_possible - rem >= num_stations:
        #                     num_stations = num_stations + rem
        #                     rem = 0
        #                 elif total_sta <= max_possible:
        #                     num_stations = total_sta
        #                 if per_radio_sta < 1:
        #                     num_stations = 1
        #                     total_sta = total_sta - num_stations
        #                 logging.info("Adding " + str(num_stations) + " Stations on " + str(radio))
        #                 station_data = ["profile_link " + radio.split(".")[0] + "." + radio.split(".")[1] +
        #                                 " STA-AUTO " + str(num_stations) + " 'DUT: " + dut + " Radio-" +
        #                                 str(int(idx) + 1) + "'" + " NA " + radio.split(".")[2]]
        #                 self.temp_raw_lines.append(station_data)
        #                 logging.debug("Raw Line : " + str(station_data))
        #
        #         if num_stations == "max":
        #             logging.info("Total 2G Radios Available in Testbed: " + str(len(all_radio_2g)))
        #             for radio in all_radio_2g:
        #                 num_stations = self.get_max_sta(radio)
        #                 logging.info("Total stations: " + str(num_stations) + " On Radio: " + str(radio))
        #                 station_data = ["profile_link " + radio.split(".")[0] + "." + radio.split(".")[1] +
        #                                 " STA-AUTO " + str(num_stations) + " 'DUT: " + dut + " Radio-" +
        #                                 str(int(idx) + 1) + "'" + " NA " + radio.split(".")[2]]
        #                 self.temp_raw_lines.append(station_data)
        #                 logging.debug("Raw Line : " + str(station_data))
        #
        #     if band == "5G":
        #         all_radio_5g = self.wave2_5g_radios + self.wave1_radios + self.mtk_radios + self.ax200_radios + self.ax210_radios
        #         if num_stations != "max":
        #             logging.info("Total 5G Radios Available in Testbed: " + str(len(all_radio_5g)))
        #             total_sta = num_stations
        #             max_possible = 0
        #             for radio in all_radio_5g:
        #                 max_possible = max_possible + int(self.get_max_sta(radio))
        #             if total_sta <= max_possible:
        #                 per_radio_sta = int(total_sta / len(all_radio_5g))
        #                 rem = total_sta % len(all_radio_5g)
        #             else:
        #                 total_sta = max_possible
        #                 per_radio_sta = int(total_sta / len(all_radio_5g))
        #                 rem = total_sta % len(all_radio_5g)
        #             if rem != 0 and per_radio_sta == 0:
        #                 per_radio_sta = rem / len(all_radio_5g)
        #             logging.info("Total stations per radio: " + str(per_radio_sta))
        #             for radio in all_radio_5g:
        #                 max_possible = int(self.get_max_sta(radio))
        #                 if total_sta == 0:
        #                     return
        #                 num_stations = per_radio_sta
        #                 if rem == 0 and num_stations == 0:
        #                     return
        #                 if max_possible - num_stations >= rem:
        #                     num_stations = num_stations + rem
        #                     rem = 0
        #                 elif max_possible - rem >= num_stations:
        #                     num_stations = num_stations + rem
        #                     rem = 0
        #                 elif total_sta <= max_possible:
        #                     num_stations = total_sta
        #                 if per_radio_sta < 1:
        #                     num_stations = 1
        #                     total_sta = total_sta - num_stations
        #                 logging.info("Adding " + str(num_stations) + " Stations on " + str(radio))
        #                 station_data = ["profile_link " + radio.split(".")[0] + "." + radio.split(".")[1] +
        #                                 " STA-AUTO " + str(num_stations) + " 'DUT: " + dut + " Radio-" +
        #                                 str(int(idx) + 1) + "'" + " NA " + radio.split(".")[2]]
        #                 self.temp_raw_lines.append(station_data)
        #                 logging.debug("Raw Line : " + str(station_data))
        #
        #         if num_stations == "max":
        #             logging.info("Total 5G Radios Available in Testbed: " + str(len(all_radio_5g)))
        #             for radio in all_radio_5g:
        #                 num_stations = self.get_max_sta(radio)
        #                 logging.info("Total stations: " + str(num_stations) + " On Radio: " + str(radio))
        #                 station_data = ["profile_link " + radio.split(".")[0] + "." + radio.split(".")[1] +
        #                                 " STA-AUTO " + str(num_stations) + " 'DUT: " + dut + " Radio-" +
        #                                 str(int(idx) + 1) + "'" + " NA " + radio.split(".")[2]]
        #                 self.temp_raw_lines.append(station_data)
        #                 logging.debug("Raw Line : " + str(station_data))
        #     if band == "6g":
        #         all_radio_6g = self.ax210_radios
        #         if num_stations != "max":
        #             logging.info("Total 6G Radios Available in Testbed: " + str(len(all_radio_6g)))
        #             total_sta = num_stations
        #             max_possible = 0
        #             for radio in all_radio_6g:
        #                 max_possible = max_possible + int(self.get_max_sta(radio))
        #             if total_sta <= max_possible:
        #                 per_radio_sta = int(total_sta / len(all_radio_6g))
        #                 rem = total_sta % len(all_radio_6g)
        #             else:
        #                 total_sta = max_possible
        #                 per_radio_sta = int(total_sta / len(all_radio_6g))
        #                 rem = total_sta % len(all_radio_6g)
        #             if rem != 0 and per_radio_sta == 0:
        #                 per_radio_sta = rem / len(all_radio_6g)
        #             logging.info("Total stations per radio: " + str(per_radio_sta))
        #             for radio in all_radio_6g:
        #                 max_possible = int(self.get_max_sta(radio))
        #                 if total_sta == 0:
        #                     return
        #                 num_stations = per_radio_sta
        #                 if rem == 0 and num_stations == 0:
        #                     return
        #                 if max_possible - num_stations >= rem:
        #                     num_stations = num_stations + rem
        #                     rem = 0
        #                 elif max_possible - rem >= num_stations:
        #                     num_stations = num_stations + rem
        #                     rem = 0
        #                 elif total_sta <= max_possible:
        #                     num_stations = total_sta
        #                 if per_radio_sta < 1:
        #                     num_stations = 1
        #                     total_sta = total_sta - num_stations
        #                 logging.info("Adding " + str(num_stations) + " Stations on " + str(radio))
        #                 station_data = ["profile_link " + radio.split(".")[0] + "." + radio.split(".")[1] +
        #                                 " STA-AUTO " + str(num_stations) + " 'DUT: " + dut + " Radio-" +
        #                                 str(int(idx) + 1) + "'" + " NA " + radio.split(".")[2]]
        #                 self.temp_raw_lines.append(station_data)
        #                 logging.debug("Raw Line : " + str(station_data))
        #         if num_stations == "max":
        #             logging.info("Total AX Radios Available in Testbed: " + str(len(all_radio_6g)))
        #             for radio in all_radio_6g:
        #                 num_stations = self.get_max_sta(radio)
        #                 logging.info("Total stations: " + str(num_stations) + " On Radio: " + str(radio))
        #                 station_data = ["profile_link " + radio.split(".")[0] + "." + radio.split(".")[1] +
        #                                 " STA-AUTO " + str(num_stations) + " 'DUT: " + dut + " Radio-" +
        #                                 str(int(idx) + 1) + "'" + " NA " + radio.split(".")[2]]
        #                 self.temp_raw_lines.append(station_data)
        #                 logging.debug("Raw Line : " + str(station_data))


if __name__ == '__main__':
    basic_04 = {
        "target": "tip_2x",
        "controller": {
            "url": "https://sec-qa01.cicd.lab.wlan.tip.build:16001",
            "username": "tip@ucentral.com",
            "password": "OpenWifi%123"
        },
        "device_under_tests": [{
            "model": "cig_wf196",
            "supported_bands": ["2G", "5G", "6G"],
            "supported_modes": ["BRIDGE", "NAT", "VLAN"],
            "wan_port": "1.3.eth2",
            "lan_port": None,
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
            "mode": "wifi6e",
            "identifier": "824f816011e4",
            "method": "serial",
            "host_ip": "localhost",
            "host_username": "lanforge",
            "host_password": "pumpkin77",
            "host_ssh_port": 22,
            "serial_tty": "/dev/ttyAP5",
            "firmware_version": "next-latest"
        }],
        "traffic_generator": {
            "name": "lanforge",
            "testbed": "basic",
            "scenario": "dhcp-bridge",
            "details": {
                "manager_ip": "10.28.3.12",
                "http_port": 8080,
                "ssh_port": 22,
                "setup": {"method": "build", "DB": "Test_Scenario_Automation"},
                "wan_ports": {
                    "1.3.eth2": {"addressing": "dhcp-server", "subnet": "172.16.0.1/16", "dhcp": {
                        "lease-first": 10,
                        "lease-count": 10000,
                        "lease-time": "6h"
                    }
                                 }
                },
                "lan_ports": {

                },
                "uplink_nat_ports": {
                    "1.1.eth3": {
                        "addressing": "dhcp-server",
                        "ip": "10.28.2.9",
                        "gateway_ip": "10.28.2.1/24",
                        "ip_mask": "255.255.255.0",
                        "dns_servers": "BLANK"
                    }
                }
            }
        }
    }

    obj = lf_tests(lf_data=dict(basic_04["traffic_generator"]), dut_data=list(basic_04["device_under_tests"]),
                   log_level=logging.DEBUG, run_lf=False)
    # obj.add_stations()
    # obj.add_stations(band="5G")
    # obj.chamber_view(raw_lines="custom")
    # dut = {'0000c1018812': {"ssid_data": {
    #     0: {"ssid": 'TestSSID-2G', "encryption": 'wpa2', "password": 'OpenWifi', "band": '2G',
    #         "bssid": '00:00:C1:01:88:15'},
    #     1: {"ssid": 'TestSSID-5G', "encryption": 'wpa2', "password": 'OpenWifi', "band": '5G',
    #         "bssid": '00:00:C1:01:88:14'}}, "radio_data": {'2G': [1, 40, 2422], '5G': [36, 80, 5210], '6G': None}}}
    # obj.wifi_capacity(instance_name="test_client_wpa2_BRIDGE_udp_bi", mode="BRIDGE",
    #                   vlan_id=[100],
    #                   download_rate="1Gbps", batch_size="1,5,10,20,40,64,128,256",
    #                   influx_tags="Jitu",
    #                   upload_rate="1Gbps", protocol="UDP-IPv4", duration="60000",
    #                   move_to_influx=False, dut_data=dut, ssid_name="OpenWifi",
    #                   num_stations={"2G": 10, "5G": 10})
    # A =obj.setup_interfaces(band="fiveg", vlan_id=100, mode="NAT-WAN", num_sta=1)
    # print(A)
    # obj.setup_relevent_profiles()
    # obj.client_connect(ssid="OpenWifi", passkey="OpenWifi", security="wpa2", mode="BRIDGE", band="twog",
    #                    vlan_id=[None], num_sta=65, scan_ssid=True,
    #                    station_data=["4way time (us)", "channel", "cx time (us)", "dhcp (ms)", "ip", "signal"],
    #                    allure_attach=True)
    obj.dfs_test(ssid="OpenWifi", security="wpa2", passkey="OpenWifi", mode="BRIDGE",
                 band="fiveg", num_sta=1)
    # obj.add_vlan(vlan_iFds=[100])
    # obj.create_dhcp_external()obj.add_vlan(vlan_ids=[100, 200, 300, 400, 500, 600])
    # obj.get_cx_data()
    # obj.chamber_view()
    # dut = {'0000c1018812': [['ssid_open_2g_nat', 'open', 'something', '2G', '6A:21:5F:DA:45:6F'],
    #                         {'2G': [6, 40, 2437], '5G': None, '6G': None}]}

    # passes, result = obj.client_connectivity_test(ssid="ssid_open_2g_nat", passkey="something", security="open",
    #                                               extra_securities=[],
    #                                               num_sta=1, mode="NAT-WAN", dut_data=dut,
    #                                               band="twog")
    # print(passes == "PASS", result)
    # # obj.start_sniffer(radio_channel=1, radio="wiphy7", test_name="sniff_radio", duration=30)
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
