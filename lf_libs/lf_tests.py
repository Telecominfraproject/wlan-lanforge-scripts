import csv
import importlib
import json
import logging
import os
import sys
import time
import string
import random
import threading
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
lf_dataplane_test = importlib.import_module("py-scripts.lf_dataplane_test")
DataplaneTest = lf_dataplane_test.DataplaneTest
ttlstest = importlib.import_module("py-scripts.test_ipv4_ttls")
TTLSTest = ttlstest.TTLSTest
tr398v2test = importlib.import_module("py-scripts.lf_tr398v2_test")
TR398v2Test = tr398v2test.TR398v2Test
rvr = importlib.import_module("py-scripts.lf_rvr_test")
rvr_test = rvr.RvrTest


class lf_tests(lf_libs):
    """
        lf_tools is needed in lf_tests to do various operations needed by various tests
    """

    def __init__(self, lf_data={}, dut_data={}, log_level=logging.DEBUG, run_lf=False, influx_params=None,
                 local_report_path="../reports/"):
        super().__init__(lf_data, dut_data, run_lf, log_level)
        self.local_report_path = local_report_path,
        self.influx_params = influx_params

    def client_connectivity_test(self, ssid="[BLANK]", passkey="[BLANK]", bssid="[BLANK]", dut_data={},
                                 security="open", extra_securities=[], sta_mode=0,
                                 num_sta=1, mode="BRIDGE", vlan_id=[None], band="twog",
                                 allure_attach=True, runtime_secs=40):
        self.check_band_ap(band=band)
        if self.run_lf:
            dut_data = self.run_lf_dut_data()
        logging.info("DUT Data:\n" + json.dumps(str(dut_data), indent=2))
        allure.attach(name="DUT Data:\n", body=json.dumps(str(dut_data), indent=2),
                      attachment_type=allure.attachment_type.JSON)

        data = self.setup_interfaces(ssid=ssid, bssid=bssid, passkey=passkey, encryption=security,
                                     band=band, vlan_id=vlan_id, mode=mode, num_sta=num_sta, dut_data_=dut_data)
        logging.info("Setup interface data:\n" + json.dumps(str(data), indent=2))
        allure.attach(name="Interface Info: \n", body=json.dumps(str(data), indent=2),
                      attachment_type=allure.attachment_type.JSON)
        if data == {}:
            pytest.skip("Skipping This Test")
        # list of multiple sta_connect objects
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
                obj_sta_connect.dut_ssid = data[dut]["ssid"]
                obj_sta_connect.dut_passwd = data[dut]["passkey"]
                obj_sta_connect.dut_security = data[dut]["encryption"]
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
                result = self.scan_ssid(radio=radio, ssid=data[dut]["ssid"])
                logging.info("ssid scan data : " + str(result))
                if not result:
                    # Sniffer required
                    for duts in self.dut_data:
                        identifier = duts["identifier"]
                        if dut_data.keys().__contains__(identifier):
                            if band == "twog":
                                if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("2G") and \
                                        dict(dut_data.get(identifier)["radio_data"])["2G"] is not None:
                                    channel = data[dut]["channel"]
                                    if data[dut]["sniff_radio_2g"] is not None and channel is not None:
                                        self.start_sniffer(radio_channel=channel,
                                                           radio=data[dut]["sniff_radio_2g"],
                                                           duration=10)
                                        time.sleep(10)
                                        self.stop_sniffer()
                            elif band == "fiveg":
                                if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("5G") and \
                                        dict(dut_data.get(identifier)["radio_data"])["5G"] is not None:
                                    channel = data[dut]["channel"]
                                    if data[dut]["sniff_radio_5g"] is not None and channel is not None:
                                        self.start_sniffer(radio_channel=channel,
                                                           radio=data[dut]["sniff_radio_5g"],
                                                           duration=10)
                                        time.sleep(10)
                                        self.stop_sniffer()
                            elif band == "sixg":
                                if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("6G") and \
                                        dict(dut_data.get(identifier)["radio_data"])["6G"] is not None:
                                    channel = self.lf_sixg_lookup_validation(int(data[dut]["channel"]))
                                    logging.info("LF sixg channel: " + str(channel))
                                    if data[dut]["sniff_radio_6g"] is not None and channel is not None:
                                        self.start_sniffer(radio_channel=channel,
                                                           radio=data[dut]["sniff_radio_6g"],
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
                            channel = data[dut]["channel"]
                            if data[dut]["sniff_radio_2g"] is not None and channel is not None:
                                self.start_sniffer(radio_channel=channel,
                                                   radio=data[dut]["sniff_radio_2g"],
                                                   duration=runtime_secs)
                            logging.info("started-sniffer")
                            for obj in sta_connect_obj:
                                obj.start()
                            logging.info("napping %f sec" % runtime_secs)
                            time.sleep(runtime_secs)
                            logging.info("stopping-sniffer")
                            if data[dut]["sniff_radio_2g"] is not None and channel is not None:
                                self.stop_sniffer()
                    elif band == "fiveg":
                        if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("5G") and \
                                dict(dut_data.get(identifier)["radio_data"])["5G"] is not None:
                            channel = data[dut]["channel"]
                            if data[dut]["sniff_radio_5g"] is not None and channel is not None:
                                self.start_sniffer(radio_channel=channel,
                                                   radio=data[dut]["sniff_radio_5g"],
                                                   duration=runtime_secs)
                            for obj in sta_connect_obj:
                                obj.start()
                            logging.info("napping %f sec" % runtime_secs)
                            time.sleep(runtime_secs)
                            if data[dut]["sniff_radio_5g"] is not None and channel is not None:
                                self.stop_sniffer()
                    elif band == "sixg":
                        if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("6G") and \
                                dict(dut_data.get(identifier)["radio_data"])["6G"] is not None:
                            channel = self.lf_sixg_lookup_validation(int(data[dut]["channel"]))
                            logging.info("LF sixg channel: " + str(channel))
                            if data[dut]["sniff_radio_6g"] is not None and channel is not None:
                                self.start_sniffer(radio_channel=channel,
                                                   radio=data[dut]["sniff_radio_6g"],
                                                   duration=runtime_secs)
                            for obj in sta_connect_obj:
                                obj.start()
                            logging.info("napping %f sec" % runtime_secs)
                            time.sleep(runtime_secs)
                            if data[dut]["sniff_radio_6g"] is not None and channel is not None:
                                self.stop_sniffer()
                else:
                    for obj in sta_connect_obj:
                        obj.start()
                    logging.info("napping %f sec" % runtime_secs)
                    time.sleep(runtime_secs)
        pass_fail_result = []
        for obj in sta_connect_obj:
            sta_rows = ["4way time (us)", "channel", "cx time (us)", "dhcp (ms)", "ip", "signal", "mac"]
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
                # print("1." + str(obj.resource) + "." + str(obj.radio))
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

    def enterprise_client_connectivity_test(self, ssid="[BLANK]", passkey="[BLANK]", bssid="[BLANK]", dut_data={},
                                            security="open", extra_securities=[], sta_mode=0, key_mgmt="WPA-EAP",
                                            pairwise="NA", group="NA", wpa_psk="DEFAULT", ttls_passwd="nolastart",
                                            ieee80211w=1, wep_key="NA", ca_cert="NA", eap="TTLS", identity="nolaradius",
                                            d_vlan=False, cleanup=True,
                                            num_sta=1, mode="BRIDGE", vlan_id=[None], band="twog",
                                            allure_attach=True, runtime_secs=40, pk_passwd="whatever"):
        self.check_band_ap(band=band)
        logging.info("DUT Data:\n" + json.dumps(str(dut_data), indent=2))
        allure.attach(name="DUT Data:\n", body=json.dumps(str(dut_data), indent=2),
                      attachment_type=allure.attachment_type.JSON)

        if self.run_lf:
            dut_data = self.run_lf_dut_data()
        data = self.setup_interfaces(ssid=ssid, bssid=bssid, passkey=passkey, encryption=security,
                                     band=band, vlan_id=vlan_id, mode=mode, num_sta=num_sta, dut_data_=dut_data)

        logging.info("Setup interface data:\n" + json.dumps(str(data), indent=2))
        allure.attach(name="Interface Info: \n", body=json.dumps(str(data), indent=2),
                      attachment_type=allure.attachment_type.JSON)
        if data == {}:
            pytest.skip("Skipping This Test")
        # list of multiple eap_connect objects
        eap_connect_objs = []
        for dut in data:
            for radio in data[dut]["station_data"]:
                obj_eap_connect = TTLSTest(host=self.manager_ip, port=self.manager_http_port,
                                           sta_list=data[dut]["station_data"][radio], vap=False, _debug_on=True)
                obj_eap_connect.station_profile.sta_mode = sta_mode
                obj_eap_connect.upstream_resource = data[dut]["upstream_resource"]
                obj_eap_connect.l3_cx_obj_udp.upstream_resource = data[dut]["upstream_resource"]
                obj_eap_connect.l3_cx_obj_tcp.upstream_resource = data[dut]["upstream_resource"]
                obj_eap_connect.l3_cx_obj_udp.upstream = data[dut]["upstream"]
                obj_eap_connect.l3_cx_obj_tcp.upstream = data[dut]["upstream"]
                self.enable_verbose_debug(radio=radio, enable=True)
                obj_eap_connect.radio = radio
                obj_eap_connect.admin_down(radio)
                obj_eap_connect.admin_up(radio)
                # changed to auto channel
                self.set_radio_channel(radio=radio, channel="AUTO")
                logging.info("scan ssid radio: " + str(radio.split(".")[2]))
                result = self.scan_ssid(radio=radio, ssid=data[dut]["ssid"])
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
                                    if data[dut]["sniff_radio_2g"] is not None and channel is not None:
                                        self.start_sniffer(radio_channel=channel,
                                                           radio=data[dut]["sniff_radio_2g"],
                                                           duration=10)
                                        time.sleep(10)
                                        self.stop_sniffer()
                            elif band == "fiveg":
                                if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("5G") and \
                                        dict(dut_data.get(identifier)["radio_data"])["5G"] is not None:
                                    channel = dict(dut_data.get(identifier)["radio_data"])["5G"]["channel"]
                                    if data[dut]["sniff_radio_5g"] is not None and channel is not None:
                                        self.start_sniffer(radio_channel=channel,
                                                           radio=data[dut]["sniff_radio_5g"],
                                                           duration=10)
                                        time.sleep(10)
                                        self.stop_sniffer()
                            elif band == "sixg":
                                if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("6G") and \
                                        dict(dut_data.get(identifier)["radio_data"])["6G"] is not None:
                                    channel = dict(dut_data.get(identifier)["radio_data"])["6G"]["channel"]
                                    if data[dut]["sniff_radio_6g"] is not None and channel is not None:
                                        self.start_sniffer(radio_channel=channel,
                                                           radio=data[dut]["sniff_radio_6g"],
                                                           duration=10)
                                        time.sleep(10)
                                        self.stop_sniffer()
                if not result:
                    pytest.fail("SSID is not Available in Scan Result")
                if eap == "TTLS":
                    obj_eap_connect.ieee80211w = ieee80211w
                    obj_eap_connect.key_mgmt = key_mgmt
                    obj_eap_connect.station_profile.set_command_flag("add_sta", "80211u_enable", 0)
                    obj_eap_connect.identity = identity
                    obj_eap_connect.ttls_passwd = ttls_passwd
                    obj_eap_connect.pairwise = pairwise
                    obj_eap_connect.group = group
                if eap == "TLS":
                    obj_eap_connect.key_mgmt = key_mgmt
                    obj_eap_connect.station_profile.set_command_flag("add_sta", "80211u_enable", 0)
                    obj_eap_connect.eap = eap
                    obj_eap_connect.identity = identity
                    obj_eap_connect.ttls_passwd = ttls_passwd
                    obj_eap_connect.private_key = "/home/lanforge/client.p12"
                    obj_eap_connect.ca_cert = "/home/lanforge/ca.pem"
                    obj_eap_connect.pk_passwd = pk_passwd
                    obj_eap_connect.ieee80211w = 1

                obj_eap_connect.ssid = data[dut]["ssid"]
                obj_eap_connect.password = data[dut]["passkey"]
                obj_eap_connect.security = data[dut]["encryption"]
                obj_eap_connect.sta_list = data[dut]["station_data"][radio]
                obj_eap_connect.build(extra_securities=extra_securities)
            eap_connect_objs.append(obj_eap_connect)
            for dut_ in self.dut_data:
                identifier = dut_["identifier"]
                if dut_data.keys().__contains__(identifier):
                    if band == "twog":
                        if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("2G") and \
                                dict(dut_data.get(identifier)["radio_data"])["2G"] is not None:
                            channel = dict(dut_data.get(identifier)["radio_data"])["2G"]["channel"]
                            if data[dut]["sniff_radio_2g"] is not None and channel is not None:
                                self.start_sniffer(radio_channel=channel,
                                                   radio=data[dut]["sniff_radio_2g"],
                                                   duration=runtime_secs)
                            logging.info("started-sniffer")
                            for obj in eap_connect_objs:
                                obj.start(obj.sta_list, True, True, wait_time=1)
                            logging.info("napping %f sec" % runtime_secs)
                            time.sleep(runtime_secs)
                            if data[dut]["sniff_radio_2g"] is not None and channel is not None:
                                self.stop_sniffer()
                    elif band == "fiveg":
                        if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("5G") and \
                                dict(dut_data.get(identifier)["radio_data"])["5G"] is not None:
                            channel = dict(dut_data.get(identifier)["radio_data"])["5G"]["channel"]
                            if data[dut]["sniff_radio_5g"] is not None and channel is not None:
                                self.start_sniffer(radio_channel=channel,
                                                   radio=data[dut]["sniff_radio_5g"],
                                                   duration=runtime_secs)
                            for obj in eap_connect_objs:
                                obj.start(obj.sta_list, True, True, wait_time=1)
                            logging.info("napping %f sec" % runtime_secs)
                            time.sleep(runtime_secs)
                            if data[dut]["sniff_radio_5g"] is not None and channel is not None:
                                self.stop_sniffer()
                    elif band == "sixg":
                        if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("6G") and \
                                dict(dut_data.get(identifier)["radio_data"])["6G"] is not None:
                            channel = dict(dut_data.get(identifier)["radio_data"])["6G"]["channel"]
                            if data[dut]["sniff_radio_6g"] is not None and channel is not None:
                                self.start_sniffer(radio_channel=channel,
                                                   radio=data[dut]["sniff_radio_6g"],
                                                   duration=runtime_secs)
                            for obj in eap_connect_objs:
                                obj.start(obj.sta_list, True, True, wait_time=1)
                            logging.info("napping %f sec" % runtime_secs)
                            time.sleep(runtime_secs)
                            if data[dut]["sniff_radio_6g"] is not None and channel is not None:
                                self.stop_sniffer()
                else:
                    for obj in eap_connect_objs:
                        obj.start(obj.sta_list, True, True, wait_time=1)
                    logging.info("napping %f sec" % runtime_secs)
                    time.sleep(runtime_secs)
        pass_fail_result = []
        for obj in eap_connect_objs:
            sta_rows = ["4way time (us)", "channel", "cx time (us)", "dhcp (ms)", "ip", "signal", "mac"]
            self.station_data = self.get_station_data(sta_name=obj.sta_list, rows=sta_rows,
                                                      allure_attach=False)
            sta_table_dict = {}
            sta_table_dict["station name"] = list(self.station_data.keys())
            for i in sta_rows:
                temp_list = []
                for j in obj.sta_list:
                    temp_list.append(self.station_data[j][i])
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
            cx_name = list(obj.l3_cx_obj_udp.cx_profile.get_cx_names()) + list(
                obj.l3_cx_obj_tcp.cx_profile.get_cx_names())
            cx_row = ["type", "bps rx a", "bps rx b"]
            cx_data = self.get_cx_data(cx_name=cx_name, cx_data=cx_row, allure_attach=False)
            cx_table_dict = {}
            upstream = []
            for i in range(len(obj.sta_list)):
                upstream.append(data[dut]["upstream_port"])
            cx_table_dict["Upstream"] = upstream
            cx_table_dict["Downstream"] = obj.sta_list
            cx_tcp_ul = []
            cx_tcp_dl = []
            cx_udp_ul = []
            cx_udp_dl = []
            for sta in obj.sta_list:
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
            if cleanup:
                obj.cleanup(obj.sta_list)
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
        for obj in eap_connect_objs:
            try:
                # print("1." + str(obj.resource) + "." + str(obj.radio))
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

    def multiband_performance_test(self):
        pass

    def multi_psk_test(self, band="twog", mpsk_data=None, ssid="OpenWifi", bssid="['BLANK']", passkey="OpenWifi",
                       encryption="wpa", mode="BRIDGE", num_sta=1, dut_data=None):
        if mpsk_data is None:
            mpsk_data = {100: {"num_stations": num_sta, "passkey": "OpenWifi1"},
                         200: {"num_stations": num_sta, "passkey": "OpenWifi2"}}

        logging.info("Creating VLAN's as per MPSK data")
        # create VLAN's
        vlan_ids = list(mpsk_data.keys())
        if "default" in vlan_ids:
            vlan_ids.remove("default")

        data = self.setup_interfaces(ssid=ssid, passkey=passkey, encryption=encryption,
                                     band=band, vlan_id=vlan_ids, mode="VLAN", num_sta=num_sta, dut_data_=dut_data)
        if data == {}:
            pytest.skip("Skipping This Test")

        logging.info("Setup interface data:\n" + json.dumps(str(data), indent=2))

        # query and fetch vlan Ip Address
        port_data = self.json_get(_req_url="/port?fields=alias,port+type,ip,mac")['interfaces']
        # Fail if Vlan don't have IP
        vlan_data = {}
        for i in port_data:
            for item in i:
                if i[item]['port type'] == '802.1Q VLAN' and i[item]['ip'] == '0.0.0.0':
                    logging.error(f"VLAN Interface - {i[item]['alias']} do not have IP")
                    pytest.fail("VLAN do not have IP")
                    break
                elif i[item]['port type'] == '802.1Q VLAN' and i[item]['ip'] != '0.0.0.0':
                    vlan_data[i[item]['alias'].split(".")[1]] = i[item]
                else:
                    pass

        # create stations
        sta_data = {}
        non_vlan_sta = ""
        if mode == "BRIDGE" or mode == "NAT-WAN":
            non_vlan_sta = "WAN Upstream"
            upstream_port = self.dut_data[0]["wan_port"]
            vlan_data[non_vlan_sta] = self.wan_ports[upstream_port]
        if mode == "NAT-LAN":
            non_vlan_sta = "LAN upstream"
            upstream_port = self.dut_data[0]["lan_port"]
            vlan_data[non_vlan_sta] = self.lan_ports[upstream_port]
        for key in list(mpsk_data.keys()):
            if key == "default":
                sta_data[non_vlan_sta] = self.client_connect(ssid=ssid, passkey=passkey, security=encryption, mode=mode,
                                                             band=band, pre_cleanup=False,
                                                             vlan_id=[None], num_sta=num_sta, scan_ssid=True,
                                                             station_data=["ip", "alias", "mac", "port type"],
                                                             allure_attach=True, dut_data=dut_data)
                self.client_disconnect(station_name=list(sta_data[non_vlan_sta].keys()))
            else:
                sta_data[key] = self.client_connect(ssid=ssid, passkey=mpsk_data[key]["passkey"], security=encryption,
                                                    mode=mode, band=band, pre_cleanup=False,
                                                    vlan_id=[None], num_sta=num_sta, scan_ssid=True,
                                                    station_data=["ip", "alias", "mac", "port type"],
                                                    allure_attach=True, dut_data=dut_data)
                self.client_disconnect(station_name=list(sta_data[key].keys()))

        logging.info("station data: " + str(sta_data))

        for dut in dut_data.keys():
            supplicants = list(data[str(dut)]['station_data'].keys())
            try:
                for supplicant in supplicants:
                    self.get_supplicant_logs(radio=str(supplicant))
            except Exception as e:
                logging.error(f"Error in getting Supplicant logs: {str(e)}")

        # check Pass/Fail
        table_heads = ["station name", "configured vlan-id", "expected IP Range", "allocated IP", "mac address",
                       'pass/fail']
        table_data = []
        pf = 'PASS'
        for i in sta_data:
            if (str(i) in vlan_data) and (str(i) != 'WAN Upstream' and str(i) != 'LAN Upstream'):
                for item in sta_data[i]:
                    exp1 = sta_data[i][item]['ip'].split('.')
                    ip1 = vlan_data[str(i)]['ip'].split('.')
                    if exp1[0] == ip1[0] and exp1[1] == ip1[1]:
                        pf = 'PASS'
                        logging.info(f"PASS: Station got IP from vlan {i}")
                    else:
                        pf = 'FAIL'
                        logging.info(f"FAIL: Station did not got IP from vlan {i}")
                    table_data.append(
                        [sta_data[i][item]['alias'], str(i), f'{exp1[0]}.{exp1[1]}.X.X', sta_data[i][item]['ip'],
                         sta_data[i][item]['mac'],
                         f'{pf}'])
            elif str(i) == "WAN Upstream" and mode == "BRIDGE":
                for item in sta_data[i]:
                    exp2 = sta_data[i][item]['ip'].split('.')
                    ip2 = vlan_data[str(i)]['subnet'].split('.')
                    if exp2[0] == ip2[0] and exp2[1] == ip2[1]:
                        pf = 'PASS'
                        logging.info(f"PASS: Station got IP from WAN Upstream")
                    else:
                        pf = 'FAIL'
                        logging.info(f"FAIL: Station did not got IP from WAN Upstream")
                    table_data.append(
                        [sta_data[i][item]['alias'], str(i), vlan_data[str(i)]['subnet'],
                         sta_data[i][item]['ip'], sta_data[i][item]['mac'],
                         f'{pf}'])
            elif str(i) == "WAN Upstream" and mode == "NAT-WAN":
                for item in sta_data[i]:
                    exp3 = sta_data[i][item]['ip'].split('.')
                    if exp3[0] == '192' and exp3[1] == '168':
                        pf = 'PASS'
                        logging.info(f"PASS: Station got IP from WAN Upstream")
                    else:
                        pf = 'FAIL'
                        logging.info(f"FAIL: Station did not got IP from WAN Upstream")
                    table_data.append(
                        [sta_data[i][item]['alias'], 'WAN upstream', f'192.168.X.X', sta_data[i][item]['ip'],
                         sta_data[i][item]['mac'], f'{pf}'])
            elif str(i) == "LAN Upstream":
                for item in sta_data[i]:
                    exp3 = sta_data[i][item]['ip'].split('.')
                    if exp3[0] == '192' and exp3[1] == '168':
                        pf = 'PASS'
                        logging.info(f"PASS: Station got IP from LAN Upstream")
                    else:
                        pf = 'FAIL'
                        logging.info(f"FAIL: Station did not got IP from LAN Upstream")
                    table_data.append(
                        [sta_data[i][item]['alias'], 'LAN upstream', f'192.168.X.X', sta_data[i][item]['ip'],
                         sta_data[i][item]['mac'], f'{pf}'])

        # attach test data in a table to allure
        report_obj = Report()
        table_info = report_obj.table2(table=table_data, headers=table_heads)
        logging.info(str("\n") + str(table_info))
        allure.attach(name="Test Results", body=table_info)
        if pf == 'FAIL':
            logging.info("Station did not get an ip or Obtained IP of Station is not in Expected Range")
            pytest.fail("Expected IP and Obtained IP are Different")
        else:
            logging.info("ALL Stations got IP as Expected")

    def client_connect(self, ssid="[BLANK]", passkey="[BLANK]", security="wpa2", mode="BRIDGE", band="twog",
                       vlan_id=[None], num_sta=None, scan_ssid=True, sta_mode=0, pre_cleanup=True,
                       station_data=["4way time (us)", "channel", "cx time (us)", "dhcp (ms)", "ip", "signal"],
                       allure_attach=True, identifier=None, allure_name="station data", client_type=None, dut_data={}):
        # pre cleanup
        if pre_cleanup:
            self.pre_cleanup()
        self.check_band_ap(band=band)
        if identifier is None:
            identifier = self.dut_data[0]["identifier"]
            logging.info("Identifier: " + str(identifier))
        else:
            all_identifier_list = []
            for dut in self.dut_data:
                all_identifier_list.append(dut["identifier"])
            print(all_identifier_list)
            if identifier not in all_identifier_list:
                logging.error("Identifier is missing")
                pytest.fail("Identifier is missing")
        if self.run_lf:
            dut_data = self.run_lf_dut_data()

        data = self.setup_interfaces(ssid=ssid, passkey=passkey, encryption=security,
                                     band=band, vlan_id=vlan_id, mode=mode, num_sta=num_sta, dut_data_=dut_data)

        logging.info("Setup interface data:\n" + json.dumps(str(data), indent=2))
        allure.attach(name="Interface Info: \n", body=json.dumps(str(data), indent=2),
                      attachment_type=allure.attachment_type.JSON)
        if data == {}:
            pytest.skip("Skipping This Test")
        client_connect_obj = []
        station_data_all = {}
        for radio in data[identifier]["station_data"]:
            if band == "twog":
                if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("2G") and \
                        dict(dut_data.get(identifier)["radio_data"])["2G"] is not None:
                    sniffer_channel = dict(dut_data.get(identifier)["radio_data"])["2G"]["channel"]
                    if data[identifier]["sniff_radio_2g"] is not None and sniffer_channel is not None:
                        self.start_sniffer(radio_channel=sniffer_channel, test_name=f'{data[identifier]["station_data"][radio][0]}',
                                           radio=data[identifier]["sniff_radio_2g"],
                                           duration=120)
                    logging.info("started-sniffer")
            if band == "fiveg":
                if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("5G") and \
                        dict(dut_data.get(identifier)["radio_data"])["5G"] is not None:
                    sniffer_channel = dict(dut_data.get(identifier)["radio_data"])["5G"]["channel"]
                    if data[identifier]["sniff_radio_5g"] is not None and sniffer_channel is not None:
                        self.start_sniffer(radio_channel=sniffer_channel,
                                           radio=data[identifier]["sniff_radio_5g"],
                                           duration=120)
                    logging.info("started-sniffer")
            if band == "sixg":
                if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("6G") and \
                        dict(dut_data.get(identifier)["radio_data"])["6G"] is not None:
                    sniffer_channel = dict(dut_data.get(identifier)["radio_data"])["6G"]["channel"]
                    if data[identifier]["sniff_radio_6g"] is not None and sniffer_channel is not None:
                        self.start_sniffer(radio_channel=sniffer_channel,
                                           radio=data[identifier]["sniff_radio_6g"],
                                           duration=120)
                    logging.info("started-sniffer")
            client_connect = CreateStation(_host=self.manager_ip, _port=self.manager_http_port,
                                           _sta_list=data[identifier]["station_data"][radio],
                                           _password=data[identifier]["passkey"],
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
            result = obj.wait_for_ip(station_list=obj.sta_list, timeout_sec=240)
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

        # stop sniffer if active
        logging.info(msg=str("Cleaning up sniffer interface If available on PORT Manager"))
        port_data = self.json_get(_req_url="/port?fields=alias,parent+dev,port+type,ip,mac")['interfaces']
        # for i in port_data:
        #     for item in i:
        #         if i[item]['port type'] == '802.1Q VLAN' and i[item]['ip'] == '0.0.0.0':
        #             logging.info('VLAN do not have IP')
        if self.start_sniffer:
            self.stop_sniffer()

        logging.info("pass_fail result: " + str(pass_fail))
        if False in pass_fail:
            logging.info("Station did not get an ip")
            for radio in data[identifier]["station_data"]:
                self.get_supplicant_logs(radio=str(radio))
            pytest.fail("Station did not get an ip")
        else:
            logging.info("ALL Stations got IP's")
            for radio in data[identifier]["station_data"]:
                self.get_supplicant_logs(radio=str(radio))
            return station_data_all

    def dfs_test(self, ssid=None, security=None, passkey=None, mode=None,
                 band=None, num_sta=1, vlan_id=[None], dut_data={}, tip_2x_obj=None):
        """DFS test"""
        self.check_band_ap(band=band)
        logging.info("DUT DATA: " + str(dut_data))
        for dut in self.dut_data:
            identifier = dut["identifier"]
            station_data = self.client_connect(ssid=ssid, security=security, passkey=passkey, mode=mode,
                                               band=band, num_sta=num_sta, vlan_id=vlan_id,
                                               allure_name="Station data before simulate radar", identifier=identifier,
                                               station_data=["4way time (us)", "channel", "cx time (us)", "dhcp (ms)",
                                                             "ip", "signal", "mode"], dut_data=dut_data)
            station_list = list(station_data.keys())
            table_dict = {}
            sta_channel_before_dfs_list = []
            sta_channel_after_dfs_list = []
            pass_fail = []
            sta_channel_after_dfs = None
            sta_channel_before_dfs = None
            ap_channel = dut_data[identifier]["radio_data"]["5G"]["channel"]
            logging.info("AP channel: " + str(ap_channel))
            sta_channel_before_dfs = station_data[station_list[0]]["channel"]
            logging.info("station channel before dfs: " + str(sta_channel_before_dfs))
            if str(ap_channel) == str(sta_channel_before_dfs):
                if tip_2x_obj is not None:
                    logging.info("AP idx: " + str(self.dut_data.index(dut)))
                    tip_2x_obj.simulate_radar(idx=self.dut_data.index(dut))
                    time.sleep(30)
                else:
                    logging.error("tip_2x_obj is empty")
            else:
                logging.error("Station not connected to applied channel")
                pytest.fail("Station not connected to applied channel")
            self.get_station_data(
                rows=["4way time (us)", "channel", "cx time (us)", "dhcp (ms)", "ip", "signal", "mode"],
                sta_name=station_list, allure_name="Station data after simulate radar")
            for i in range(5):
                sta_channel_after_dfs = self.station_data_query(station_name=station_list[0], query="channel")
                if sta_channel_after_dfs != sta_channel_before_dfs and str(sta_channel_after_dfs) != "-1":
                    break
                else:
                    time.sleep(20)
            sta_channel_before_dfs_list.append(sta_channel_before_dfs)
            sta_channel_after_dfs_list.append(sta_channel_after_dfs)
            table_dict["station name"] = station_list
            table_dict["Before"] = sta_channel_before_dfs_list
            table_dict["After"] = sta_channel_after_dfs_list
            # pass fail checking
            if str(sta_channel_before_dfs) != str(sta_channel_after_dfs):
                pass_fail.append("Pass")
                table_dict["Pass/Fail"] = pass_fail
            else:
                pass_fail.append("Fail")
                table_dict["Pass/Fail"] = pass_fail
            logging.info("dfs_table_data: " + str(table_dict))
            self.attach_table_allure(data=table_dict, allure_name="Pass_Fail Table")

            if sta_channel_before_dfs != sta_channel_after_dfs and str(sta_channel_after_dfs) != "-1":
                logging.info("channel after dfs: " + str(sta_channel_after_dfs))
                ret = tip_2x_obj.get_dfs_logs(idx=self.dut_data.index(dut))
                allure.attach(name="Simulate Radar Logs ", body=ret)

            else:
                logging.error("5 Ghz channel didn't changed after radar detected")
                pytest.fail("5 Ghz channel didn't changed after radar detected")

    def update_dut_ssid(self, dut_data={}):
        r_val = dict()
        for dut in self.dut_data:
            r_val[dut["identifier"]] = None
        # updating ssids on all APS
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
                self.update_duts(identifier=identifier, ssid_data=ssid_data)

    def add_stations(self, band="2G", num_stations=9, ssid_name="", dut_data={}, identifier=None):
        dut_name = []
        # for index in range(0, len(self.dut_data)):
        #     dut_name.append(self.dut_data[index]["identifier"])
        self.check_band_ap(band=band)
        if num_stations == 0:
            logging.warning("0 Stations")
            return
        idx = None
        r_val = dict()
        for dut in self.dut_data:
            r_val[dut["identifier"]] = None
        # updating ssids on all APS
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

        for dut in dut_data:
            for idx_ in dut_data[dut]["ssid_data"]:
                temp_band = dut_data[dut]["ssid_data"][idx_]["band"]
                if band == "2G":
                    if temp_band != "2G":
                        temp_band = "2G"
                elif band == "5G":
                    if temp_band != "5G":
                        temp_band = "5G"
                elif band == "6G":
                    if temp_band != "6G":
                        temp_band = "6G"
                if band == temp_band and ssid_name == \
                        dut_data[dut]["ssid_data"][idx_]["ssid"]:
                    idx = idx_
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

        logging.info("Radio data: " + str(radio_data))
        for radio in radio_data:
            if identifier is None:
                logging.error("Identifier is None")
                pytest.fail("Identifier is None")
            station_data = ["profile_link " + radio.split(".")[0] + "." + radio.split(".")[1] +
                            " STA-AUTO " + str(radio_data[radio]) + " 'DUT: " + identifier + " Radio-" +
                            str(int(idx) + 1) + "'" + " NA " + radio.split(".")[2]]
            self.temp_raw_lines.append(station_data)
            print(self.temp_raw_lines)

    def rate_limiting_test(self, mode="BRIDGE", vlan_id=100, batch_size="1,5,10,20,40,64,128",
                           instance_name="wct_instance", download_rate="1Gbps", influx_tags="",
                           upload_rate="1Gbps", protocol="TCP-IPv4", duration="60000", stations="",
                           create_stations=False,
                           sort="interleave", raw_lines=[], move_to_influx=False, dut_data={}, ssid_name=None,
                           num_stations={}, add_stations=True, passkey=None, up_rate=None, down_rate=None):
        self.wifi_capacity(mode=mode, vlan_id=vlan_id, batch_size=batch_size, instance_name=instance_name,
                           download_rate=download_rate,
                           influx_tags=influx_tags, upload_rate=upload_rate, protocol=protocol, duration=duration,
                           stations=stations, create_stations=create_stations, sort=sort, raw_lines=raw_lines,
                           move_to_influx=move_to_influx,
                           dut_data=dut_data, ssid_name=ssid_name, num_stations=num_stations, add_stations=add_stations)

    def wifi_capacity(self, mode="BRIDGE", vlan_id=100, batch_size="1,5,10,20,40,64,128",
                      instance_name="wct_instance", download_rate="1Gbps", influx_tags="",
                      upload_rate="1Gbps", protocol="TCP-IPv4", duration="60000", stations="", create_stations=False,
                      sort="interleave", raw_lines=[], move_to_influx=False, dut_data={}, ssid_name=None,
                      num_stations={}, add_stations=True, create_vlan=True):
        wificapacity_obj_list = []
        vlan_raw_lines = None
        for dut in self.dut_data:
            sets = [["DUT_NAME", dut["model"]]]
            identifier = dut["identifier"]
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
                    if create_vlan:
                        vlan_raw_lines = self.add_vlan(vlan_ids=vlan_id, build=True)
                    else:
                        vlan_raw_lines = self.add_vlan(vlan_ids=vlan_id, build=False)
                    ret = self.get_wan_upstream_ports()
                    upstream_port = ret[identifier] + "." + str(vlan_id[0])
            logging.info("Upstream data: " + str(upstream_port))
            sets = [["DUT_NAME", dut]]

            if add_stations:
                '''SINGLE WIFI CAPACITY using lf_wifi_capacity.py'''
                self.temp_raw_lines = self.default_scenario_raw_lines.copy()
                for band_ in num_stations:
                    if band_ not in ["2G", "5G", "6G"]:
                        logging.error("Band is missing")
                        pytest.fail("band is missing")

                    if not isinstance(num_stations[band_], int):
                        if not num_stations[band_] == "max":
                            logging.error("Number of stations are wrong")
                            pytest.fail("Number of stations are wrong")
                    if ssid_name is None:
                        logging.error("ssid name is missing")
                        pytest.fail("ssid name is missing")
                    if self.run_lf:
                        dut_data = self.run_lf_dut_data()
                        for i in dut_data:
                            if mode != dut_data[i]["mode"]:
                                pytest.skip("Dut is not configured in mode: " + mode)
                            else:
                                for j in dut_data[i]["ssid_data"]:
                                    if band_ == "2G":
                                        temp_band = "twog"
                                    elif band_ == "5G":
                                        temp_band = "fiveg"
                                    elif band_ == "6G":
                                        temp_band = "sixg"
                                    if temp_band == dut_data[i]["ssid_data"][j]["band"]:
                                        ssid_name = dut_data[i]["ssid_data"][j]["ssid"]
                    self.add_stations(band=band_, num_stations=num_stations[band_], ssid_name=ssid_name,
                                      dut_data=dut_data,
                                      identifier=identifier)
                    if vlan_raw_lines is not None:
                        for i in vlan_raw_lines:
                            self.temp_raw_lines.append(i)
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
                                  wificapacity_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[
                                      -1] + "/"
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
            time.sleep(10)
            logging.info("report_name: " + str(report_name))
            self.attach_report_graphs(report_name=report_name)
            self.attach_report_kpi(report_name=report_name)
            wificapacity_obj_list.append(wificapacity_obj)
        return wificapacity_obj_list

    def dataplane_throughput_test(self, ssid="[BLANK]", passkey="[BLANK]", security="wpa2", num_sta=1, mode="BRIDGE",
                                  vlan_id=[None],
                                  download_rate="85%", band="twog", scan_ssid=True, sta_mode=0,
                                  upload_rate="0", duration="15s", instance_name="test_demo", raw_lines=None,
                                  influx_tags="",
                                  move_to_influx=False,
                                  station_data=["4way time (us)", "channel", "cx time (us)", "dhcp (ms)", "ip",
                                                "signal"],
                                  allure_attach=True, allure_name="station data", client_type=None, dut_data={}):
        instance_name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
        dataplane_obj_list = []
        for dut in self.dut_data:
            identifier = dut["identifier"]
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
                    # self.add_vlan(vlan_ids=vlan_id)
                    ret = self.get_wan_upstream_ports()
                    upstream_port = ret[identifier] + "." + str(vlan_id[0])
            logging.info("Upstream data: " + str(upstream_port))
            station_data = self.client_connect(ssid=ssid, passkey=passkey, security=security, mode=mode, band=band,
                                               vlan_id=vlan_id, num_sta=num_sta, scan_ssid=scan_ssid, sta_mode=sta_mode,
                                               station_data=station_data,
                                               allure_attach=allure_attach, identifier=identifier,
                                               allure_name=allure_name, client_type=client_type, dut_data=dut_data)

            if raw_lines is None:
                raw_lines = [['pkts: 142;256;512;1024;MTU;4000'], ['directions: DUT Transmit;DUT Receive'],
                             ['traffic_types: UDP;TCP'],
                             ["show_3s: 1"], ["show_ll_graphs: 1"], ["show_log: 1"]]

            dataplane_obj = DataplaneTest(lf_host=self.manager_ip,
                                          lf_port=self.manager_http_port,
                                          ssh_port=self.manager_ssh_port,
                                          local_lf_report_dir=self.local_report_path,
                                          lf_user="lanforge",
                                          lf_password="lanforge",
                                          instance_name=instance_name,
                                          config_name="dpt_config",
                                          upstream=upstream_port,
                                          pull_report=True,
                                          load_old_cfg=False,
                                          download_speed=download_rate,
                                          upload_speed=upload_rate,
                                          duration=duration,
                                          dut=identifier,
                                          station=list(station_data.keys())[0],
                                          test_tag=influx_tags,
                                          raw_lines=raw_lines)

            dataplane_obj.setup()
            dataplane_obj.run()
            if move_to_influx:
                report_name = "../reports/" + \
                              dataplane_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1] + "/"
                try:
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
            report_name = dataplane_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1] + "/"
            self.attach_report_graphs(report_name=report_name, pdf_name="Dataplane Throughput Test - TCP-UDP 5G")
            self.attach_report_kpi(report_name=report_name)
            logging.info("Test Completed... Cleaning up Stations")
            self.client_disconnect(station_name=list(station_data.keys()))
            dataplane_obj_list.append(dataplane_obj)
        return dataplane_obj_list

    def multi_asso_disasso(self, band="2G", num_stations=16, dut_data={}, idx=0, mode="BRIDGE", vlan=1,
                           instance_name="wct_instance", traffic_direction="upload", traffic_rate="0Mbps"):
        try:
            def thread_fun(station_list):
                time.sleep(60)
                for i in station_list:
                    self.local_realm.admin_down(i)
                logging.info("stations down")
                time.sleep(10)
                for i in station_list:
                    self.local_realm.admin_up(i)
                logging.info("stations up")

            # clean l3 traffics which won't get cleaned by deleting old scenario in CV
            self.client_disconnect(clean_l3_traffic=True)
            radio = self.wave2_5g_radios if band == "5G" else self.wave2_2g_radios
            upld_rate, downld_rate = "0Gbps", "0Gbps"
            if traffic_direction == "upload":
                upld_rate = traffic_rate
            elif traffic_direction == "download":
                downld_rate = traffic_rate
            per_radio_sta = int(num_stations / len(radio))
            rem = num_stations % len(radio)
            logging.info("Total stations per radio: " + str(per_radio_sta))
            num_stations = lambda rem: per_radio_sta + 1 if rem else per_radio_sta
            identifier = list(dut_data.keys())[0]
            allure.attach(name="Definition",
                          body="Multiple association/disassociation stability test intends to measure stability of Wi-Fi device " \
                               "under a dynamic environment with frequent change of connection status.")
            allure.attach(name="Procedure",
                          body=f"This test case definition states that we Create 16 stations on {band} radio and" \
                               " Run Wifi-capacity test for first 8 stations. 8 stations are picked for sending/receiving packets "
                               "while the other 8 STAs are picked to do a dis-association/re-association process during the test" \
                               f" Enable {traffic_direction} {traffic_rate} Mbps UDP flow from DUT to each of the 8 traffic stations" \
                               "Disassociate the other 8 stations. Wait for 30 seconds, after that Re-associate the 8 stations.")

            self.add_vlan(vlan_ids=vlan)
            for i in radio:
                station_data = ["profile_link " + i.split(".")[0] + "." + i.split(".")[1] +
                                " STA-AUTO " + str(num_stations(rem)) + " 'DUT: " + identifier + " Radio-" +
                                str(int(idx) + 1) + "'" + " NA " + i.split(".")[2]]
                rem = 0
                self.temp_raw_lines.append(station_data)
                logging.debug("Raw Line : " + str(station_data))
            # update the dut ssid in CV
            self.update_dut_ssid(dut_data=dut_data)
            self.chamber_view(raw_lines="custom")
            sta_list = []
            for rad in radio:
                self.set_radio_channel(radio=rad, antenna=4)
            for u in self.json_get("/port/?fields=port+type,alias")['interfaces']:
                if list(u.values())[0]['port type'] in ['WIFI-STA']:
                    sta_list.append(list(u.keys())[0])

            for i in sta_list:
                self.local_realm.admin_up(i)
            sel_stations = ",".join(sta_list[0:8])
            val = [['ul_rate_sel: Per-Station Upload Rate:']]
            thr1 = threading.Thread(target=thread_fun, args=(sta_list[8:16],))
            thr1.start()
            wct_obj = self.wifi_capacity(instance_name=instance_name, mode=mode, vlan_id=vlan,
                                         download_rate=downld_rate,add_stations=False,
                                         stations=sel_stations, raw_lines=val, batch_size="8", upload_rate=upld_rate,
                                         protocol="UDP-IPv4", duration="120000", create_stations=False,
                                         dut_data=dut_data, create_vlan=False,
                                         sort="interleave", )

            report_name = wct_obj[0].report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1] + "/"
            # self.attach_report_graphs(report_name=report_name)
            csv_val = self.read_csv_individual_station_throughput(dir_name=report_name, option=traffic_direction)
            logging.info(csv_val)
            pass_value = int(traffic_rate[0]) * 0.99
            logging.info(csv_val)
            allure.attach(name="Pass Fail Criteria",
                          body=f"UDP traffic rate is at least 99% of the configured rate for each station. Here configured " \
                               f"traffic rate is {traffic_rate[0]} Mbps so traffic for each station should be {pass_value} Mbps ")
            if not csv_val:
                return False, "csv file does not exist"
            else:
                pass_fail = [1 if i >= pass_value else 0 for i in csv_val.values()]
                try:
                    allure.attach.file(source="../reports/" + report_name + "/csv-data/data-Combined_bps__60_second_running_average-1.csv",
                    name="Throughput CSV file", attachment_type=allure.attachment_type.CSV)
                except FileNotFoundError as e:
                    allure.attach.file(
                        source="../reports/" + report_name + "/csv-data/data-Combined_Mbps__60_second_running_average-1.csv",
                        name="Throughput CSV file", attachment_type=allure.attachment_type.CSV)
                if pass_fail.count(0) == 0:
                    return True, "Test passed"
                else:
                    return False, "Test failed due to lesser value"
        except Exception as e:
            logging.error(f"{e}")
            return False, f"{e}"
        finally:
            try:
                self.client_disconnect(clear_all_sta=True, clean_l3_traffic=True)
            except Exception as e:
                logging.error(f"{e}")
                return False, f"{e}"

    def country_code_channel_division(self, ssid="[BLANK]", passkey='[BLANK]', security="wpa2", mode="BRIDGE",
                                      band='twog', num_sta=1, vlan_id=100, channel='1', channel_width=20,
                                      country_num=392, country='United States(US)', dut_data={}):
        try:
            radio = self.wave2_5g_radios[0] if band == "fiveg" else self.wave2_2g_radios[0]
            self.set_radio_channel(radio=radio, channel=0, country=country_num)
            station = self.client_connect(ssid=ssid, passkey=passkey, security=security, mode=mode, band=band,
                                          num_sta=num_sta, vlan_id=vlan_id, dut_data=dut_data)
            allure.attach(name="Definition",
                          body="Country code channel test intends to verify stability of Wi-Fi device " \
                               "where the AP is configured with different countries with different channels.")
            allure.attach(name="Procedure",
                          body=f"This test case definition states that we need to push the basic {mode.lower()} mode config on the AP to "
                               f"be tested by configuring it with {country} on {channel_width}MHz channel width and "
                               f"channel {channel}. Create a client on {'5' if band == 'fiveg' else '2.4'} GHz radio. Pass/ fail criteria: "
                               f"The client created on {'5' if band == 'fiveg' else '2.4'} GHz radio should get associated to the AP")
            allure.attach(name="Details",
                          body=f"Country code : {country[country.find('(') + 1:-1]}\n"
                               f"Bandwidth : {channel_width}Mhz\n"
                               f"Channel : {channel}\n")
            if station[list(station.keys())[0]]['ip'] != '0.0.0.0':
                if str(station[list(station.keys())[0]]['channel']) != str(channel):
                    logging.warning(f"Station Falling back to channel {station[list(station.keys())[0]]['channel']}")
                    return False
                else:
                    logging.info(f"Station connected to channel {station[list(station.keys())[0]]['channel']}")
                    return True
            else:
                logging.warning(f"Station didn't get IP")
                return False
        except Exception as e:
            logging.error(f"{e}")
            return False
        finally:
            try:
                self.client_disconnect(clear_all_sta=True)
                self.set_radio_channel(radio=radio, country=840)
            except Exception as e:
                logging.error(f"{e}")
                return False

    def tr398(self,radios_2g=[], radios_5g=[], radios_ax=[], dut_name="TIP", dut_5g="", dut_2g="", mode="BRIDGE",
              vlan_id=1, skip_2g=True, skip_5g=False, instance_name="", test=None, move_to_influx=False,dut_data={},
              ssid_name='', security_key='[BLANK]', security="open"):
        #User can select one or more TR398 tests
        try:
            if type(test) == str:
                test = test.split(",")
            self.client_disconnect(clean_l3_traffic=True)
            raw_line = []
            skip_twog, skip_fiveg = '1' if skip_2g else '0', '1' if skip_5g else '0'
            if mode == "BRIDGE" or mode == "NAT":
                upstream_port = list(self.lanforge_data['wan_ports'].keys())[0]
            else:
                upstream_port = list(self.lanforge_data['wan_ports'].keys())[0] + "." + str(vlan_id)
            atten_serial = self.attenuator_serial_radio(ssid=ssid_name, passkey=security_key, security=security, sta_mode=0,
                                                        station_name=['sta0000'])

            enable_tests = [['rxsens: 0'], ['max_cx: 0'], ['max_tput: 0'], ['peak_perf: 0'], ['max_tput_bi: 0'],
                            ['dual_band_tput: 0'],
                            ['multi_band_tput: 0'], ['atf: 0'], ['atf3: 0'], ['qos3: 0'], ['lat3: 0'], ['mcast3: 0'],
                            ['rvr: 0'],
                            ['spatial: 0'], ['multi_sta: 0'], ['reset: 0'], ['mu_mimo: 0'], ['stability: 0'],
                            ['ap_coex: 0'], ['acs: 0']]

            rad_atten = [[f'atten-0: {atten_serial[0]}.0'], [f'atten-1: {atten_serial[0]}.1'], [f'atten-2: {atten_serial[0]}.2'],
                         [f'atten-3: {atten_serial[0]}.3'], [f'atten-4: {atten_serial[1]}.0'], [f'atten-5: {atten_serial[1]}.1'],
                         [f'atten-8: {atten_serial[1]}.2'], [f'atten-9: {atten_serial[1]}.3']]

            skip_band = [['Skip 2.4Ghz Tests', f'{skip_twog}'], ['Skip 5Ghz Tests', f'{skip_fiveg}'],
                         ['2.4Ghz Channel', 'AUTO'], ['5Ghz Channel', 'AUTO'], ['Skip AX Tests', '1']]
            for t in test:
                if [f"{t}: 0"] in enable_tests:
                    enable_tests[enable_tests.index([f"{t}: 0"])] = [f"{t}: 1"]
            if len(radios_2g) >= 3 and len(radios_5g) >= 3:
                for i in range(6):
                    if i == 0 or i == 2:
                        raw_line.append([f'radio-{i}: {radios_5g[0] if i == 0 else radios_5g[1]}'])
                    if i == 1 or i == 3:
                        raw_line.append([f'radio-{i}: {radios_2g[0] if i == 1 else radios_2g[1]}'])
                    if i == 4 or i == 5:
                        raw_line.append([f'radio-{i}: {radios_5g[2] if i == 4 else radios_2g[2]}'])
            elif len(radios_2g) >= 2 and len(radios_5g) >= 2 and len(radios_ax) >= 2:
                for i in range(6):
                    if i == 0 or i == 2:
                        raw_line.append([f'radio-{i}: {radios_5g[0] if i == 0 else radios_5g[1]}'])
                    if i == 1 or i == 3:
                        raw_line.append([f'radio-{i}: {radios_2g[0] if i == 1 else radios_2g[1]}'])
                    if i == 4 or i == 5:
                        raw_line.append([f'radio-{i}: {radios_ax[0] if i == 4 else radios_ax[1]}'])

            if len(raw_line) != 6:
                raw_line = [['radio-0: 1.1.5 wiphy1'], ['radio-1: 1.1.4 wiphy0'], ['radio-2: 1.1.7 wiphy3'],
                            ['radio-3: 1.1.6 wiphy2'], ['radio-4: 1.1.8 wiphy4'], ['radio-5: 1.1.9 wiphy5']]
            raw_line.extend(enable_tests + rad_atten)
            self.update_dut_ssid(dut_data=dut_data)
            instance_name = "tr398-instance-{}".format(str(random.randint(0, 100000)))

            # if not os.path.exists("tr398-test-config.txt"):
            with open("tr398-test-config.txt", "wt") as f:
                for i in raw_line:
                    f.write(str(i[0]) + "\n")
                f.close()

            self.cvtest_obj = TR398v2Test(lf_host=self.manager_ip,
                                        lf_port=self.manager_http_port,
                                        lf_user="lanforge",
                                        lf_password="lanforge",
                                        instance_name=instance_name,
                                        config_name="cv_dflt_cfg",
                                        upstream=upstream_port,
                                        pull_report=True,
                                        local_lf_report_dir=self.local_report_path,
                                        load_old_cfg=False,
                                        dut2=dut_2g,
                                        dut5=dut_5g,
                                        raw_lines_file="tr398-test-config.txt",
                                        enables=[],
                                        disables=[],
                                        raw_lines=[],
                                        sets=skip_band,
                                        test_rig=dut_name
                                        )
            self.cvtest_obj.test_name = "TR-398 Issue 2"
            self.cvtest_obj.result = True
            self.cvtest_obj.setup()
            self.cvtest_obj.run()
            if os.path.exists("tr398-test-config.txt"):
                os.remove("tr398-test-config.txt")

            if move_to_influx:
                try:
                    report_name = "../reports/" + self.cvtest_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1]
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
            report_name = self.cvtest_obj[0].report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1] + "/"
            self.attach_report_graphs(report_name=report_name)
            result = self.read_kpi_file(column_name=["pass/fail"], dir_name=report_name)
            allure.attach.file(source="../reports/" + report_name + "/kpi.csv",
                               name=f"{test}_CSV", attachment_type=allure.attachment_type.CSV)
            if result[0][0] == "PASS":
                return True, "Test Passed"
            else:
                return False, "Test Failed"
        except Exception as e:
            logging.error(f"{e}")
            return False, f"{e}"
        finally:
            try:
                self.client_disconnect(clear_all_sta=True, clean_l3_traffic=True)
            except Exception as e:
                logging.error(f"{e}")
                return False, f"{e}"

    def air_time_fairness(self, ssid="[BLANK]", passkey='[BLANK]', security="wpa2", mode="BRIDGE", band='twog',
                          vlan_id=100, atn=100, pass_value=None, dut_data={}):
        try:
            allure.attach(name="Definition",
                          body="Airtime Fairness test intends to verify the capacity of Wi-Fi device to ensure the fairness of " \
                               "airtime usage.")
            allure.attach(name="Procedure",
                          body="This test case definition states that Create 2 stations of greenfeild mode and 1 station of legacy mode"
                               " on 2.4/5Ghz radio. Run TCP download for station_1 as throughpt_1, station_2 as throughpt_2, "
                               "station_2 with attenuation as throughpt_3, station_3 as throughpt_4, UDP download for station_1 + station_2"
                               "of data_rates 40% of throughput_1 and 40% of throughput_2 as throughput_5, station_1 + station_2 with attenuation"
                               "of data_rates 40% of throughput_1 and 40% of throughput_3 as throughput_6, station_1 + station_3"
                               "of data_rates 40% of throughput_1 and 40% of throughput_4 as throughput_7")
            self.client_disconnect(clear_all_sta=True, clean_l3_traffic=True)
            sta = list(map(lambda i: f"sta000{i}",range(3)))
            radios, sta_mode = (self.wave2_5g_radios, [1,9]) if band == "fiveg" else (self.wave2_2g_radios, [2,11])
            thrpt = {"sta0_tcp_dl": None, "sta1_tcp_dl": None, "sta1_tcp_dl_atn": None, "sta2_tcp_dl": None,
                     "sta0+1_udp": None, "sta0+1_udp_atn": None, "sta0+2": None}
            no_of_iter = list(thrpt.keys())

            atten_serial = self.attenuator_serial_radio(ssid=ssid, passkey=passkey, security=security, radio=radios[1],
                                                        station_name=[sta[0]])
            atten_serial_split = atten_serial[0].split(".")
            self.attenuator_modify("all", 'all', 100)
            for i in range(len(radios)):
                if i == 2:
                    # mode = 2/1 will create legacy client
                    create_sta = self.client_connect_using_radio(ssid=ssid, passkey=passkey, security=security,
                                                                 radio=radios[i], station_name=[sta[i]], sta_mode=sta_mode[0])
                else:
                    # mode = 11/9 will create bgn-AC/an-AC client
                    create_sta = self.client_connect_using_radio(ssid=ssid, passkey=passkey, security=security,
                                                                 radio=radios[i], station_name=[sta[i]], sta_mode=sta_mode[1])
                if create_sta == False:
                    logging.info(f"Test failed due to no IP for {sta[i]}")
                    assert False, f"Test failed due to no IP for {sta[i]}"
            else:
                lf_sta = list(create_sta.station_map().keys())

                def wifi_cap(sta=None, down=None, up=0, proto=None, thrpt_key=None, wifi_cap=False, atn=None, l3_trf=False):
                    if atn:
                        for i in range(2):
                            self.attenuator_modify(int(atten_serial_split[2]), i, int(atn))
                            time.sleep(0.5)
                    if wifi_cap:
                        wct_obj = self.wifi_capacity(mode=mode, add_stations=False, vlan_id=vlan_id, download_rate=down,
                                                     batch_size="1", stations=f"{sta}", create_stations=False,
                                                     upload_rate=up, protocol=proto, duration="60000", sort="linear",
                                                     dut_data=dut_data)
                        report_name = wct_obj[0].report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1]
                        # self.attach_report_graphs(report_name=report_name)
                        entries = os.listdir("../reports/" + report_name + '/')
                        if "kpi.csv" in entries:
                            thrpt[thrpt_key] = self.read_kpi_file(column_name=["numeric-score"], dir_name=report_name)[0][0]
                    if l3_trf:
                        self.client_disconnect(clean_l3_traffic=True)
                        self.create_layer3(sta_list=sta[0:1], traffic_type=proto, side_a_min_rate=0,
                                           side_b_min_rate=int(down[0]), start_cx=False)
                        self.create_layer3(sta_list=sta[1:2], traffic_type=proto, side_a_min_rate=0,
                                           side_b_min_rate=int(down[1]), start_cx=False)
                        created_cx = {}
                        cx_list = [created_cx.setdefault(i, "Endpoints") for i in self.get_cx_list() if i not in created_cx]
                        self.start_cx_list(created_cx=created_cx, check_run_status=True)
                        thrpt[thrpt_key] = self.monitor(duration_sec=int(60) + 10, monitor_interval=1, created_cx=created_cx.keys(),
                                                        col_names=['bps rx a', 'bps rx b'], iterations=0, side_a_min_rate=0,
                                                        side_b_min_rate=down)[0]

                # station_0 TCP down throughtput
                wifi_cap(down="1Gbps", sta=f"{lf_sta[0]}", up="0Gbps", proto="TCP-IPv4", thrpt_key=f"{no_of_iter[0]}",
                         wifi_cap=True)
                # station_1 TCP down throughtput
                wifi_cap(down="1Gbps", sta=f"{lf_sta[1]}", up="0Gbps", proto="TCP-IPv4", thrpt_key=f"{no_of_iter[1]}",
                         wifi_cap=True)
                # station_1 with medium distance TCP down throughtput
                wifi_cap(down="1Gbps", sta=f"{lf_sta[1]}", up="0Gbps", proto="TCP-IPv4", thrpt_key=f"{no_of_iter[2]}",
                         wifi_cap=True, atn=atn)
                # station_2 TCP down throughtput
                wifi_cap(down="1Gbps", sta=f"{lf_sta[2]}", up="0Gbps", proto="TCP-IPv4", thrpt_key=f"{no_of_iter[3]}",
                         wifi_cap=True, atn=100)
                # UDP traffic for station_0 of data-rate 40% of sta0_data_rate and station_1 of data-rate 40% of sta1_data_rate
                wifi_cap(down=[(thrpt["sta0_tcp_dl"] * 0.01) * 4E7, (thrpt["sta1_tcp_dl"] * 0.01) * 4E7], sta=sta[0:2],
                         up="0Gbps", thrpt_key=f"{no_of_iter[4]}", l3_trf=True, proto="lf_udp")
                # UDP traffic for station_0 of data-rate 40% of sta0_data_rate and medium distance station_1 of data-rate 40% of sta1_data_rate
                wifi_cap(down=[(thrpt["sta0_tcp_dl"] * 0.01) * 4E7, (thrpt["sta1_tcp_dl_atn"] * 0.01) * 4E7], sta=sta[0:2],
                         up="0Gbps", thrpt_key=f"{no_of_iter[5]}", l3_trf=True, atn=atn, proto="lf_udp")
                # UDP traffic for station_0 of data-rate 40% of sta0_data_rate and station_2 of data-rate 40% of sta2_data_rate
                wifi_cap(down=[(thrpt["sta0_tcp_dl"] * 0.01) * 4E7, (thrpt["sta2_tcp_dl"] * 0.01) * 4E7], sta=sta[0:3:2],
                         up="0Gbps", thrpt_key=f"{no_of_iter[6]}", l3_trf=True, atn=100, proto="lf_udp")
                logging.info("Throughput values: \n", thrpt)
                self.allure_report_table_format(dict_data=thrpt, key="Station combination", value="Throughput values",
                                                name="Test_results")
                if pass_value:
                    if sum(thrpt["sta0+1_udp"]) >= pass_value[0] and sum(thrpt["sta0+1_udp_atn"]) >= pass_value[1] and \
                            sum(thrpt["sta0+2"]) >= pass_value[2]:
                        return True, "Test Passed"
                    else:
                        return False, "Failed due to Lesser value"
                else:
                    return True, "Test Passed without pass-fail verification"
        except Exception as e:
            logging.error(f"{e}")
            return False, f"{e}"
        finally:
            try:
                self.client_disconnect(clear_all_sta=True, clean_l3_traffic=True)
            except Exception as e:
                logging.error(f"{e}")
                return False, f"{e}"

    def rate_vs_range_test(self, station_name=None, mode="BRIDGE", vlan_id=100, download_rate="85%", dut_name="TIP",
                           upload_rate="0", duration="1m", instance_name="test_demo", raw_lines=None,move_to_influx=False):
        for dut in self.dut_data:
            if mode == "BRIDGE" or mode == "NAT-WAN":
                upstream_port = dut["wan_port"]
            elif mode == "NAT-LAN":
                upstream_port = dut["lan_port"]
            elif mode == "VLAN":
                if vlan_id is None:
                    logging.error("VLAN ID is Unspecified in the VLAN Case")
                    pytest.skip("VLAN ID is Unspecified in the VLAN Case")
                else:
                    # self.add_vlan(vlan_ids=vlan_id, build=True)
                    upstream_port = dut["wan_port"] + "." + str(vlan_id[0])
            logging.info("Upstream data: " + str(upstream_port))

        rvr_obj = rvr_test(lf_host=self.manager_ip,
                               lf_port=self.manager_http_port,
                               ssh_port=self.manager_ssh_port,
                               lf_user="lanforge",
                               local_lf_report_dir="../reports/",
                               lf_password="lanforge",
                               instance_name=instance_name,
                               config_name="rvr_config",
                               upstream=upstream_port,
                               pull_report=True,
                               load_old_cfg=False,
                               upload_speed=upload_rate,
                               download_speed=download_rate,
                               duration=duration,
                               station=station_name,
                               dut=dut_name,
                               raw_lines=raw_lines)
        rvr_obj.run()
        if move_to_influx:
            try:
                report_name = self.rvr_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1]
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
        #fetch the report
        report_name = rvr_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1]
        time.sleep(10)
        logging.info("report_name: " + str(report_name))
        self.attach_report_graphs(report_name=report_name,pdf_name= "Rate vs Range Test PDF Report")
        self.attach_report_kpi(report_name=report_name)

        return rvr_obj, report_name

if __name__ == '__main__':
    basic = {
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
            "wan_port": "1.1.eth3",
            "lan_port": None,
            "ssid": {
                "mode": "BRIDGE",
                "ssid_data": {
                    "0": {
                        "ssid": "OpenWifi",
                        "encryption": "wpa2",
                        "password": "OpenWifi",
                        "band": "fiveg",
                        "bssid": "90:3C:B3:6C:43:04"
                    },
                    "1": {
                        "ssid": "OpenWifi",
                        "encryption": "wpa2",
                        "password": "OpenWifi",
                        "band": "twog",
                        "bssid": "90:3C:B3:6C:43:04"
                    }
                },
                "radio_data": {
                    "2G": {
                        "channel": 1,
                        "bandwidth": 20,
                        "frequency": 2437
                    },
                    "5G": {
                        "channel": 52,
                        "bandwidth": 20,
                        "frequency": 5260
                    },
                    "6G": {
                        "channel": None,
                        "bandwidth": None,
                        "frequency": None
                    }
                }
            },
            "mode": "wifi6",
            "identifier": "903cb36c4301",
            "method": "serial",
            "host_ip": "192.168.52.89",
            "host_username": "lanforge",
            "host_password": "lanforge",
            "host_ssh_port": 22,
            "serial_tty": "/dev/ttyUSB0",
            "firmware_version": "next-latest"
        }],
        "traffic_generator": {
            "name": "lanforge",
            "testbed": "basic",
            "scenario": "dhcp-bridge",
            "details": {
                "manager_ip": "localhost",
                "http_port": 8840,
                "ssh_port": 8841,
                "setup": {"method": "build", "DB": "Test_Scenario_Automation"},
                "wan_ports": {
                    "1.1.eth3": {"addressing": "dhcp-server", "subnet": "172.16.0.1/16", "dhcp": {
                        "lease-first": 10,
                        "lease-count": 10000,
                        "lease-time": "6h"
                    }
                                 }
                },
                "lan_ports": {

                },
                "uplink_nat_ports": {
                    "1.1.eth2": {
                        "addressing": "static",
                        "ip": "192.168.52.150",
                        "gateway_ip": "192.168.52.1/24",
                        "ip_mask": "255.255.255.0",
                        "dns_servers": "BLANK"
                    }
                }
            }
        }
    }

    obj = lf_tests(lf_data=dict(basic["traffic_generator"]), dut_data=list(basic["device_under_tests"]),
                   log_level=logging.DEBUG, run_lf=True)
    l = obj.run_lf_dut_data()
    print(l)
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
    # obj.multi_psk_test(band="twog", mpsk_data=None, ssid="OpenWifi", bssid="['00:00:c1:01:88:12']", passkey="OpenWifi",
    #                    encryption="wpa", mode="BRIDGE", num_sta=1)
    # obj.add_vlan(vlan_iFds=[100])
    # obj.create_dhcp_external()obj.add_vlan(vlan_ids=[100, 200, 300, 400, 500, 600])
    # obj.get_cx_data()
    # obj.chamber_view()
    dut = {'903cb36c4301':
        {'ssid_data': {
            0: {'ssid': 'ssid_wpa_2g_br', 'encryption': 'wpa', 'password': 'something', 'band': '2G',
                'bssid': '90:3C:B3:6C:43:04'}}, 'radio_data': {'2G': {'channel': 6, 'bandwidth': 20, 'frequency': 2437},
                                                               '5G': {'channel': None, 'bandwidth': None,
                                                                      'frequency': None},
                                                               '6G': {'channel': None, 'bandwidth': None,
                                                                      'frequency': None}}}}

    passes, result = obj.client_connectivity_test(ssid="ssid_wpa_2g_br", passkey="something", security="wpa",
                                                  extra_securities=[],
                                                  num_sta=1, mode="BRIDGE", dut_data=dut,
                                                  band="fiveg")
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
