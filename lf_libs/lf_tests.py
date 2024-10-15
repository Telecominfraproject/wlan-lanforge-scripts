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
import re

import requests

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
tr398test = importlib.import_module("py-scripts.lf_tr398_test")
TR398Test = tr398test.TR398Test
tr398v2test = importlib.import_module("py-scripts.lf_tr398v2_test")
TR398v2Test = tr398v2test.TR398v2Test
rvr = importlib.import_module("py-scripts.lf_rvr_test")
rvr_test = rvr.RvrTest
lf_pcap = importlib.import_module("py-scripts.lf_pcap")
LfPcap = lf_pcap.LfPcap
lf_ap_auto_test = importlib.import_module("py-scripts.lf_ap_auto_test")
ApAutoTest = lf_ap_auto_test.ApAutoTest
roam_test = importlib.import_module("py-scripts.lf_hard_roam_test")
Roam = roam_test.Roam
wifi_mobility_test = importlib.import_module("py-scripts.lf_wifi_mobility_test")
WifiMobility = wifi_mobility_test.WifiMobility


class lf_tests(lf_libs):
    """
        lf_tools is needed in lf_tests to do various operations needed by various tests
    """

    def __init__(self, lf_data={}, dut_data={}, log_level=logging.DEBUG, run_lf=False, influx_params=None,
                 local_report_path="../reports/"):
        super().__init__(lf_data, dut_data, run_lf, log_level)
        self.local_report_path = local_report_path
        self.influx_params = influx_params

    def client_connectivity_test(self, ssid="[BLANK]", passkey="[BLANK]", bssid="[BLANK]", dut_data={},
                                 security="open", extra_securities=[], client_type=0,
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

                obj_sta_connect.sta_mode = client_type
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
            sta_rows = ["4way time (us)", "channel", "ssid", "key/phrase", "cx time (us)", "dhcp (ms)", "ip", "signal",
                        "mac", "mode"]
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




    def hot_config_reload_test(self, ssid="[BLANK]", security="wpa2", dut_data={}, passkey="[BLANK]", mode="BRIDGE",
                                band="fiveg", num_sta=1, vlan_id=[None], json_post_data='', get_testbed_details={},
                                tip_2x_obj=None, reconfig = None):
        self.check_band_ap(band=band)
        self.pre_cleanup()
        pass_fail = "PASS"
        description = ""
        logging.info("DUT DATA: " + str(dut_data))
        deauth_result = 0 #to check Deauthentication packet
        for dut in self.dut_data:
            station_result = self.client_connect_using_radio(ssid=ssid, passkey=passkey, security=security, mode=mode,
                                                             band=band, vlan_id=vlan_id, radio="1.1.wiphy4",
                                                             client_type=0,
                                                             station_name=["sta0000"],
                                                             dut_data=dut_data, attach_port_info=False)
            sta = "sta0000"
            sta_data = self.json_get(_req_url="port/1/1/%s" % sta)
            self.allure_report_table_format(dict_data=sta_data["interface"], key="Station Data",
                                            value="Value", name="%s info before Reconfiguration" % sta)

            print("type of station_result", type(station_result))
            print("station_result",station_result)
            # allure.attach(name=f"Response - {resp.status_code} {resp.reason}", body=str(resp.json()))

            if not station_result:
                allure.attach(name="Test Result", body="TEST FAILED, due to station has no ip")
                return "FAIL", "TEST FAILED, due to station has no ip"
            logging.info("sta " + str(sta))

            sta_channel = sta_data['interface']['channel']

            current_config = tip_2x_obj.dut_library_object.get_active_config()

            sniff_radio = self.setup_sniffer(band="fiveg", station_radio_data={"wiphy4": 1})  # to setup sniffer radio
            print("------------------sniffer_radio", sniff_radio)
            self.start_sniffer(radio_channel=sta_channel, radio=sniff_radio, test_name="hot_reload_sniff", duration=360)
            print("------------------sniffer started-------------------")

            serial_number = list(dut_data.keys())[0]
            print("---------active config:", current_config)
            sta_name = sta_data['interface']['device']

            iwinfo = tip_2x_obj.dut_library_object.get_iwinfo()
            # print("iwinfo before reconfiguration:", iwinfo)

            # Reconfiguration
            # Reconfiguring the AP, Modifying the Band parameter from 5G to 5G-upper
            if reconfig == "band":
                for radio in current_config['radios']:
                    if radio['band'] == '5G':
                        radio['band'] = '5G-upper'

            # Reconfiguring the AP, Modifying the Channel Width parameter from 80 Mhz to 40 Mhz
            if reconfig == "channel_width":
                sta_mode = sta_data['interface']['mode']
                #sta_mode = self.station_data_query(station_name=sta_name, query="mode")
                print("Station mode before reconfiguration:", sta_mode)
                new_radios = []
                for radio in current_config['radios']:
                    if radio.get('band') == '5G':
                        radio['channel-width'] = 40
                    new_radios.append(radio)
                current_config['radios'] = new_radios

            # Reconfiguring the AP, Modifying the TX power parameter from 18 to 20
            if reconfig == "tx_power":
                # Extract the Tx-Power value using a regular expression
                tx_power_value = re.search(r'Tx-Power:\s+(\d+)\s+dBm', iwinfo)
                print(f"tx_power_value before reconfiguration: {int(tx_power_value.group(1))} dBm")
                new_radios = []
                for radio in current_config['radios']:
                    if radio.get('band') == '5G':
                        radio['tx-power'] = 20
                    new_radios.append(radio)
                current_config['radios'] = new_radios

            # Reconfiguring the AP, Modifying the dfs parameter (setting True for allow-dfs parameter)
            if reconfig == "dfs":
                res = tip_2x_obj.dut_library_object.get_uci_show(param='wireless')
                for radio in current_config['radios']:
                    if radio['band'] == '5G':
                        radio['allow-dfs'] = True

            # Reconfiguring the AP, Modifying the HE parameter (setting "he-settings": { "bss-color": 60 })
            if reconfig == "he":
                bss_color = sta_data['interface']['bss color']
                print("bss_color before reconfiguration", bss_color)
                for radio in current_config['radios']:
                    if radio['band'] == '5G':
                        radio['he-settings'] = {"bss-color": 60}


                # modified current_config
            print("---------Reconfiguration data---------:", current_config)

            print("serial number:", serial_number)
            path = "device/" + serial_number + "/configure"

            uri = tip_2x_obj.controller_library_object.build_uri(path)

            payload = {"configuration": json.dumps(current_config), "serialNumber": serial_number, "UUID": 2}
            # Send the POST request with the current configuration
            resp = requests.post(uri, data=json.dumps(payload, indent=2),
                                 headers=tip_2x_obj.controller_library_object.make_headers(), verify=False,
                                 timeout=120)

            time.sleep(10)
            print("resp",resp)
            print(resp.status_code)
            if resp.status_code == 200:
                print("Reconfigured successfully")
                allure.attach(name=f"Response for Reconfiguration - {resp.status_code} {resp.reason}", body=str(resp.json()))
            else:
                allure.attach(name=f"Response for Reconfiguration - {resp.status_code} {resp.reason}", body=f"TEST FAILED, Reconfiguration is not successful {str(resp.json())}")
                # return "FAIL", "TEST FAILED, Reconfiguration is not successful."


            time.sleep(10)
            sta_data = self.json_get(_req_url="port/1/1/%s" % sta_name)
            self.allure_report_table_format(dict_data=sta_data["interface"], key="Station Data",
                                            value="Value", name="%s info after Reconfiguration" % sta)

            pcap_name = self.stop_sniffer([sta_name])
            print("------------------sniffer stopped-------------------")
            print("pcap_name:", pcap_name)

            timestamp = datetime.utcnow()
            allure.attach(name="config after Reconfiguration",
                          body="TimeStamp: " + str(timestamp) + "\n" + str(json.dumps(current_config, indent=2)),
                          attachment_type=allure.attachment_type.JSON)


            # step-1 validation
            pcap_obj = LfPcap(host=self.manager_ip, port=self.manager_http_port)
            filter = 'wlan.fixed.reason_code == 0x0003' # wlan.fc.type_subtype == 12 is a filter for Deauthentication packet, wlan.fixed.reason_code == 0x0003 for client disruption deauthentication packet
            pcap = pcap_obj.read_pcap(pcap_file=pcap_name, apply_filter=filter)

            for packet in pcap:
                print("packet:", packet)
                if 'WLAN.MGT' in packet:
                    WLAN_MGT_layer = packet['WLAN.MGT']
                    if '0x0003' in WLAN_MGT_layer.wlan_fixed_reason_code:
                        print("Deauthentication packet detected.")
                        allure.attach(name=f"Deauthentication packet detected.",
                                          body=str(packet))
                        deauth_result = 1
                    else:
                        print("Deauthentication packet is not detected.")
                        deauth_result = 0

            if reconfig == "tx_power":
                if deauth_result == 1:
                    allure.attach(name="Test Result", body="TEST FAILED, Deauthentication packet is detected. This response is not expected in Tx power parameter configuration.")
                    return "FAIL", "TEST FAILED, Deauthentication packet is detected, which is not expected in Tx power parameter configuration."
                else:
                    allure.attach(name="Test Result",
                                  body="TEST Passed, Deauthentication packet is not detected. This response is expected in Tx power parameter configuration.")
            else:
                if deauth_result == 0:
                    allure.attach(name="Test Result", body="TEST FAILED, Deauthentication packet is not detected")
                    return "FAIL", "TEST FAILED, Deauthentication packet is not detected"


            #Step 2 validation
            print("station_name", sta_name)
            sta_data = self.json_get(_req_url="port/1/1/%s" % sta_name)

            if reconfig == "band":
                sta_channel = sta_data['interface']['channel']
                print("channel of the station:", sta_channel)
                sta_channel = int(sta_channel)  # Convert sta_channel to an integer
                if 100  <= sta_channel <= 165:
                    print("station channel is changed to upper band successfully") # upper band
                else:
                    print("station channel is not changed to upper band")
                    pass_fail = 'FAIL'
                    allure.attach(name="Test Result", body="TEST FAILED, station channel is not changed to 5G-upper band")
                    return "FAIL", "TEST FAILED, station channel is not changed to 5G-upper band"
            # Step 2 validation
            if reconfig == "channel_width":
                sta_mode = sta_data['interface']['mode']
                print("mode of the station:", sta_mode)
                if '40' in sta_mode:
                    print("channel-width changed to 40Mhz successfully")
                else:
                    print("Test failed, channel-width is not changed to 40Mhz")
                    pass_fail = 'FAIL'
                    allure.attach(name="Test Result",
                                  body="TEST FAILED, station channel-width is not changed to 40Mhz")
                    return "FAIL", "TEST FAILED, station channel-width is not changed to 40Mhz"
            # Step 2 validation
            if reconfig == "tx_power":
                iwinfo = tip_2x_obj.dut_library_object.get_iwinfo()
                # print("iwinfo after Reconfiguration:", iwinfo)
                if "Tx-Power: 20 dBm" in iwinfo:
                    print("Tx-power is changed to 20dBm successfully")
                else:
                    print("Test failed, Tx-power is not changed to 20dBm")
                    pass_fail = 'FAIL'
                    allure.attach(name="Test Result",
                                  body="TEST FAILED, Tx-power is not changed to 20dBm")
                    return "FAIL", "TEST FAILED, Tx-power is not changed to 20dBm"
            # Step 2 validation
            if reconfig == "dfs":
                res = tip_2x_obj.dut_library_object.get_uci_show(param = 'wireless')
                if "wireless.radio1.acs_exclude_dfs='0'" in res:
                    print("dfs parameter is changed successfully")
                else:
                    print("dfs parameter is not changed")
                    pass_fail = 'FAIL'
                    allure.attach(name="Test Result",
                                  body="TEST FAILED, dfs parameter is not changed")
                    return "FAIL", "TEST FAILED, dfs parameter is not changed"
            # Step 2 validation
            if reconfig == "he":
                bss_color = sta_data['interface']['bss color']
                print("bss_color after reconfiguration", bss_color)
                bss_color = int(bss_color)  # Convert sta_channel to an integer
                if bss_color == 60:
                    print("bss color is changed successfully") # upper band
                else:
                    print("bss color is not changed")
                    pass_fail = 'FAIL'
                    allure.attach(name="Test Result", body="TEST FAILED, bss color is not changed")
                    return "FAIL", "TEST FAILED, bss color is not changed"

        return pass_fail, description



    def enterprise_client_connectivity_test(self, ssid="[BLANK]", passkey="[BLANK]", bssid="[BLANK]", dut_data={},
                                            security="open", extra_securities=[], client_type=0, key_mgmt="WPA-EAP",
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
                obj_eap_connect.station_profile.sta_mode = client_type
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
            sta_rows = ["4way time (us)", "channel", "ssid", "cx time (us)", "dhcp (ms)", "ip", "signal", "mac", "mode"]
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
                       vlan_id=[None], num_sta=None, scan_ssid=True, client_type=0, pre_cleanup=True,
                       station_data=["4way time (us)", "channel", "cx time (us)", "dhcp (ms)", "ip", "signal", "mode"],
                       allure_attach=True, identifier=None, allure_name="station data", dut_data={}):
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
        start_sniffer = False
        for radio in data[identifier]["station_data"]:
            if band == "twog":
                if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("2G") and \
                        dict(dut_data.get(identifier)["radio_data"])["2G"] is not None:
                    sniffer_channel = dict(dut_data.get(identifier)["radio_data"])["2G"]["channel"]
                    if data[identifier]["sniff_radio_2g"] is not None and sniffer_channel is not None:
                        start_sniffer = True
                        self.start_sniffer(radio_channel=sniffer_channel,
                                           test_name=f'{data[identifier]["station_data"][radio][0]}',
                                           radio=data[identifier]["sniff_radio_2g"],
                                           duration=120)
                    logging.info("started-sniffer")
            if band == "fiveg":
                if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("5G") and \
                        dict(dut_data.get(identifier)["radio_data"])["5G"] is not None:
                    sniffer_channel = dict(dut_data.get(identifier)["radio_data"])["5G"]["channel"]
                    if data[identifier]["sniff_radio_5g"] is not None and sniffer_channel is not None:
                        start_sniffer = True
                        self.start_sniffer(radio_channel=sniffer_channel,
                                           radio=data[identifier]["sniff_radio_5g"],
                                           duration=120)
                    logging.info("started-sniffer")
            if band == "sixg":
                if dict(dut_data.get(identifier)["radio_data"]).keys().__contains__("6G") and \
                        dict(dut_data.get(identifier)["radio_data"])["6G"] is not None:
                    sniffer_channel = self.lf_sixg_lookup_validation(
                        int(dict(dut_data.get(identifier)["radio_data"])["6G"]["channel"]))
                    logging.info("LF sixg channel: " + str(sniffer_channel))
                    if data[identifier]["sniff_radio_6g"] is not None and sniffer_channel is not None:
                        start_sniffer = True
                        self.start_sniffer(radio_channel=sniffer_channel,
                                           radio=data[identifier]["sniff_radio_6g"],
                                           duration=120)
                    logging.info("started-sniffer")
            client_connect = CreateStation(_host=self.manager_ip, _port=self.manager_http_port,
                                           _sta_list=data[identifier]["station_data"][radio],
                                           _password=data[identifier]["passkey"],
                                           _ssid=data[identifier]["ssid"],
                                           _security=data[identifier]["encryption"])
            client_connect.station_profile.sta_mode = client_type
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
        if start_sniffer:
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
                              "be200_radios": self.be200_radios,
                              "ax210_radios": self.ax210_radios}

        dict_all_radios_5g = {"wave2_5g_radios": self.wave2_5g_radios,
                              "wave1_radios": self.wave1_radios, "mtk_radios": self.mtk_radios,
                              "ax200_radios": self.ax200_radios,
                              "be200_radios": self.be200_radios,
                              "ax210_radios": self.ax210_radios}

        dict_all_radios_6g = {"be200_radios": self.be200_radios, "ax210_radios": self.ax210_radios}

        max_station_per_radio = {"wave2_2g_radios": 64, "wave2_5g_radios": 64, "wave1_radios": 64, "mtk_radios": 19,
                                 "ax200_radios": 1, "ax210_radios": 1, "be200_radios": 1}
        radio_data = {}
        sniff_radio = ""

        for dut in dut_data:
            for idx_ in dut_data[dut]["ssid_data"]:
                temp_band = dut_data[dut]["ssid_data"][idx_]["band"]
                if band == "2G":
                    if temp_band.lower() == "twog":
                        temp_band = "2G"
                elif band == "5G":
                    if temp_band.lower() == "fiveg":
                        temp_band = "5G"
                elif band == "6G":
                    if temp_band.lower() == "sixg":
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

        return radio_data

    def rate_limiting_test(self, mode="BRIDGE", vlan_id=100, batch_size="1,5,10,20,40,64,128",
                           instance_name="wct_instance", download_rate="1Gbps", influx_tags="",
                           upload_rate="1Gbps", protocol="TCP-IPv4", duration="60000", stations="",
                           create_stations=False,
                           sort="interleave", raw_lines=[], move_to_influx=False, dut_data={}, ssid_name=None,
                           num_stations={}, add_stations=True, passkey=None, up_rate=None, down_rate=None):
        obj = self.wifi_capacity(mode=mode, vlan_id=vlan_id, batch_size=batch_size, instance_name=instance_name,
                                 download_rate=download_rate,
                                 influx_tags=influx_tags, upload_rate=upload_rate, protocol=protocol, duration=duration,
                                 stations=stations, create_stations=create_stations, sort=sort, raw_lines=raw_lines,
                                 move_to_influx=move_to_influx,
                                 dut_data=dut_data, ssid_name=ssid_name, num_stations=num_stations,
                                 add_stations=add_stations)
        report_name = obj[0].report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1] + "/"
        numeric_score = self.read_kpi_file(column_name=["numeric-score"], dir_name=report_name)
        logging.info("Numeric-score: " + str(numeric_score))
        download_rate = self.convert_to_gbps(download_rate)
        logging.info("download_rate:- " + str(download_rate))
        upload_rate = self.convert_to_gbps(upload_rate)
        logging.info("upload_rate:- " + str(upload_rate))

        if upload_rate > download_rate:
            logging.info("rate limit ingress-rate:- " + str(up_rate))
            actual_tht = int(numeric_score[1][0])
            logging.info("Actual throughput:- " + str(actual_tht))
            if actual_tht > up_rate:
                pytest.fail(f"Expected Throughput should be less than {up_rate} Mbps")
        elif upload_rate < download_rate:
            logging.info("rate limit egress-rate:- " + str(down_rate))
            actual_tht = int(numeric_score[0][0])
            logging.info("Actual throughput:- " + str(actual_tht))
            if actual_tht > down_rate:
                pytest.fail(f"Expected Throughput should be less than {down_rate} Mbps")
        elif upload_rate == download_rate:
            # Pass fail logic for bidirectional
            logging.info("rate limit ingress-rate:- " + str(up_rate))
            logging.info("rate limit egress-rate:- " + str(down_rate))
            actual_tht_dw = int(numeric_score[0][0])
            actual_tht_up = int(numeric_score[1][0])
            logging.info("Actual throughput download:- " + str(actual_tht_dw))
            logging.info("Actual throughput upload:- " + str(actual_tht_up))
            if actual_tht_dw > down_rate:
                pytest.fail(f"Expected Throughput should be less than {down_rate} Mbps")
            if actual_tht_up > up_rate:
                pytest.fail(f"Expected Throughput should be less than {up_rate} Mbps")

    def wifi_capacity(self, mode="BRIDGE", vlan_id=100, batch_size="1,5,10,20,40,64,128",
                      instance_name="wct_instance", download_rate="1Gbps", influx_tags="",
                      upload_rate="1Gbps", protocol="TCP-IPv4", duration="60000", stations="", create_stations=False,
                      sort="interleave", raw_lines=[], move_to_influx=False, dut_data={}, ssid_name=None,
                      num_stations={}, add_stations=True, create_vlan=True, pass_fail_criteria=False):
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
                    radio_data = self.add_stations(band=band_, num_stations=num_stations[band_], ssid_name=ssid_name,
                                                   dut_data=dut_data,
                                                   identifier=identifier)
                    if vlan_raw_lines is not None:
                        for i in vlan_raw_lines:
                            self.temp_raw_lines.append(i)
                    self.chamber_view(raw_lines="custom")
                    if pass_fail_criteria:
                        # Station data
                        self.band_sta = list(num_stations.keys())[0]
                        logging.info("band: " + str(self.band_sta))
                        if num_stations[self.band_sta] == 1:
                            logging.info("radio_data: " + str(radio_data))
                            sta_radio = list(radio_data.keys())[0]
                            logging.info("sta_radio: " + str(sta_radio))
                            sta_radio = sta_radio.split(".")
                            shelf = int(sta_radio[0])
                            resource = int(sta_radio[1])
                            radio_ = sta_radio[2]
                            # finding radio number for sta name e.g. for wiphy2 the radio num is 2. Sta name will be wlan2
                            radio_num = int(''.join(x for x in radio_ if x.isdigit()))
                            logging.info("radio_num: " + str(radio_num))
                            sta_name = f"{shelf}.{resource}.wlan{radio_num}"
                            logging.info("sta_name: " + str(sta_name))
                            self.local_realm.admin_up(sta_name)
                            sta_ip = self.local_realm.wait_for_ip([sta_name], timeout_sec=120)
                            sta_rows = ["4way time (us)", "channel", "ssid", "key/phrase", "cx time (us)", "dhcp (ms)",
                                        "ip", "signal",
                                        "mac", "mode"]
                            if str(self.band_sta) != "6G":
                                allure_attach = True
                            else:
                                allure_attach = False
                            self.get_station_data(sta_name=[sta_name], rows=sta_rows,
                                                  allure_attach=allure_attach)
                            if sta_ip:
                                logging.info("ip's acquired")
                                self.sta_mode_ = \
                                    self.json_get(f'/port/{shelf}/{resource}/wlan{radio_num}?fields=mode')['interface'][
                                        'mode']
                                logging.info("sta_mode:- " + str(self.sta_mode_))
                            else:
                                logging.info("Stations Failed to get IP's")
                                pytest.fail("Stations Failed to get IP's")
                            ssid = self.json_get(f'/port/{shelf}/{resource}/wlan{radio_num}?fields=ssid')['interface'][
                                'ssid']
                            logging.info("ssid:- " + str(ssid))
                            passkey = \
                                self.json_get(f'/port/{shelf}/{resource}/wlan{radio_num}?fields=key/phrase')[
                                    'interface'][
                                    'key/phrase']
                            logging.info("passkey:- " + str(passkey))
                            if "160" in self.sta_mode_ or str(self.band_sta) == "6G":
                                self.client_disconnect(station_name=[sta_name])
                                logging.info("DUT Data: " + str(dut_data))
                                encryption_value = None
                                # Finding sta security
                                for ssid_info in dut_data[identifier]['ssid_data'].values():
                                    if ssid_info['ssid'] == ssid:
                                        encryption_value = ssid_info['encryption']
                                        if encryption_value.lower() == "open":
                                            security_ = "[BLANK]"
                                        else:
                                            security_ = encryption_value
                                        break

                                client_connect = CreateStation(_host=self.manager_ip, _port=self.manager_http_port,
                                                               _sta_list=[sta_name],
                                                               _password=passkey,
                                                               _ssid=ssid,
                                                               _security=security_)
                                client_connect.station_profile.sta_mode = 0
                                client_connect.station_profile.use_ht160 = True
                                client_connect.upstream_resource = int(upstream_port.split(".")[1])
                                client_connect.upstream_port = str(upstream_port.split(".")[2])
                                client_connect.radio = sta_radio
                                client_connect.build()
                                result = client_connect.wait_for_ip(station_list=[sta_name], timeout_sec=240)
                                self.get_station_data(sta_name=[sta_name], rows=sta_rows,
                                                      allure_attach=True)
                                if result:
                                    logging.info("ip's acquired")
                                    self.sta_mode_ = \
                                        self.json_get(f'/port/{shelf}/{resource}/wlan{radio_num}?fields=mode')[
                                            'interface'][
                                            'mode']
                                    logging.info("sta_mode_vht_160_enable:- " + str(self.sta_mode_))
                                else:
                                    logging.info("Stations Failed to get IP's")
                                    pytest.fail("Stations Failed to get IP's")

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
            time.sleep(15)
            logging.info("report_name: " + str(report_name))
            self.attach_report_graphs(report_name=report_name)
            self.attach_report_kpi(report_name=report_name)
            numeric_score = self.read_kpi_file(column_name=["numeric-score"], dir_name=report_name)
            logging.info("Numeric-score: " + str(numeric_score))
            max_num_stations = int(sum(num_stations.values()))
            logging.info("Max num stations: " + str(max_num_stations))
            try:
                # Admin down
                exist_sta = []
                for u in self.json_get("/port/?fields=port+type,alias")['interfaces']:
                    if list(u.values())[0]['port type'] not in ['Ethernet', 'WIFI-Radio', 'NA']:
                        exist_sta.append(list(u.values())[0]['alias'])
                if len(exist_sta) == 0:
                    logging.info("Existing stations are not available")
                else:
                    for port_eid in exist_sta:
                        # admin down
                        self.local_realm.admin_down(port_eid)
                        time.sleep(0.3)
            except Exception as e:
                print(e)
                pass
            if len(numeric_score) < 5:
                if int(numeric_score[0][0]) < max_num_stations and int(numeric_score[1][0]) < max_num_stations and int(
                        numeric_score[-1][0]) > 0 and int(numeric_score[-2][0]) > 0:
                    pytest.fail("Station did not get an ip")
            else:
                if int(numeric_score[0][0]) == 0 and int(numeric_score[1][0]) == 0 and int(
                        numeric_score[2][0]) == 0:
                    pytest.fail("Did not report traffic")
            if pass_fail_criteria:
                if add_stations:
                    if num_stations[self.band_sta] == 1:
                        current_directory = os.getcwd()
                        file_path = current_directory + "/e2e/basic/performance_tests/performance_pass_fail.json"
                        logging.info("performance_pass file config path:- " + str(file_path))
                        with open(file_path, 'r') as file:
                            json_string = file.read()
                            all_pass_fail_data = json.loads(json_string)
                        logging.info("All Testbed pass fail data:- " + str(all_pass_fail_data))
                        # validate config json data
                        try:
                            json_object = json.dumps(all_pass_fail_data)
                        except ValueError as e:
                            logging.info("Performance Pass/Fail data is invalid")
                            pytest.fail("Performance Pass/Fail data is invalid")
                        logging.info("DUT Data: " + str(self.dut_data))
                        model = self.dut_data[0]["model"]
                        if model in all_pass_fail_data["AP Models"]:
                            pass_fail_values = all_pass_fail_data["AP Models"][model]
                        else:
                            logging.error("AP model is not available in performance_pass_fail.json file")
                        logging.info(str(model) + " All Benchmark throughput:- " + str(pass_fail_values))
                        split_mode = self.sta_mode_.split(" ")
                        key = f"{self.band_sta} {split_mode[2]} {split_mode[1]}MHz"
                        logging.info("key:- " + str(key))
                        proto = None
                        if "TCP" in protocol:
                            proto = "TCP"
                        else:
                            proto = "UDP"
                        logging.info("Proto:- " + str(proto))
                        logging.info("Given LF download_rate:- " + str(download_rate))
                        logging.info("Given LF upload_rate:- " + str(upload_rate))
                        pass_fail_value = pass_fail_values[key][proto]
                        download_rate = self.convert_to_gbps(download_rate)
                        logging.info("download_rate:- " + str(download_rate))
                        upload_rate = self.convert_to_gbps(upload_rate)
                        logging.info("upload_rate:- " + str(upload_rate))
                        # Pass fail logic for Upload. validating download rate because providing some value during Upload
                        if upload_rate > download_rate:
                            logging.info("Benchmark throughput:- " + str(pass_fail_value) + "+")
                            allure.attach(name="Benchmark throughput: ",
                                          body=str(pass_fail_value) + "+ Mbps")
                            actual_tht = int(numeric_score[1][0])
                            logging.info("Actual throughput:- " + str(actual_tht))
                            allure.attach(name="Actual throughput: ",
                                          body=str(actual_tht) + " Mbps")
                            if actual_tht < pass_fail_value:
                                pytest.fail(
                                    f"Benchmark throughput:- {pass_fail_value}+ Mbps, Actual throughput:- {actual_tht} Mbps")
                        elif upload_rate < download_rate:
                            # Pass fail logic for Download. validating upload rate because providing some value during download
                            logging.info("Benchmark throughput:- " + str(pass_fail_value) + "+")
                            allure.attach(name="Benchmark throughput: ",
                                          body=str(pass_fail_value) + "+ Mbps")
                            actual_tht = int(numeric_score[0][0])
                            logging.info("Actual throughput:- " + str(actual_tht))
                            allure.attach(name="Actual throughput: ",
                                          body=str(actual_tht) + " Mbps")
                            if actual_tht < pass_fail_value:
                                pytest.fail(
                                    f"Benchmark throughput:- {pass_fail_value}+ Mbps, Actual throughput:- {actual_tht} Mbps")
                        elif upload_rate == download_rate:
                            # Pass fail logic for bidirectional
                            pass_fail_value = pass_fail_value * 2
                            logging.info("Benchmark throughput:- " + str(pass_fail_value) + "+")
                            allure.attach(name="Benchmark throughput: ",
                                          body=str(pass_fail_value) + "+ Mbps")
                            actual_tht = int(numeric_score[2][0])
                            logging.info("Actual throughput:- " + str(actual_tht))
                            allure.attach(name="Actual throughput: ",
                                          body=str(actual_tht) + " Mbps")
                            if actual_tht < pass_fail_value:
                                pytest.fail(
                                    f"Benchmark throughput:- {pass_fail_value}+ Mbps, Actual throughput:- {actual_tht} Mbps")

            wificapacity_obj_list.append(wificapacity_obj)

        return wificapacity_obj_list

    def dataplane_throughput_test(self, ssid="[BLANK]", passkey="[BLANK]", security="wpa2", num_sta=1, mode="BRIDGE",
                                  vlan_id=[None],
                                  download_rate="85%", band="twog", scan_ssid=True,
                                  upload_rate="0", duration="15s", instance_name="test_demo", raw_lines=None,
                                  influx_tags="",
                                  move_to_influx=False,
                                  station_data=["4way time (us)", "channel", "cx time (us)", "dhcp (ms)", "ip",
                                                "signal", "mode"],
                                  allure_attach=True, allure_name="station data", client_type=0, dut_data={}):
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
                                               vlan_id=vlan_id, num_sta=num_sta, scan_ssid=scan_ssid,
                                               station_data=station_data,
                                               allure_attach=allure_attach, identifier=identifier,
                                               allure_name=allure_name, client_type=client_type, dut_data=dut_data)

            if raw_lines is None:
                raw_lines = [['pkts: 142;256;512;1024;MTU;4000'], ['directions: DUT Transmit;DUT Receive'],
                             ['traffic_types: UDP;TCP'],
                             ["show_3s: 1"], ["show_ll_graphs: 1"], ["show_log: 1"]]
            sets = [['Maximize Unused Attenuators', '0']]

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
                                          sets=sets,
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
            all_radio_5g = (self.wave2_5g_radios + self.wave1_radios + self.mtk_radios + self.ax200_radios +
                            self.be200_radios + self.ax210_radios)
            logging.info("All 5g radios" + str(all_radio_5g))
            all_radio_2g = (self.wave2_2g_radios + self.wave1_radios + self.mtk_radios + self.ax200_radios +
                            self.be200_radios + self.ax210_radios)
            logging.info("All 2g radios" + str(all_radio_2g))
            radio = all_radio_5g[:2] if band == "5G" else all_radio_2g[:2]
            logging.info("Radios: " + str(radio))
            upld_rate, downld_rate, val = "0Gbps", "0Gbps", []
            if traffic_direction == "upload":
                upld_rate = traffic_rate
                val = [['ul_rate_sel: Per-Station Upload Rate:']]
            elif traffic_direction == "download":
                downld_rate = traffic_rate
                val = [['dl_rate_sel: Per-Station Download Rate:']]
            per_radio_sta = int(num_stations / len(radio))
            rem = num_stations % len(radio)
            logging.info("Total stations per radio: " + str(per_radio_sta))
            num_stations = lambda rem: per_radio_sta + rem if rem else per_radio_sta
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
            self.temp_raw_lines = self.default_scenario_raw_lines.copy()

            if mode == "VLAN":
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
            thr1 = threading.Thread(target=thread_fun, args=(sta_list[8:16],))
            thr1.start()
            wct_obj = self.wifi_capacity(instance_name=instance_name, mode=mode, vlan_id=vlan,
                                         download_rate=downld_rate, add_stations=False,
                                         stations=sel_stations, raw_lines=val, batch_size="8", upload_rate=upld_rate,
                                         protocol="UDP-IPv4", duration="120000", create_stations=False,
                                         dut_data=dut_data, create_vlan=False,
                                         sort="interleave", )

            report_name = wct_obj[0].report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1] + "/"
            file_name = "/csv-data/data-Combined_bps__60_second_running_average-1.csv"
            if not os.path.exists(f"../reports/{report_name}{file_name}"):
                file_name = file_name.replace('_bps__', '_Mbps__')
            csv_val = self.read_csv_individual_station_throughput(dir_name=report_name, option=traffic_direction,
                                                                  file_name=file_name)
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
                allure.attach.file(source="../reports/" + report_name + file_name, name="Throughput CSV file",
                                   attachment_type=allure.attachment_type.CSV)
                self.allure_report_table_format(dict_data=csv_val, key="Stations", value="Throughput values",
                                                name="Test_results")
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

    def tr398v2(self, mode="BRIDGE",
                vlan_id=1, skip_2g=False, skip_5g=False, test=None,
                move_to_influx=False,
                dut_data={},
                create_vlan=True, testbed=None, extra_raw_lines=[[]]):
        current_directory = os.getcwd()
        file_path = current_directory + "/e2e/advanced/advanced-config.json"
        logging.info("Advanced file config path:- " + str(file_path))
        with open(file_path, 'r') as file:
            json_string = file.read()
            all_config_data = json.loads(json_string)
        logging.info("Advanced testbeds config data:- " + str(all_config_data))
        # validate config json data
        try:
            json_object = json.dumps(all_config_data)
        except ValueError as e:
            logging.info("Advanced config data is invalid")
            pytest.fail("Advanced config data is invalid")
        testbed_ = testbed[:-1]
        testbed_config_data = all_config_data["TESTBEDS"][testbed_]
        logging.info(str(testbed_) + " Testbed config data:- " + str(testbed_config_data))
        self.client_disconnect(clean_l3_traffic=True)
        if type(test) == str:
            test = test.split(",")
        # DUT Name
        dut_name = list(dut_data.keys())[0]
        logging.info("DUT name:- " + str(dut_name))
        """ 2G and 5G channel """
        channel_2g = dut_data[dut_name]["radio_data"]["2G"]["channel"]
        channel_5g = dut_data[dut_name]["radio_data"]["5G"]["channel"]
        logging.info("2g_channel:- " + str(channel_2g))
        logging.info("5g_channel:- " + str(channel_5g))
        logging.info("DUT data:- " + str(dut_data))
        virtual_sta_radios = {}
        virtual_sta_rssi_0_2 = {}
        virtual_sta_rssi_0_5 = {}
        virtual_sta_atten = {}
        ax_radios = {}
        ax_rssi_0_2 = {}
        ax_rssi_0_5 = {}
        ax_atten = {}
        raw_line = []
        k = 0
        """ Logic for virtual sta radios """
        # find out virtual sta radios and make raw lines
        config_data = testbed_config_data["Virtual Sta Radio Settings"]
        for i in config_data:
            for j in config_data[i]:
                virtual_sta_radios["radio-" + str(k)] = config_data[i]["5Ghz"]
                k = k + 1
                virtual_sta_radios["radio-" + str(k)] = config_data[i]["2.4Ghz"]
                break
            k = k + 1
        logging.info("virtual_sta_radios:- " + str(virtual_sta_radios))
        raw_line_list = [[f"{key}: {value}"] for key, value in virtual_sta_radios.items()]
        raw_line.extend(raw_line_list)
        # find out virtual sta virtual_sta_rssi_0_2, virtual_sta_rssi_0_5, virtual_sta_atten and make raw lines
        c1 = 0
        c2 = 0
        c3 = 0
        config_data = testbed_config_data["Virtual Sta Radio Settings"]
        for i in config_data:
            for j in config_data[i]:
                if j == "2.4Ghz RSSI 0 Atten":
                    for k in config_data[i]["2.4Ghz RSSI 0 Atten"]:
                        virtual_sta_rssi_0_2["rssi_0_2-" + str(c1)] = k
                        c1 = c1 + 1
                if j == "5Gh RSSI 0 Atten":
                    for l in config_data[i]["5Gh RSSI 0 Atten"]:
                        virtual_sta_rssi_0_5["rssi_0_5-" + str(c2)] = l
                        c2 = c2 + 1
                if j == "Attenuator Modules":
                    for m in config_data[i]["Attenuator Modules"]:
                        virtual_sta_atten["atten-" + str(c3)] = m
                        c3 = c3 + 1

        logging.info("virtual_sta_rssi_0_2:- " + str(virtual_sta_rssi_0_2))
        logging.info("virtual_sta_rssi_0_5:- " + str(virtual_sta_rssi_0_5))
        logging.info("virtual_sta_atten:- " + str(virtual_sta_atten))
        raw_line_list = [[f"{key}: {value}"] for key, value in virtual_sta_rssi_0_2.items()]
        raw_line.extend(raw_line_list)
        raw_line_list = [[f"{key}: {value}"] for key, value in virtual_sta_rssi_0_5.items()]
        raw_line.extend(raw_line_list)
        raw_line_list = [[f"{key}: {value}"] for key, value in virtual_sta_atten.items()]
        raw_line.extend(raw_line_list)
        """ Logic for Ax radio setting """
        c1 = 0
        c2 = 0
        c3 = 0
        c4 = 0
        config_data = testbed_config_data["802.11AX Settings"]
        for i in config_data:
            for j in config_data[i]:
                if j == "Radios":
                    for k in config_data[i]["Radios"]:
                        ax_radios["ax_radio-" + str(c1)] = k
                        c1 = c1 + 1
                if j == "2.4Ghz RSSI 0 Atten":
                    for l in config_data[i]["2.4Ghz RSSI 0 Atten"]:
                        ax_rssi_0_2["ax_rssi_0_2-" + str(c2)] = l
                        c2 = c2 + 1
                if j == "5Ghz RSSI 0 Atten":
                    for m in config_data[i]["5Ghz RSSI 0 Atten"]:
                        ax_rssi_0_5["ax_rssi_0_5-" + str(c3)] = m
                        c3 = c3 + 1
                if j == "Attenuator Modules":
                    for m in config_data[i]["Attenuator Modules"]:
                        if m != "":
                            ax_atten["ax_atten-" + str(c4)] = m
                        if c4 >= 12:
                            c4 = c4 + 2
                        else:
                            c4 = c4 + 1

        logging.info("ax_radios:- " + str(ax_radios))
        logging.info("ax_rssi_0_2:- " + str(ax_rssi_0_2))
        logging.info("ax_rssi_0_5:- " + str(ax_rssi_0_5))
        logging.info("ax_atten:- " + str(ax_atten))
        raw_line_list = [[f"{key}: {value}"] for key, value in ax_radios.items()]
        raw_line.extend(raw_line_list)
        raw_line_list = [[f"{key}: {value}"] for key, value in ax_rssi_0_2.items()]
        raw_line.extend(raw_line_list)
        raw_line_list = [[f"{key}: {value}"] for key, value in ax_rssi_0_5.items()]
        raw_line.extend(raw_line_list)
        raw_line_list = [[f"{key}: {value}"] for key, value in ax_atten.items()]
        raw_line.extend(raw_line_list)

        # Fetch 2g_dut and 5g_dut
        dut_2g = None
        dut_5g = None
        for i in dut_data[dut_name]['ssid_data']:
            self.dut_idx_mapping[str(i)] = list(dut_data[dut_name]['ssid_data'][i].values())
            if self.dut_idx_mapping[str(i)][3] == "2G":
                dut_2g = dut_name + ' ' + self.dut_idx_mapping[str(i)][0] + ' ' \
                                                                            '' + self.dut_idx_mapping[str(i)][
                             4].lower() + f' (1)'
            if self.dut_idx_mapping[str(i)][3] == "5G":
                dut_5g = dut_name + ' ' + self.dut_idx_mapping[str(i)][0] + ' ' \
                                                                            '' + \
                         self.dut_idx_mapping[str(i)][4].lower() + f' (2)'
        logging.info("dut_2g:- " + str(dut_2g))
        logging.info("dut_5g:- " + str(dut_5g))
        skip_twog, skip_fiveg = '1' if skip_2g else '0', '1' if skip_5g else '0'
        if mode == "BRIDGE" or mode == "NAT-WAN":
            upstream_port = list(self.lanforge_data['wan_ports'].keys())[0]
        if mode == "VLAN":
            if vlan_id is None:
                logging.error("VLAN ID is Unspecified in the VLAN Case")
                pytest.skip("VLAN ID is Unspecified in the VLAN Case")
            else:
                if create_vlan:
                    vlan_raw_lines = self.add_vlan(vlan_ids=vlan_id, build=True)
                upstream_port = list(self.lanforge_data['wan_ports'].keys())[0] + "." + str(vlan_id[0])
        logging.info("Upstream data: " + str(upstream_port))
        skip_bandv2 = [['Skip 2.4Ghz Tests', f'{skip_twog}'], ['Skip 5Ghz Tests', f'{skip_fiveg}'],
                       ['2.4Ghz Channel', f'{channel_2g}'], ['5Ghz Channel', f'{channel_5g}'],
                       ["use_virtual_ax_sta", "1"],
                       ["Use Issue-3 Behaviour", "0"], ["Skip 6Ghz Tests", "1"]]
        enable_tests = [['rxsens: 0'], ['max_cx: 0'], ['max_tput: 0'], ['peak_perf: 0'], ['max_tput_bi: 0'],
                        ['dual_band_tput: 0'], ['multi_band_tput: 0'], ['atf: 0'], ['atf3: 0'], ['qos3: 0'],
                        ['lat3: 0'], ['mcast3: 0'], ['rvr: 0'], ['spatial: 0'], ['multi_sta: 0'], ['reset: 0'],
                        ['mu_mimo: 0'], ['stability: 0'], ['ap_coex: 0'], ['acs: 0']]
        for t in test:
            if [f"{t}: 0"] in enable_tests:
                enable_tests[enable_tests.index([f"{t}: 0"])] = [f"{t}: 1"]
            else:
                logging.info(f"Unable to find the {t} test in selected run")
                raise ValueError(f"Unable to find the {t} test in selected run")
        raw_line.extend(enable_tests)
        update_cv_dut = {}
        try:
            for i in dut_data:
                update_cv_dut[i] = dict.fromkeys(dut_data[i], {})
                for j in dut_data[i]:
                    if j == 'ssid_data':
                        for k in dut_data[i][j]:
                            if (dut_data[i][j][k]['band'] == '5G' and dut_5g != ""
                            ) or (dut_data[i][j][k]['band'] == '2G' and dut_2g != ""):
                                update_cv_dut[i][j][k] = dut_data[i][j][k].copy()
                    else:
                        update_cv_dut[i][j] = dut_data[i][j].copy()
        except Exception as e:
            logging.error(f"{e}")
        logging.info("update cv dut:- " + str(update_cv_dut))
        self.update_dut_ssid(dut_data=update_cv_dut)
        instance_name = "tr398v2-instance-{}".format(str(random.randint(0, 100000)))

        # if not os.path.exists("tr398-test-config.txt"):
        # with open("tr398v2-test-config.txt", "wt") as f:
        #     for i in raw_line:
        #         f.write(str(i[0]) + "\n")
        #     f.close()
        """ Test duration 60 sec """
        raw_line.append(["dur120: 60"])
        """Add turn table"""
        raw_line.append(["turn_table: DUT-Chamber"])
        """Adding extra raw lines """
        if extra_raw_lines[0]:
            raw_line.extend(extra_raw_lines)
        logging.info("raw lines:- " + str(raw_line))
        cvtest_obj = TR398v2Test(lf_host=self.manager_ip,
                                 lf_port=self.manager_http_port,
                                 lf_user="lanforge",
                                 lf_password="lanforge",
                                 instance_name=instance_name,
                                 upstream=upstream_port,
                                 pull_report=True,
                                 local_lf_report_dir=self.local_report_path,
                                 load_old_cfg=False,
                                 dut2=dut_2g,
                                 dut5=dut_5g,
                                 enables=[],
                                 disables=[],
                                 raw_lines=raw_line,
                                 sets=skip_bandv2,
                                 test_rig=dut_name)
        # self.cvtest_obj.test_name, self.cvtest_obj.blob_text = "TR-398 Issue 2", "TR-398v2-"
        # self.cvtest_obj.result = True
        cvtest_obj.setup()
        cvtest_obj.run()
        # if os.path.exists("tr398v2-test-config.txt"):
        #     os.remove("tr398v2-test-config.txt")
        if move_to_influx:
            try:
                report_name = "../reports/" + \
                              cvtest_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1]
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
        report_name = cvtest_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1] + "/"
        time.sleep(10)
        self.attach_report_graphs(report_name=report_name, pdf_name=str(test[0]) + " Test PDF Report")
        result = self.read_kpi_file(column_name=["pass/fail"], dir_name=report_name)
        logging.info("result: " + str(result))
        numeric_score = self.read_kpi_file(column_name=["numeric-score"], dir_name=report_name)
        logging.info("Numeric-score: " + str(numeric_score))
        test_details = self.read_kpi_file(column_name=["test details"], dir_name=report_name)
        logging.info("test_details: " + str(test_details))
        self.attach_report_kpi(report_name=report_name)
        self.client_disconnect(clear_all_sta=True, clean_l3_traffic=True)
        if result[0][0] == "PASS":
            return True, "Test Passed"
        else:
            return False, f"Test is Failed. Candela Score:- {numeric_score[0][0]}. Test Details:- {test_details[0][0]}."

    def tr398(self, radios_2g=[], radios_5g=[], radios_ax=[], dut_name="TIP", dut_5g="", dut_2g="", mode="BRIDGE",
              vlan_id=1, skip_2g=True, skip_5g=False, instance_name="", test=None, move_to_influx=False, dut_data={},
              ssid_name='', security_key='[BLANK]', security="open", sniff_packets=False, create_vlan=True,
              tr398v2=True, tr398=False):
        # User can select one or more TR398 tests
        try:
            if type(test) == str:
                test = test.split(",")
            self.client_disconnect(clean_l3_traffic=True)
            raw_line = []
            skip_twog, skip_fiveg = '1' if skip_2g else '0', '1' if skip_5g else '0'
            channel = 149 if skip_twog else 11
            sniff_radio = 'wiphy0'
            if mode == "BRIDGE" or mode == "NAT-WAN":
                upstream_port = list(self.lanforge_data['wan_ports'].keys())[0]
            if mode == "VLAN":
                if vlan_id is None:
                    logging.error("VLAN ID is Unspecified in the VLAN Case")
                    pytest.skip("VLAN ID is Unspecified in the VLAN Case")
                else:
                    if create_vlan:
                        vlan_raw_lines = self.add_vlan(vlan_ids=vlan_id, build=True)
                    upstream_port = list(self.lanforge_data['wan_ports'].keys())[0] + "." + str(vlan_id[0])
            logging.info("Upstream data: " + str(upstream_port))

            # atten_serial = self.attenuator_serial_radio(ssid=ssid_name, passkey=security_key, security=security,
            # sta_mode=0, station_name=['sta0000'], radio=self.wave2_2g_radios[0] if skip_5g else
            # self.wave2_5g_radios[0])

            atten_serial = self.attenuator_serial()

            if tr398v2:
                enable_tests = [['rxsens: 0'], ['max_cx: 0'], ['max_tput: 0'], ['peak_perf: 0'], ['max_tput_bi: 0'],
                                ['dual_band_tput: 0'], ['multi_band_tput: 0'], ['atf: 0'], ['atf3: 0'], ['qos3: 0'],
                                ['lat3: 0'], ['mcast3: 0'], ['rvr: 0'], ['spatial: 0'], ['multi_sta: 0'], ['reset: 0'],
                                ['mu_mimo: 0'], ['stability: 0'], ['ap_coex: 0'], ['acs: 0']]
            elif tr398:
                enable_tests = [['rxsens: 0'], ['max_cx: 0'], ['max_tput: 0'], ['atf: 0'], ['rvr: 0'], ['spatial: 0'],
                                ['multi_sta: 0'], ['reset: 0'], ['mu_mimo: 0'], ['stability: 0'], ['ap_coex: 0']]
            for t in test:
                if [f"{t}: 0"] in enable_tests:
                    enable_tests[enable_tests.index([f"{t}: 0"])] = [f"{t}: 1"]
                else:
                    logging.info(f"Unable to find the {t} test in selected run")
                    raise ValueError(f"Unable to find the {t} test in selected run")

            rad_atten = [[f'atten-0: {atten_serial[0]}.0'], [f'atten-1: {atten_serial[0]}.1'],
                         [f'atten-2: {atten_serial[0]}.2'],
                         [f'atten-3: {atten_serial[0]}.3'], [f'atten-4: {atten_serial[1]}.0'],
                         [f'atten-5: {atten_serial[1]}.1'],
                         [f'atten-8: {atten_serial[1]}.2'], [f'atten-9: {atten_serial[1]}.3']]

            skip_band = [['Skip 2.4Ghz Tests', f'{skip_twog}'], ['Skip 5Ghz Tests', f'{skip_fiveg}'],
                         ['2.4Ghz Channel', 'AUTO'], ['5Ghz Channel', 'AUTO']]

            skip_bandv2 = [['Skip 2.4Ghz Tests', f'{skip_twog}'], ['Skip 5Ghz Tests', f'{skip_fiveg}'],
                           ['2.4Ghz Channel', 'AUTO'], ['5Ghz Channel', 'AUTO'], ['Skip AX Tests', '1']]

            if len(radios_2g) >= 3 and len(radios_5g) >= 3:
                for i in range(6):
                    if i == 0 or i == 2:
                        raw_line.append([f'radio-{i}: {radios_5g[0] if i == 0 else radios_5g[1]}'])
                    if i == 1 or i == 3:
                        raw_line.append([f'radio-{i}: {radios_2g[0] if i == 1 else radios_2g[1]}'])
                    if i == 4 or i == 5:
                        raw_line.append([f'radio-{i}: {radios_5g[2] if i == 4 else radios_2g[2]}'])
                if sniff_packets:
                    if len(radios_ax) >= 1:
                        temp_ax = str(radios_ax[0]).split(" ")
                        if len(temp_ax) == 2:
                            sniff_radio = str(temp_ax[1])
                    elif skip_2g:
                        temp = str(radios_5g[0]).split(" ")
                        if len(temp) == 2:
                            sniff_radio = str(temp[1])
                    elif skip_5g:
                        temp = str(radios_2g[0]).split(" ")
                        if len(temp) == 2:
                            sniff_radio = str(temp[1])
            elif len(radios_2g) >= 2 and len(radios_5g) >= 2 and len(radios_ax) >= 2:
                if len(radios_2g) >= 3 and len(radios_5g) >= 3:
                    for i in range(6):
                        if i == 0 or i == 2:
                            raw_line.append([f'radio-{i}: {radios_5g[0] if i == 0 else radios_5g[1]}'])
                        if i == 1 or i == 3:
                            raw_line.append([f'radio-{i}: {radios_2g[0] if i == 1 else radios_2g[1]}'])
                        if i == 4 or i == 5:
                            raw_line.append([f'radio-{i}: {radios_5g[2] if i == 4 else radios_2g[2]}'])
                    if sniff_packets:
                        if len(radios_ax) >= 1:
                            temp_ax = str(radios_ax[0]).split(" ")
                            if len(temp_ax) == 2:
                                sniff_radio = str(temp_ax[1])
                else:
                    for i in range(6):
                        if i == 0 or i == 2:
                            raw_line.append([f'radio-{i}: {radios_5g[0] if i == 0 else radios_5g[1]}'])
                        if i == 1 or i == 3:
                            raw_line.append([f'radio-{i}: {radios_2g[0] if i == 1 else radios_2g[1]}'])
                        if i == 4 or i == 5:
                            raw_line.append([f'radio-{i}: {radios_ax[0] if i == 4 else radios_ax[1]}'])
            elif len(radios_2g) == 0 and len(radios_5g) == 0 and len(radios_ax) >= 3 and len(radios_ax) >= 6:
                for i in range(6):
                    raw_line.append([f'radio-{i}: {radios_ax[i]}'])

            if len(raw_line) != 6:
                raw_line = [['radio-0: 1.1.5 wiphy1'], ['radio-1: 1.1.4 wiphy0'], ['radio-2: 1.1.7 wiphy3'],
                            ['radio-3: 1.1.6 wiphy2'], ['radio-4: 1.1.8 wiphy4'], ['radio-5: 1.1.9 wiphy5']]
            raw_line.extend(enable_tests + rad_atten)
            update_cv_dut = {}
            try:
                for i in dut_data:
                    update_cv_dut[i] = dict.fromkeys(dut_data[i], {})
                    for j in dut_data[i]:
                        if j == 'ssid_data':
                            for k in dut_data[i][j]:
                                if (dut_data[i][j][k]['band'] == '5G' and dut_5g != ""
                                ) or (dut_data[i][j][k]['band'] == '2G' and dut_2g != ""):
                                    update_cv_dut[i][j][k] = dut_data[i][j][k].copy()
                        else:
                            update_cv_dut[i][j] = dut_data[i][j].copy()
            except Exception as e:
                logging.error(f"{e}")
            self.update_dut_ssid(dut_data=update_cv_dut)
            instance_name = "tr398-instance-{}".format(str(random.randint(0, 100000)))

            # if not os.path.exists("tr398-test-config.txt"):
            with open("tr398-test-config.txt", "wt") as f:
                for i in raw_line:
                    f.write(str(i[0]) + "\n")
                f.close()

            if tr398v2:
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
                                              sets=skip_bandv2,
                                              test_rig=dut_name)
                self.cvtest_obj.test_name, self.cvtest_obj.blob_text = "TR-398 Issue 2", "TR-398v2-"
            elif tr398:
                self.cvtest_obj = TR398Test(lf_host=self.lanforge_ip,
                                            lf_port=self.lanforge_port,
                                            lf_user="lanforge",
                                            lf_password="lanforge",
                                            instance_name=instance_name,
                                            config_name="cv_dflt_cfg",
                                            upstream="1.1." + upstream_port,
                                            pull_report=True,
                                            local_lf_report_dir=self.local_report_path,
                                            load_old_cfg=False,
                                            dut2=dut_2g,
                                            dut5=dut_5g,
                                            raw_lines_file="mu-mimo-config.txt",
                                            enables=[],
                                            disables=[],
                                            raw_lines=[],
                                            sets=skip_band,
                                            test_rig=dut_name
                                            )
                self.cvtest_obj.test_name, self.cvtest_obj.blob_text = "TR-398", "TR-398-"
            self.cvtest_obj.result = True
            self.cvtest_obj.setup()
            if sniff_packets:
                self.pcap_obj = LfPcap(host=self.manager_ip, port=self.manager_http_port)
                t1 = threading.Thread(target=self.cvtest_obj.run)
                t1.start()
                t2 = threading.Thread(target=self.pcap_obj.sniff_packets, args=(sniff_radio, "mu-mimo", channel, 40))
                if t1.is_alive():
                    time.sleep(375)
                    t2.start()
                while t1.is_alive():
                    time.sleep(1)
            else:
                self.cvtest_obj.run()
            if os.path.exists("tr398-test-config.txt"):
                os.remove("tr398-test-config.txt")

            if move_to_influx:
                try:
                    report_name = "../reports/" + \
                                  self.cvtest_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1]
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
            report_name = self.cvtest_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1] + "/"
            self.attach_report_graphs(report_name=report_name)
            result = self.read_kpi_file(column_name=["pass/fail"], dir_name=report_name)
            allure.attach.file(source="../reports/" + report_name + "/kpi.csv",
                               name=f"{test}_test_report.csv", attachment_type=allure.attachment_type.CSV)
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
            sta = list(map(lambda i: f"sta000{i}", range(3)))
            all_radio_5g = (self.wave2_5g_radios + self.wave1_radios + self.mtk_radios + self.ax200_radios +
                            self.be200_radios + self.ax210_radios)
            logging.info("All 5g radios" + str(all_radio_5g))
            all_radio_2g = (self.wave2_2g_radios + self.wave1_radios + self.mtk_radios + self.ax200_radios +
                            self.be200_radios + self.ax210_radios)
            logging.info("All 2g radios" + str(all_radio_2g))
            if len(all_radio_5g) < 3:
                pytest.fail("3 Radios are not available")
            else:
                radio_5g = all_radio_5g[:3]
            if len(all_radio_2g) < 3:
                pytest.fail("3 Radios are not available")
            else:
                radio_2g = all_radio_2g[:3]
            radios, sta_mode = (radio_5g, [1, 9]) if band == "fiveg" else (radio_2g, [2, 11])
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
                                                                 radio=radios[i], station_name=[sta[i]],
                                                                 client_type=sta_mode[0])
                else:
                    # mode = 11/9 will create bgn-AC/an-AC client
                    create_sta = self.client_connect_using_radio(ssid=ssid, passkey=passkey, security=security,
                                                                 radio=radios[i], station_name=[sta[i]],
                                                                 client_type=sta_mode[1])
                if create_sta == False:
                    logging.info(f"Test failed due to no IP for {sta[i]}")
                    assert False, f"Test failed due to no IP for {sta[i]}"
            else:
                lf_sta = list(create_sta.station_map().keys())

                def wifi_cap(sta=None, down=None, up=0, proto=None, thrpt_key=None, wifi_cap=False, atn=None,
                             l3_trf=False):
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
                            thrpt[thrpt_key] = \
                                self.read_kpi_file(column_name=["numeric-score"], dir_name=report_name)[0][0]
                    if l3_trf:
                        self.client_disconnect(clean_l3_traffic=True)
                        for i in sta[0:1]:
                            self.local_realm.admin_up(i)
                            time.sleep(0.3)
                        self.create_layer3(sta_list=sta[0:1], traffic_type=proto, side_a_min_rate=0,
                                           side_b_min_rate=int(down[0]), start_cx=False)
                        for i in sta[1:2]:
                            self.local_realm.admin_up(i)
                            time.sleep(0.3)
                        self.create_layer3(sta_list=sta[1:2], traffic_type=proto, side_a_min_rate=0,
                                           side_b_min_rate=int(down[1]), start_cx=False)
                        created_cx = {}
                        cx_list = [created_cx.setdefault(i, "Endpoints") for i in self.get_cx_list() if
                                   i not in created_cx]
                        self.start_cx_list(created_cx=created_cx, check_run_status=True)
                        thrpt[thrpt_key] = \
                            self.monitor(duration_sec=int(60) + 10, monitor_interval=1, created_cx=created_cx.keys(),
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
                wifi_cap(down=[(thrpt["sta0_tcp_dl"] * 0.01) * 4E7, (thrpt["sta1_tcp_dl_atn"] * 0.01) * 4E7],
                         sta=sta[0:2],
                         up="0Gbps", thrpt_key=f"{no_of_iter[5]}", l3_trf=True, atn=atn, proto="lf_udp")
                # UDP traffic for station_0 of data-rate 40% of sta0_data_rate and station_2 of data-rate 40% of sta2_data_rate
                wifi_cap(down=[(thrpt["sta0_tcp_dl"] * 0.01) * 4E7, (thrpt["sta2_tcp_dl"] * 0.01) * 4E7],
                         sta=sta[0:3:2],
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
                           upload_rate="0", duration="1m", instance_name="test_demo", raw_lines=None,
                           move_to_influx=False, create_vlan=True):
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
                    if create_vlan:
                        self.add_vlan(vlan_ids=vlan_id, build=True)
                    else:
                        self.add_vlan(vlan_ids=vlan_id, build=False)
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
        # fetch the report
        report_name = rvr_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1]
        time.sleep(10)
        logging.info("report_name: " + str(report_name))
        self.attach_report_graphs(report_name=report_name, pdf_name="Rate vs Range Test PDF Report")
        self.attach_report_kpi(report_name=report_name)

        return rvr_obj, report_name

    def dual_band_performance_test(self, ssid_5G="[BLANK]", ssid_2G="[BLANK]", mode="BRIDGE", vlan_id=100,
                                   dut_name="TIP",
                                   instance_name="test_demo", dut_5g="", dut_2g="", influx_tags="",
                                   move_to_influx=False,
                                   create_vlan=True, dut_data={}):
        try:
            instance_name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))

            if mode == "BRIDGE" or mode == "NAT-WAN":
                upstream_port = list(self.lanforge_data['wan_ports'].keys())[0]
            if mode == "VLAN":
                if vlan_id is None:
                    logging.error("VLAN ID is Unspecified in the VLAN Case")
                    pytest.skip("VLAN ID is Unspecified in the VLAN Case")
                else:
                    if create_vlan:
                        vlan_raw_lines = self.add_vlan(vlan_ids=vlan_id, build=True)
                    upstream_port = list(self.lanforge_data['wan_ports'].keys())[0] + "." + str(vlan_id[0])
            logging.info("Upstream data: " + str(upstream_port))

            self.update_dut_ssid(dut_data=dut_data)
            self.dualbandptest_obj = ApAutoTest(lf_host=self.manager_ip,
                                                lf_port=self.manager_http_port,
                                                lf_user="lanforge",
                                                lf_password="lanforge",
                                                ssh_port=self.manager_ssh_port,
                                                instance_name=instance_name,
                                                config_name="dbp_config",
                                                upstream=upstream_port,
                                                pull_report=True,
                                                dut5_0=dut_5g,
                                                dut2_0=dut_2g,
                                                load_old_cfg=False,
                                                local_lf_report_dir=self.local_report_path,
                                                max_stations_2=64,
                                                max_stations_5=64,
                                                max_stations_dual=124,
                                                radio2=[self.wave2_2g_radios],
                                                radio5=[self.wave2_5g_radios],
                                                raw_lines=[['modes', 'AUTO']],
                                                # test_tag=influx_tags,
                                                sets=[['Basic Client Connectivity', '0'],
                                                      ['Multi Band Performance', '1'],
                                                      ['Throughput vs Pkt Size', '0'], ['Capacity', '0'],
                                                      ['Skip 2.4Ghz Tests', '1'],
                                                      ['Skip 5Ghz Tests', '1'],
                                                      ['Stability', '0'],
                                                      ['Band-Steering', '0'],
                                                      ['Multi-Station Throughput vs Pkt Size', '0'],
                                                      ['Long-Term', '0']]
                                                )
            self.dualbandptest_obj.setup()
            self.dualbandptest_obj.run()
            if move_to_influx:
                report_name = "../reports/" + \
                              self.dualbandptest_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1]
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
            report_name = self.dualbandptest_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1] + "/"
            self.attach_report_graphs(report_name=report_name, pdf_name="Dual Band Performance Test")
            result = self.read_kpi_file(column_name=["pass/fail"], dir_name=report_name)
            allure.attach.file(source="../reports/" + report_name + "/kpi.csv",
                               name=f"dual_band_CSV", attachment_type="CSV")
            # if result[0][0] == "PASS":
            #     return True, "Test Passed"
            # else:
            #     return False, "Test Failed"

        except Exception as e:
            logging.error(f"{e}")
            return False, f"{e}"
        return self.dualbandptest_obj

    def multi_station_performance(self, ssid_name=None, security_key=None, mode="BRIDGE", vlan=1, band="twog",
                                  antenna=1,
                                  instance_name="", set_att_db="10db", download_rate="0Gbps", upload_rate="1Gbps",
                                  batch_size="", protocol="UDP-IPv4", duration="120000", expected_throughput=35,
                                  traffic_type="udp_upload", sniff_radio=False, create_vlan=True, dut_data=None):
        global station_name, radio_prefix, set_value, set_value1, type
        self.chamber_view()
        self.client_disconnect(clean_l3_traffic=True)
        batch_size = batch_size
        if band == "twog":
            station_name = self.twog_prefix
            radio_prefix = (self.wave2_2g_radios + self.wave1_radios + self.mtk_radios + self.ax200_radios +
                            self.be200_radios + self.ax210_radios)
        elif band == "fiveg":
            station_name = self.fiveg_prefix
            radio_prefix = (self.wave2_5g_radios + self.wave1_radios + self.mtk_radios + self.ax200_radios +
                            self.be200_radios + self.ax210_radios)
        print("station_name:", station_name)
        print("radio:", radio_prefix)

        # setting attenuator serial
        atten_sr = self.attenuator_serial()
        print(atten_sr)
        atten_sr1 = atten_sr[1].split(".")
        atten_sr2 = atten_sr[0].split(".")
        print(atten_sr1, atten_sr2)

        # creating stations
        if batch_size == "3":
            radio_name = radio_prefix[0]
            print("radio:", radio_name)
            values = radio_name.split(".")
            shelf = int(values[0])
            resource = int(values[1])
            print(shelf, resource)
            sta = []
            for i in range(3):
                sta.append(station_name + str(i))
            print(sta)
            data = {"shelf": shelf, "resource": resource, "radio": values[2], "antenna": antenna}
            self.json_post(_req_url="cli-json/set_wifi_radio", data=data)
            sta_ip = self.client_connect_using_radio(ssid=ssid_name, passkey=security_key, mode=mode, band=band,
                                                     radio=radio_name, station_name=sta, vlan_id=[vlan],
                                                     dut_data=dut_data, sniff_radio=sniff_radio)
            if not sta_ip:
                logging.info("Test Failed, due to station has no ip")
                return False, "TEST FAILED, due to station has no ip"

        elif batch_size == "3,6" or batch_size == "3,6,9":
            sta = []
            list_three_sta = []
            count = batch_size.split(',')
            n, j = 0, 0
            if len(count) == 2:
                n, j = 6, 2
            elif len(count) == 3:
                n, j = 9, 3
            print("number_of_stations:%s  & iterations : %s" % (n, j))
            for i in range(n):
                list_three_sta.append(station_name + str(i))
                if (i != 0) and (((i + 1) % 3) == 0):
                    sta.append(list_three_sta)
                    list_three_sta = []
            print(sta)
            for i in range(j):
                radio_name = radio_prefix[i]
                print(radio_name)
                print(station_name)
                values = radio_name.split(".")
                shelf = int(values[0])
                resource = int(values[1])
                print(shelf, resource)
                data = {"shelf": shelf, "resource": resource, "radio": values[2], "antenna": antenna}
                self.json_post(_req_url="cli-json/set_wifi_radio", data=data)
                time.sleep(0.5)
                sta_ip = self.client_connect_using_radio(ssid=ssid_name, passkey=security_key, mode=mode, band=band,
                                                         radio=radio_name, station_name=sta[i], vlan_id=[vlan],
                                                         dut_data=dut_data, sniff_radio=sniff_radio,
                                                         create_vlan=create_vlan)
                create_vlan = False
                if not sta_ip:
                    logging.info("Test Failed, due to station has no ip")
                    return False, "TEST FAILED, due to station has no ip"
                time.sleep(0.5)
        # attenuator setup for different db
        if set_att_db == "10db":
            for i in range(4):
                self.attenuator_modify(int(atten_sr1[2]), i, 100)
                time.sleep(0.5)
        elif set_att_db == "10db,38db" or "10db,25db":
            for i in range(4):
                self.attenuator_modify(int(atten_sr1[2]), i, 100)
                time.sleep(0.5)
            if "25db" in set_att_db:
                set_value = 250
            elif "38db" in set_att_db:
                set_value = 380
            print(set_value)
            for i in range(2):
                self.attenuator_modify(int(atten_sr2[2]), i, set_value)
                time.sleep(0.5)
        elif set_att_db == "10db,38db,48db" or "10db,25db,35db":
            for i in range(4):
                self.attenuator_modify(int(atten_sr1[2]), i, 100)
                time.sleep(0.5)
            if "25db" and "35db" in set_att_db:
                set_value = 250
                set_value1 = 350
            elif "38db" and "48db" in set_att_db:
                set_value = 380
                set_value1 = 480
            print(set_value, set_value1)
            for i in range(4):
                self.attenuator_modify(int(atten_sr2[2]), i, set_value)
                time.sleep(0.5)
                if i >= 2:
                    self.attenuator_modify(int(atten_sr2[2]), i, set_value1)
                    time.sleep(0.5)
        # wifi_capacity test
        wct_obj = self.wifi_capacity(instance_name=instance_name, mode=mode, vlan_id=[vlan],
                                     download_rate=download_rate, batch_size=batch_size,
                                     upload_rate=upload_rate, protocol=protocol, duration=duration,
                                     sort="linear", create_vlan=False)
        report_name = wct_obj[0].report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1]
        csv_val = self.read_csv_individual_station_throughput(dir_name=report_name, option=None,
                                                              individual_station_throughput=False,
                                                              kpi_csv=True,
                                                              file_name="/kpi.csv", batch_size=batch_size)
        print(csv_val)
        # considering the 70% from the expected throughput
        pass_value = (expected_throughput * 0.7)
        print("pass value ", pass_value)
        self.client_disconnect(clear_all_sta=True, clean_l3_traffic=True)
        if not csv_val:
            print("csv file does not exist, Test failed")
            allure.attach(name="Csv Data", body="csv file does not exist, Test failed")
            return False, "CSV file does not exist, Test failed"
        else:
            if traffic_type == "udp_upload":
                type = "Up"
            elif traffic_type == "udp_download":
                type = "Down"
            print("Traffic type", type)
            if list(csv_val[type].values())[-1] >= pass_value:
                allure.attach(name="Csv Data", body="Throughput value : " + str(list(csv_val[type].values())[-1]))
                logging.info("Test passed successfully")
                return True, "TEST PASSED"
            else:
                allure.attach(name="Csv Data", body="Throughput value : " + str(list(csv_val[type].values())[-1]))
                logging.info("TEST FAILED, Actual throughput is lesser than Expected.")
                return False, "TEST FAILED, Actual throughput (%sMbps) is lesser than Expected (%sMbps)" % (
                    str(list(csv_val[type].values())[-1]), str(pass_value))

    def spatial_consistency(self, ssid_name=None, security_key=None, security="wpa2", mode="BRIDGE", band="twog",
                            vlan=1, dut_data=None, num_sta=1, download_rate="100%", upload_rate="0", spatial_streams=1,
                            instance_name="", pass_value=None, attenuations=None, create_vlan=True):
        logging.info("Cleanup existing clients and traffic")
        chamber_view_obj = self.chamber_view()
        dut_name = list(dut_data.keys())[0]
        logging.info("DUT name: " + str(dut_name))
        self.client_disconnect(clean_l3_traffic=True)
        # client connect
        station = self.client_connect(ssid=ssid_name, security=security, passkey=security_key, mode=mode,
                                      band=band, num_sta=num_sta, vlan_id=[vlan], dut_data=dut_data)
        sta_name = list(station.keys())
        ser_no = self.attenuator_serial()
        print(ser_no)
        val = [['modes: Auto'], ['pkts: MTU'], ['directions: DUT Transmit'], ['traffic_types:UDP'],
               ['bandw_options: AUTO'], ['spatial_streams: ' + str(spatial_streams)],
               ['attenuator: ' + str(ser_no[0])],
               ['attenuator2: ' + str(ser_no[1])],
               ['attenuations: 100 380 480'], ['attenuations2: 100 380 480'], ['chamber: DUT-Chamber'],
               ['tt_deg: 0..+60..300']]
        if station:
            # rvr test
            rvr_o, report_name = self.rate_vs_range_test(station_name=sta_name[0], mode=mode,
                                                         download_rate=download_rate,
                                                         upload_rate=upload_rate, instance_name=instance_name,
                                                         duration="60000",
                                                         vlan_id=[vlan], dut_name=dut_name, raw_lines=val,
                                                         create_vlan=create_vlan)
            entries = os.listdir("../reports/" + report_name + '/')
            print("entries", entries)
            self.client_disconnect(clear_all_sta=True, clean_l3_traffic=True)
            logging.info("Test Completed... Cleaning up Stations")
            kpi = "kpi.csv"
            pass_value = pass_value
            atn, deg = attenuations, [0, 60, 120, 180, 240, 300]
            if kpi in entries:
                kpi_val = self.read_kpi_file(column_name=["numeric-score"], dir_name=report_name)
                print("kpi_calue :", kpi_val)
                if str(kpi_val) == "empty":
                    logging.info("TEST FAILED, Throughput value from kpi.csv is empty.")
                    allure.attach(name="CSV Data", body="TEST FAILED, Throughput value from kpi.csv is empty.")
                    return False, "TEST FAILED, Throughput value from kpi.csv is empty."
                else:
                    allure.attach(name="CSV Data", body="Throughput value : " + str(kpi_val))
                    start, thrpt_val, pass_fail = 0, {}, []
                    for i in pass_value:
                        count = 0
                        for j in range(start, len(kpi_val), len(atn)):
                            thrpt_val[f"{atn[start]}atn-{deg[count]}deg"] = kpi_val[j][0]
                            if kpi_val[j][0] >= pass_value[i]:
                                pass_fail.append("PASS")
                            else:
                                pass_fail.append("FAIL")
                            count += 1
                        # start += 6
                    print(thrpt_val, "\n", pass_fail)
                    if "FAIL" in pass_fail:
                        logging.info("TEST FAILED, Actual throughput is lesser than Expected.")
                        return False, "TEST FAILED, Actual throughput  is lesser than Expected."
                    else:
                        logging.info("Test passed successfully")
                        return True, "TEST PASSED"
            else:
                logging.info("csv file does not exist, TEST FAILED.")
                allure.attach(name="CSV Data", body="csv file does not exist")
                return False, "TEST FAILED, , CSV file does not exist"
        else:
            logging.info("Test Failed, due to station has no ip")
            return False, "TEST FAILED, due to station has no ip"

    def rate_vs_range(self, ssid_name=None, security_key=None, security="wpa2", mode="BRIDGE", band="twog", vlan=1,
                      dut_data=None, num_sta=1, spatial_streams=2, direction="DUT Transmit", instance_name="",
                      pass_value=None, attenuations=None, create_vlan=True):
        logging.info("Cleanup existing clients and traffic")
        chamber_view_obj = self.chamber_view()
        dut_name = list(dut_data.keys())[0]
        logging.info("DUT name: " + str(dut_name))
        self.client_disconnect(clean_l3_traffic=True)
        # client connect
        station = self.client_connect(ssid=ssid_name, security=security, passkey=security_key, mode=mode, band=band,
                                      num_sta=num_sta, vlan_id=[vlan], dut_data=dut_data)
        sta_name = list(station.keys())
        ser_no = self.attenuator_serial()
        print("ser no", ser_no)
        atn2 = ser_no[1].split(".")[2]
        print(f"antenuation-2 : {atn2}")
        val = [['modes: Auto'], ['pkts: MTU'], ['directions: ' + str(direction)], ['traffic_types:TCP'],
               ['bandw_options: AUTO'], ['spatial_streams: 2'], ['attenuator: ' + str(ser_no[0])],
               ['attenuator2: 0'], ['attenuations: 0 60 120 180 240 300 360 390 410 430 450 470 490'],
               ['attenuations2: 0 60 120 180 240 300 360 390 410 430 450 470 490'],
               ['chamber: 0'], ['tt_deg: 0']]
        if station:
            # rvr test
            rvr_o, report_name = self.rate_vs_range_test(station_name=sta_name[0], mode=mode, download_rate="100%",
                                                         duration='30000', instance_name=instance_name, vlan_id=[vlan],
                                                         dut_name=dut_name, raw_lines=val, create_vlan=create_vlan)
            entries = os.listdir("../reports/" + report_name + '/')
            print("entries", entries)
            print("Test Completed... Cleaning up Stations")
            self.client_disconnect(clear_all_sta=True, clean_l3_traffic=True)
            kpi = "kpi.csv"
            pass_value = pass_value
            atn = attenuations
            if kpi in entries:
                kpi_val = self.read_kpi_file(column_name=["numeric-score"], dir_name=report_name)
                print(kpi_val)
                if str(kpi_val) == "empty":
                    logging.info("Throughput value from kpi.csv is empty, TEST FAILED, ")
                    allure.attach(name="CSV Data", body="Throughput value from kpi.csv is empty, TEST FAILED, ")
                    return False, "Throughput value from kpi.csv is empty, TEST FAILED, "
                else:
                    allure.attach(name="CSV Data", body="Throughput value : " + str(kpi_val))
                    start, thrpt_val, pass_fail = 0, {}, []
                    for i in pass_value:
                        # count = 0
                        # direction = "DUT-TX"
                        for j in range(start, len(kpi_val), len(atn)):
                            thrpt_val[f"{atn[start]}"] = kpi_val[j][0]
                            if kpi_val[j][0] >= pass_value[i]:
                                pass_fail.append("PASS")
                                break
                            else:
                                pass_fail.append("FAIL")
                                break
                            # count += 1
                            # direction = "DUT-RX"
                        start += 6
                    print(pass_fail, "\nThroughput value-->", thrpt_val)
                    allure.attach(name="Throughput value", body=str(thrpt_val))
                    if "FAIL" in pass_fail:
                        logging.info("TEST FAILED, Actual throughput is lesser than Expected")
                        return False, "TEST FAILED, Actual throughput is lesser than Expected"
                    else:
                        logging.info("TEST PASSED successfully")
                        return True, "TEST PASSED"
            else:
                logging.info("csv file does not exist, TEST FAILED.")
                allure.attach(name="CSV Data", body="csv file does not exist")
                return False, "TEST FAILED, CSV file does not exist"
        else:
            logging.info("Test Failed, due to station has no ip")
            return False, "TEST FAILED, due to station has no ip"

    def client_isolation(self, ssid1=None, ssid2=None, passkey=None, security=None, mode="BRIDGE", band_2g=False,
                         band_5g=False, dut_data=None, num_sta=None, side_a_min_rate=None, side_a_max_rate=None,
                         side_b_min_rate=None, side_b_max_rate=None, sniff_radio=True):
        copy_num_sta = num_sta

        # selecting radio(s) based on the requested bands of the client(s)
        dict_all_radios_2g = {"wave2_2g_radios": self.wave2_2g_radios, "wave1_radios": self.wave1_radios,
                              "mtk_radios": self.mtk_radios, "ax200_radios": self.ax200_radios,
                              "be200_radios": self.be200_radios,
                              "ax210_radios": self.ax210_radios}
        dict_all_radios_5g = {"wave2_5g_radios": self.wave2_5g_radios, "wave1_radios": self.wave1_radios,
                              "mtk_radios": self.mtk_radios, "ax200_radios": self.ax200_radios,
                              "be200_radios": self.be200_radios,
                              "ax210_radios": self.ax210_radios}
        max_station_per_radio = {"wave2_2g_radios": 64, "wave2_5g_radios": 64, "wave1_radios": 64, "mtk_radios": 19,
                                 "ax200_radios": 1, "ax210_radios": 1, "be200_radios": 1}
        radio_name_2g = []
        radio_name_5g = []
        if band_2g is True and band_5g is True:  # a 2G and a 5G station
            for type_of_radio in dict_all_radios_2g:
                if len(dict_all_radios_2g[type_of_radio]) > 0:
                    radio_name_2g.append(dict_all_radios_2g[type_of_radio][0])
                    max_station_per_radio[type_of_radio] -= 1
                    break
            for type_of_radio in dict_all_radios_5g:
                if len(dict_all_radios_5g[type_of_radio]) > 0 and max_station_per_radio[type_of_radio] > 0:
                    radio_name_5g.append(dict_all_radios_5g[type_of_radio][0])
                    break

            if len(radio_name_2g) == 0 or len(radio_name_5g) == 0:
                logging.info("Looks like the langforge radios can't support creating a 2G and a 5G station, "
                             "simultaneously.")
                pytest.skip("Looks like the langforge radios can't support creating a 2G and a 5G station, "
                            "simultaneously.")

            station_name_2g = "sta_2g"
            station_name_5g = "sta_5g"

            band = ["twog", "fiveg"]
        elif band_2g is True:  # only 2g bands but num_sta can be 1 or 2
            if self.max_2g_stations < num_sta:
                logging.info(f"Looks like the langforge radios can't support creating {num_sta} 2G stations.")
                raise ValueError(f"Looks like the langforge radios can't support creating {num_sta} 2G stations.")
            band = "twog"
            enough_radios = False
            for type_of_radio in dict_all_radios_2g:
                if len(dict_all_radios_2g[type_of_radio]) > 0:
                    for i in range(len(dict_all_radios_2g[type_of_radio])):
                        radio_name_2g.append(dict_all_radios_2g[type_of_radio][i])
                        if num_sta <= max_station_per_radio[type_of_radio]:
                            num_sta = 0
                            enough_radios = True
                            break
                        else:
                            num_sta -= max_station_per_radio[type_of_radio]
                    if enough_radios:
                        break
            station_name = "sta_2g"
        elif band_5g is True:  # only 5g bands but num_sta can be 1 or 2
            if self.max_5g_stations < num_sta:
                logging.info(f"Looks like the langforge radios can't support creating {num_sta} 5G stations.")
                raise ValueError(f"Looks like the langforge radios can't support creating {num_sta} 5G stations.")
            band = "fiveg"
            enough_radios = False
            for type_of_radio in dict_all_radios_5g:
                if len(dict_all_radios_5g[type_of_radio]) > 0:
                    for i in range(len(dict_all_radios_5g[type_of_radio])):
                        radio_name_5g.append(dict_all_radios_5g[type_of_radio][i])
                        if num_sta <= max_station_per_radio[type_of_radio]:
                            num_sta = 0
                            enough_radios = True
                            break
                        else:
                            num_sta -= max_station_per_radio[type_of_radio]
                    if enough_radios:
                        break
            station_name = "sta_5g"

        logging.info("Clearing any existing stations and Layer-3 traffics before starting the test...")
        self.pre_cleanup()  # clear any existing stations and traffic

        sta = []
        num_sta = copy_num_sta
        sta_got_ip = []
        if num_sta > 1:  # between 2 stations
            if band_2g is True and band_5g is True:  # a 2G and a 5G station
                sta_got_ip.append(self.client_connect_using_radio(ssid=ssid1, passkey=passkey, security=security,
                                                                  mode=mode, band="twog", radio=radio_name_2g[0],
                                                                  station_name=[station_name_2g], dut_data=dut_data,
                                                                  sniff_radio=sniff_radio, attach_port_info=False,
                                                                  attach_station_data=False))
                sta_got_ip.append(self.client_connect_using_radio(ssid=ssid2, passkey=passkey, security=security,
                                                                  mode=mode, band="fiveg", radio=radio_name_5g[0],
                                                                  station_name=[station_name_5g], dut_data=dut_data,
                                                                  sniff_radio=sniff_radio, attach_port_info=False,
                                                                  attach_station_data=False))

                self.create_layer3(side_a_min_rate=side_a_min_rate, side_a_max_rate=side_a_max_rate,
                                   side_b_min_rate=side_b_min_rate, side_b_max_rate=side_b_max_rate,
                                   traffic_type="lf_udp", sta_list=[station_name_2g], side_b=station_name_5g)
            else:  # else both are either 2G or 5G stations
                ssids = [ssid1, ssid2]
                radio_name = radio_name_2g + radio_name_5g
                if len(radio_name) == 1:
                    radio_name.append(radio_name[0])
                for i in range(2):
                    sta.append(station_name + "_" + str(i + 1))
                    sta_got_ip.append(self.client_connect_using_radio(ssid=ssids[i], passkey=passkey, band=band,
                                                                      security=security, mode=mode, radio=radio_name[i],
                                                                      station_name=[sta[i]], dut_data=dut_data,
                                                                      sniff_radio=sniff_radio, attach_port_info=False,
                                                                      attach_station_data=False))
                self.create_layer3(side_a_min_rate=side_a_min_rate, side_a_max_rate=side_a_max_rate,
                                   side_b_min_rate=side_b_min_rate, side_b_max_rate=side_b_max_rate,
                                   traffic_type="lf_udp", sta_list=[sta[0]], side_b=sta[1])
        elif num_sta == 1:  # else between a 2G/5G station and uplink port
            radio_name = radio_name_2g if band_2g is True else radio_name_5g
            sta_got_ip.append(self.client_connect_using_radio(ssid=ssid1, passkey=passkey, band=band, security=security,
                                                              mode=mode, radio=radio_name[0],
                                                              station_name=[station_name],
                                                              dut_data=dut_data, sniff_radio=sniff_radio,
                                                              attach_port_info=False, attach_station_data=False))
            self.create_layer3(side_a_min_rate=side_a_min_rate, side_a_max_rate=side_a_max_rate,
                               side_b_min_rate=side_b_min_rate, side_b_max_rate=side_b_max_rate,
                               traffic_type="lf_udp", sta_list=[station_name], side_b="")

        if False in sta_got_ip:
            self.pre_cleanup()
            logging.info("TEST FAILED, due to station has no ip")
            return False, "TEST FAILED, due to station has no ip"

        logging.info("Running Traffic for 60 seconds...")
        time.sleep(60)

        logging.info("Getting Layer-3 and Endpoints Data...")
        cx_list = self.get_cx_list()
        rx_data = self.json_get(_req_url=f"cx/{cx_list[0]}")

        rx_drop_a = rx_data[cx_list[0]]["rx drop % a"]
        rx_drop_b = rx_data[cx_list[0]]["rx drop % b"]

        sta = []
        for u in self.json_get("/port/?fields=port+type,alias,ssid")['interfaces']:
            if (list(u.values())[0]['port type'] in ['WIFI-STA']
                    and list(u.values())[0]['ssid'] in [ssid1, ssid2]):
                sta.append(list(u.keys())[0])

        if len(sta) == 1:
            sta.append(list(self.get_wan_upstream_ports().values())[0])

        sta_rows = ["ssid", "ip", "mode", "channel", "signal", "mac", "parent dev"]
        sta_dict = self.get_station_data(sta_name=sta, rows=sta_rows, allure_attach=False)
        station_table_dict = {"station name": list(sta_dict.keys()),
                              "Min/Max Tx rate": [f"{side_a_min_rate} bytes", f"{side_b_min_rate} bytes"],
                              "rx drop %": [rx_drop_a, rx_drop_b]}
        for col in sta_rows:
            temp_list = []
            for port in sta:
                temp_list.append(sta_dict[port][col])
            station_table_dict[col] = temp_list

        logging.info("Attaching to the allure report...")
        self.attach_table_allure(data=station_table_dict, allure_name="Endpoints Data")
        self.allure_report_table_format(dict_data=rx_data[cx_list[0]], key="Layer-3 Column", value="Value",
                                        name="Layer-3 Data")

        logging.info("Traffic ran, Clearing stations and Layer-3 traffic...")
        self.pre_cleanup()

        return True, {"drop_a": rx_drop_a, "drop_b": rx_drop_b}

    def ax_capacity_test(self, instance_name="", dut_data=None, mode="BRIDGE", download_rate="10Gbps",
                         upload_rate="0Gbps", dut_mode="", protocol="UDP-IPv4", num_stations={}, vlan_id=None):
        if self.max_ax_stations == 0:
            logging.info("This test needs AX radios, looks like no AX radios are available on the Lanforge system.")
            pytest.skip("AX radios are not available on the Lanforge, so skipping this test.")

        if dut_mode.lower() == "wifi5":
            logging.info("AP does not support AX mode, so skipping this test.")
            pytest.skip("AP does not support AX mode, so skipping this test")

        dict_all_radios_ax = {"mtk_radios": self.mtk_radios,
                              "ax200_radios": self.ax200_radios,
                              "be200_radios": self.be200_radios,
                              "ax210_radios": self.ax210_radios}
        selected_ax_radio = None
        for radio in dict_all_radios_ax:
            if len(dict_all_radios_ax[radio]) > 0:
                selected_ax_radio = dict_all_radios_ax[radio][0]
                break
        logging.info("Selected AX Radio: {}".format(selected_ax_radio))

        for data in self.dut_data:
            identifier = data["identifier"]
        ssid_name = dut_data[identifier]["ssid_data"][0]["ssid"]
        passkey = dut_data[identifier]["ssid_data"][0]["password"]
        band = list(num_stations.keys())[0]

        try:
            self.set_radio_channel(radio=selected_ax_radio, antenna="AUTO")
            values = selected_ax_radio.split(".")
            shelf = int(values[0])
            resource = int(values[1])
            self.pre_cleanup()
            sta_name = [f"{shelf}.{resource}.ax_station"]
            logging.info("sta_name:- " + str(sta_name))
            sta_ip = self.client_connect_using_radio(ssid=ssid_name, passkey=passkey, mode=mode, station_name=sta_name,
                                            radio=selected_ax_radio, vlan_id=vlan_id, create_vlan=True)
            time.sleep(0.5)

            sta_rows = ["ip", "mode", "channel", "signal", "parent dev", "mac"]
            station_data = self.get_station_data(sta_name=sta_name, rows=sta_rows, allure_attach=True,
                                                 allure_name="Station Data")
            logging.info("station_data:- " + str(station_data))
            if not sta_ip:
                logging.info("Test Failed, due to station has no ip")
                pytest.fail("Station did not get an ip")

            sta_mode = station_data[sta_name[0]]["mode"]
            logging.info("sta_mode:- " + str(sta_mode))
            wifi_capacity_obj_list = self.wifi_capacity(instance_name=instance_name, mode=mode,
                                                        download_rate=download_rate, upload_rate=upload_rate,
                                                        protocol=protocol, duration="60000", ssid_name=ssid_name,
                                                        batch_size="1", num_stations=num_stations, stations=sta_name[0],
                                                        dut_data=dut_data, vlan_id=vlan_id, add_stations=False,
                                                        create_vlan=False)

            report = wifi_capacity_obj_list[0].report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1] + "/"
            numeric_score = self.read_kpi_file(column_name=["numeric-score"], dir_name=report)
            current_directory = os.getcwd()
            file_path = current_directory + "/e2e/basic/performance_tests/performance_pass_fail.json"
            logging.info("performance_pass file config path:- " + str(file_path))
            with open(file_path, 'r') as file:
                json_string = file.read()
                all_pass_fail_data = json.loads(json_string)
            logging.info("All Testbed pass fail data:- " + str(all_pass_fail_data))
            # validate config json data
            try:
                json_object = json.dumps(all_pass_fail_data)
            except ValueError as e:
                logging.info("Performance Pass/Fail data is invalid")
                pytest.fail("Performance Pass/Fail data is invalid")
            logging.info("DUT Data: " + str(self.dut_data))
            model = self.dut_data[0]["model"]
            if model in all_pass_fail_data["AP Models"]:
                pass_fail_values = all_pass_fail_data["AP Models"][model]
            else:
                logging.error("AP model is not available in performance_pass_fail.json file")
            logging.info(str(model) + " All Benchmark throughput:- " + str(pass_fail_values))
            split_mode = sta_mode.split(" ")
            key = f"{band} {split_mode[2]} {split_mode[1]}MHz"
            logging.info("key:- " + str(key))
            proto = None
            if "TCP" in protocol:
                proto = "TCP"
            else:
                proto = "UDP"
            logging.info("Proto:- " + str(proto))
            logging.info("Given LF download_rate:- " + str(download_rate))
            logging.info("Given LF upload_rate:- " + str(upload_rate))
            pass_fail_value = pass_fail_values[key][proto]
            logging.info("pass_fail value:- " + str(pass_fail_value))
            download_rate = self.convert_to_gbps(download_rate)
            logging.info("download_rate:- " + str(download_rate))
            upload_rate = self.convert_to_gbps(upload_rate)
            logging.info("upload_rate:- " + str(upload_rate))
            # Pass fail logic for Upload. validating download rate because providing some value during Upload
            if upload_rate > download_rate:
                logging.info("Benchmark throughput:- " + str(pass_fail_value) + "+")
                allure.attach(name="Benchmark throughput: ",
                              body=str(pass_fail_value) + "+ Mbps")
                actual_tht = int(numeric_score[1][0])
                logging.info("Actual throughput:- " + str(actual_tht))
                allure.attach(name="Actual throughput: ",
                              body=str(actual_tht) + " Mbps")
                if actual_tht < pass_fail_value:
                    pytest.fail(
                        f"Benchmark throughput:- {pass_fail_value}+ Mbps, Actual throughput:- {actual_tht} Mbps")
            elif upload_rate < download_rate:
                # Pass fail logic for Download. validating upload rate because providing some value during download
                logging.info("Benchmark throughput:- " + str(pass_fail_value) + "+")
                allure.attach(name="Benchmark throughput: ",
                              body=str(pass_fail_value) + "+ Mbps")
                actual_tht = int(numeric_score[0][0])
                logging.info("Actual throughput:- " + str(actual_tht))
                allure.attach(name="Actual throughput: ",
                              body=str(actual_tht) + " Mbps")
                if actual_tht < pass_fail_value:
                    pytest.fail(
                        f"Benchmark throughput:- {pass_fail_value}+ Mbps, Actual throughput:- {actual_tht} Mbps")
            elif upload_rate == download_rate:
                # Pass fail logic for bidirectional
                pass_fail_value = pass_fail_value * 2
                logging.info("Benchmark throughput:- " + str(pass_fail_value) + "+")
                allure.attach(name="Benchmark throughput: ",
                              body=str(pass_fail_value) + "+ Mbps")
                actual_tht = int(numeric_score[2][0])
                logging.info("Actual throughput:- " + str(actual_tht))
                allure.attach(name="Actual throughput: ",
                              body=str(actual_tht) + " Mbps")
                if actual_tht < pass_fail_value:
                    pytest.fail(
                        f"Benchmark throughput:- {pass_fail_value}+ Mbps, Actual throughput:- {actual_tht} Mbps")

        finally:
            self.set_radio_channel(radio=selected_ax_radio, antenna="0")

    def multi_ssid_test(self, setup_params_general: dict, no_of_2g_and_5g_stations: int = 2, mode: str = "BRIDGE",
                        security_key: str = "something", security: str = "wpa2") -> None:
        sta_names_2g, sta_names_5g = [], []
        for i in range(no_of_2g_and_5g_stations):
            sta_names_2g.append(f"sta_2g_{i + 1}")
            sta_names_5g.append(f"sta_5g_{i + 1}")

        cx_sta_list = [sta_names_2g[-2], sta_names_2g[-1], sta_names_5g[-2], sta_names_5g[-1]]

        radio_dict_2g, radio_dict_5g = self.get_radio_availabilities(num_stations_2g=len(sta_names_2g),
                                                                     num_stations_5g=len(sta_names_5g))
        logging.info(f"Radio-2G-Stations dict : {radio_dict_2g}")
        logging.info(f"Radio-5G-Stations dict : {radio_dict_5g}")

        security_mode = 'wpa2_personal'
        for security_mode_ in setup_params_general["ssid_modes"]:
            security_mode = security_mode_

        sta_got_ip = []
        allure.attach(name="ssid info", body=str(setup_params_general["ssid_modes"][security_mode]))

        self.pre_cleanup()
        no_of_ssids = len(setup_params_general["ssid_modes"][security_mode])
        logging.info(f"A total of {no_of_2g_and_5g_stations} 2G and {no_of_2g_and_5g_stations} 5G stations will be "
                     f"created for {no_of_ssids} SSIDs, i.e., a 2G and a 5G stations on each SSID.")

        for i in range(no_of_2g_and_5g_stations):
            ssid_name = setup_params_general["ssid_modes"][security_mode][i % no_of_ssids]["ssid_name"]
            logging.info(f"Creating a 2G station on {ssid_name} ssid...")
            radio = None
            for _radio in radio_dict_2g:
                radio = _radio
                if radio_dict_2g[radio] == 1:
                    del radio_dict_2g[radio]
                else:
                    radio_dict_2g[radio] -= 1
                break
            sta_got_ip.append(self.client_connect_using_radio(ssid=ssid_name, security=security,
                                                              passkey=security_key, mode=mode,
                                                              radio=radio,
                                                              station_name=[sta_names_2g[i]],
                                                              attach_station_data=False,
                                                              attach_port_info=False))
            logging.info(f"Creating a 5G station on {ssid_name} ssid...")
            for _radio in radio_dict_5g:
                radio = _radio
                if radio_dict_5g[radio] == 1:
                    del radio_dict_5g[radio]
                else:
                    radio_dict_5g[radio] -= 1
                break
            sta_got_ip.append(self.client_connect_using_radio(ssid=ssid_name, security=security,
                                                              passkey=security_key, mode=mode,
                                                              radio=radio,
                                                              station_name=[sta_names_5g[i]],
                                                              attach_station_data=False,
                                                              attach_port_info=False))

        port_data = self.json_get(_req_url="port?fields=ip")
        port_info = {key: value for d in port_data["interfaces"] for key, value in d.items()}
        self.allure_report_table_format(dict_data=port_info, key="Port Names", value="ip",
                                        name="Port info after creating all stations")

        dict_table_2g_1st = {}
        dict_table_2g_2nd = {}
        dict_table_5g_1st = {}
        dict_table_5g_2nd = {}
        for sta in sta_names_2g + sta_names_5g:
            result = self.json_get(_req_url="port/1/1/%s" % sta)
            if "Key" not in dict_table_2g_1st:
                dict_table_2g_1st["Key"] = list(result["interface"].keys())
                dict_table_2g_2nd["Key"] = list(result["interface"].keys())
                dict_table_5g_1st["Key"] = list(result["interface"].keys())
                dict_table_5g_2nd["Key"] = list(result["interface"].keys())
            if '_2g_' in sta:
                if len(dict_table_2g_1st) < 5:
                    dict_table_2g_1st[f"Value ({sta})"] = list(result["interface"].values())
                else:
                    dict_table_2g_2nd[f"Value ({sta})"] = list(result["interface"].values())
            else:
                if len(dict_table_5g_1st) < 5:
                    dict_table_5g_1st[f"Value ({sta})"] = list(result["interface"].values())
                else:
                    dict_table_5g_2nd[f"Value ({sta})"] = list(result["interface"].values())

        data_table_2g_1st = tabulate(dict_table_2g_1st, headers='keys', tablefmt='fancy_grid')
        data_table_2g_2nd = tabulate(dict_table_2g_2nd, headers='keys', tablefmt='fancy_grid')
        data_table_5g_1st = tabulate(dict_table_5g_1st, headers='keys', tablefmt='fancy_grid')
        data_table_5g_2nd = tabulate(dict_table_5g_2nd, headers='keys', tablefmt='fancy_grid')

        logging.info(f"2G Stations Data (1-{min(4, no_of_2g_and_5g_stations)}): \n{data_table_2g_1st}\n")
        allure.attach(name=f"2G Stations Data (1-{min(4, no_of_2g_and_5g_stations)})", body=str(data_table_2g_1st))
        if no_of_2g_and_5g_stations > 4:
            logging.info(f"2G Stations Data (5-{no_of_2g_and_5g_stations}): \n{data_table_2g_2nd}\n")
            allure.attach(name=f"2G Stations Data (5-{no_of_2g_and_5g_stations})", body=str(data_table_2g_2nd))

        logging.info(f"5G Stations Data (1-{min(4, no_of_2g_and_5g_stations)}): \n{data_table_5g_1st}\n")
        allure.attach(name=f"5G Stations Data (1-{min(4, no_of_2g_and_5g_stations)})", body=str(data_table_5g_1st))
        if no_of_2g_and_5g_stations > 4:
            logging.info(f"5G Stations Data (5-{no_of_2g_and_5g_stations}): \n{data_table_5g_2nd}\n")
            allure.attach(name=f"5G Stations Data (5-{no_of_2g_and_5g_stations})", body=str(data_table_5g_2nd))

        if False in sta_got_ip:
            logging.info("Some/All Stations didn't get IP address")
            pytest.fail("Some/All Stations didn't get IP address")
        logging.info("All 2G/5G Stations got IP address")

        # create Layer 3 and check data path
        for i in range(3):
            self.create_layer3(side_a_min_rate=6291456, side_a_max_rate=0,
                               side_b_min_rate=6291456, side_b_max_rate=0,
                               traffic_type="lf_tcp", sta_list=[cx_sta_list[i]],
                               side_b=cx_sta_list[i + 1], start_cx=True,
                               prefix=f"{cx_sta_list[i][4:]}-{cx_sta_list[i + 1][4:]}:t")
            logging.info(f"CX with TCP traffic created between "
                         f"endpoint-a = {cx_sta_list[i]} and endpoint-b = {cx_sta_list[i + 1]}.")
            time.sleep(2)
            self.create_layer3(side_a_min_rate=6291456, side_a_max_rate=0,
                               side_b_min_rate=6291456, side_b_max_rate=0,
                               traffic_type="lf_udp", sta_list=[cx_sta_list[i]],
                               side_b=cx_sta_list[i + 1], start_cx=True,
                               prefix=f"{cx_sta_list[i][4:]}-{cx_sta_list[i + 1][4:]}:u")
            logging.info(f"CX with UDP traffic created between "
                         f"endpoint-a = {cx_sta_list[i]} and endpoint-b = {cx_sta_list[i + 1]}.")
            time.sleep(2)

        logging.info("Running Layer3 traffic for 40 sec ...")
        time.sleep(40)

        cx_list = self.get_cx_list()
        dict_table_cx_tcp = {}
        dict_table_cx_udp = {}
        pass_fail_data = []
        for i in range(len(cx_list)):
            cx_data = self.json_get(_req_url=f"cx/{cx_list[i]}")
            cx_name = f"sta_{cx_list[i].split(':')[0].split('-')[0]} <==> sta_{cx_list[i].split(':')[0].split('-')[1]}"

            if "L3 CX Column" not in dict_table_cx_tcp:
                dict_table_cx_tcp["L3 CX Column"] = list(cx_data[f"{cx_list[i]}"].keys())
                dict_table_cx_udp["L3 CX Column"] = list(cx_data[f"{cx_list[i]}"].keys())
            if "TCP" in cx_data[f"{cx_list[i]}"]['type']:
                dict_table_cx_tcp[f"values ({cx_name})"] = list(cx_data[f"{cx_list[i]}"].values())
            else:
                dict_table_cx_udp[f"values ({cx_name})"] = list(cx_data[f"{cx_list[i]}"].values())

            if cx_data[cx_list[i]]['bps rx a'] != 0 and cx_data[cx_list[i]]['bps rx a'] != 0:
                res = True
            else:
                res = False
            pass_fail_data.append(
                [f"{cx_list[i]}", f"{cx_data[cx_list[i]]['bps rx a']}", f"{cx_data[cx_list[i]]['bps rx b']}", res])

        # attach l3 cx data to allure
        data_table_cx_tcp = tabulate(dict_table_cx_tcp, headers='keys', tablefmt='fancy_grid')
        data_table_cx_udp = tabulate(dict_table_cx_udp, headers='keys', tablefmt='fancy_grid')
        logging.info(f"L3 cross-connects Data (TCP): \n{data_table_cx_tcp}\n")
        logging.info(f"L3 cross-connects Data (UDP): \n{data_table_cx_udp}\n")
        allure.attach(name="L3 cross-connects Data (TCP)", body=str(data_table_cx_tcp))
        allure.attach(name="L3 cross-connects Data (UDP)", body=str(data_table_cx_udp))

        # attach pass fail data to allure
        result_table = tabulate(pass_fail_data,
                                headers=["Data Path", "Tx Rate (bps)", "Rx Rate (bps)", "Pass/Fail"],
                                tablefmt='fancy_grid')
        logging.info(f"Test Result Table: \n{result_table}\n")
        allure.attach(name="Test Result Table", body=str(result_table))

        # cleanup Layer3 data
        self.client_disconnect(station_name=sta_names_2g + sta_names_5g, clean_l3_traffic=True, clear_all_sta=True)

        test_result = True
        for pf in pass_fail_data:
            if pf[3] is False:
                test_result = False

        if not test_result:
            pytest.fail("DataPath check failed, Traffic didn't reported on some endpoints")

    def max_ssid(self, setup_params_general: dict, mode: str = 'BRIDGE', vlan_id: list = None) -> None:
        self.pre_cleanup()

        ssid_2g_list = []
        ssid_5g_list = []
        for security, ssids in setup_params_general["ssid_modes"].items():
            for ssid in ssids:
                ssid_dict = {
                    'ssid_name': ssid["ssid_name"],
                    'security': security.split("_")[0],
                    'password': ssid.get("security_key", "[BLANK]"),
                }
                if "2G" in ssid["appliedRadios"]:
                    ssid_2g_list.append(ssid_dict)
                elif "5G" in ssid["appliedRadios"]:
                    ssid_5g_list.append(ssid_dict)

        no_of_sta_2g = len(ssid_2g_list)
        no_of_sta_5g = len(ssid_5g_list)
        sta_names_2g = [f"sta_2g_{i + 1}" for i in range(no_of_sta_2g)]
        sta_names_5g = [f"sta_5g_{i + 1}" for i in range(no_of_sta_5g)]

        radio_dict_2g, radio_dict_5g = self.get_radio_availabilities(num_stations_2g=no_of_sta_2g,
                                                                     num_stations_5g=no_of_sta_5g)
        if len(radio_dict_2g) > 0:
            logging.info(f"Radio-Stations dict : {radio_dict_2g}")
        if len(radio_dict_5g) > 0:
            logging.info(f"Radio-Stations dict : {radio_dict_5g}")

        if no_of_sta_2g > 0:
            logging.info(f"A total of {no_of_sta_2g} 2G stations will be created for {no_of_sta_2g} SSIDs, "
                         f"i.e., one 2G stations on each SSID.")
        if no_of_sta_5g > 0:
            logging.info(f"A total of {no_of_sta_5g} 5G stations will be created for {no_of_sta_5g} SSIDs, "
                         f"i.e., one 5G stations on each SSID.")

        upstream_port = ""
        if mode == 'VLAN':
            self.add_vlan(vlan_ids=vlan_id, build=True)
            up = self.get_wan_upstream_ports()
            upstream = list(up.values())
            upstream_port = upstream[0] + "." + str(vlan_id[0])

        radio = None
        timeout_sec = 1
        for i in range(no_of_sta_2g):
            logging.info(f"Creating a 2G station on {ssid_2g_list[i]['ssid_name']} ssid...")
            for _radio in radio_dict_2g:
                radio = _radio
                if radio_dict_2g[radio] == 1:
                    del radio_dict_2g[radio]
                else:
                    radio_dict_2g[radio] -= 1
                break
            self.client_connect_using_radio(ssid=ssid_2g_list[i]['ssid_name'],
                                            security=ssid_2g_list[i]['security'],
                                            passkey=ssid_2g_list[i]['password'],
                                            mode=mode,
                                            radio=radio,
                                            station_name=[sta_names_2g[i]],
                                            attach_station_data=False,
                                            attach_port_info=False,
                                            timeout_sec=timeout_sec,
                                            vlan_id=vlan_id,
                                            create_vlan=False)
        for i in range(no_of_sta_5g):
            logging.info(f"Creating a 5G station on {ssid_5g_list[i]['ssid_name']} ssid...")
            for _radio in radio_dict_5g:
                radio = _radio
                if radio_dict_5g[radio] == 1:
                    del radio_dict_5g[radio]
                else:
                    radio_dict_5g[radio] -= 1
                break
            self.client_connect_using_radio(ssid=ssid_5g_list[i]['ssid_name'],
                                            security=ssid_5g_list[i]['security'],
                                            passkey=ssid_5g_list[i]['password'],
                                            mode=mode,
                                            radio=radio,
                                            station_name=[sta_names_5g[i]],
                                            attach_station_data=False,
                                            attach_port_info=False,
                                            timeout_sec=timeout_sec,
                                            vlan_id=vlan_id,
                                            create_vlan=False)

        logging.info("Sleeping 60 seconds to let stations get IP address...")
        time.sleep(60)

        logging.info("Fetching port info after all stations created")
        port_data = self.json_get(_req_url="port?fields=ip")
        port_info = {key: value for d in port_data["interfaces"] for key, value in d.items()}
        self.allure_report_table_format(dict_data=port_info, key="Port Names", value="ip",
                                        name="Port info after creating all stations")

        logging.info("Adding Station Data to the report")
        dict_table_sta = {}
        start_sta, end_sta = 1, 0
        failed = False
        for index, sta in enumerate(sta_names_2g):
            end_sta += 1
            result = self.json_get(_req_url="port/1/1/%s" % sta)
            if ((no_of_sta_2g <= 8 and result['interface']['ip'] == '0.0.0.0')
                    or (no_of_sta_2g > 8 and result['interface']['ip'] != '0.0.0.0')):
                failed = True
            if "Key" not in dict_table_sta:
                dict_table_sta["Key"] = list(result["interface"].keys())
            dict_table_sta[f"Value ({sta})"] = list(result["interface"].values())

            if end_sta - start_sta == 3 or index == len(sta_names_2g) - 1:
                data_table_sta = tabulate(dict_table_sta, headers='keys', tablefmt='fancy_grid')
                logging.info(f"2G-Stations Data ({start_sta}-{end_sta}): \n{data_table_sta}\n")
                allure.attach(name=f"2G-Stations Data ({start_sta}-{end_sta})", body=str(data_table_sta))
                start_sta = end_sta + 1
                dict_table_sta.clear()

        start_sta, end_sta = 1, 0
        for index, sta in enumerate(sta_names_5g):
            end_sta += 1
            result = self.json_get(_req_url="port/1/1/%s" % sta)
            if ((no_of_sta_5g <= 8 and result['interface']['ip'] == '0.0.0.0')
                    or (no_of_sta_5g > 8 and result['interface']['ip'] != '0.0.0.0')):
                failed = True
            if "Key" not in dict_table_sta:
                dict_table_sta["Key"] = list(result["interface"].keys())
            dict_table_sta[f"Value ({sta})"] = list(result["interface"].values())

            if end_sta - start_sta == 3 or index == len(sta_names_5g) - 1:
                data_table_sta = tabulate(dict_table_sta, headers='keys', tablefmt='fancy_grid')
                logging.info(f"5G-Stations Data ({start_sta}-{end_sta}): \n{data_table_sta}\n")
                allure.attach(name=f"5G-Stations Data ({start_sta}-{end_sta})", body=str(data_table_sta))
                start_sta = end_sta + 1
                dict_table_sta.clear()

        if no_of_sta_2g > 8 or no_of_sta_5g > 8:
            self.pre_cleanup()
            if failed:
                logging.info("Some/All stations got the IP when more than 8 SSIDs were configured on a single band!")
                pytest.fail("Some/All stations got the IP when more than 8 SSIDs were configured on a single band!")
            else:
                logging.info("As expected, None of the stations got the IP when more than 8 SSIDs were configured "
                             "on a single band!")
                return

        if failed:
            self.pre_cleanup()
            logging.info("Some/All Stations didn't get IP address")
            pytest.fail("Some/All Stations didn't get IP address")
        logging.info("All Stations got IP address")

        logging.info("Creating Layer3 traffic on stations...")
        for sta in sta_names_2g + sta_names_5g:
            self.create_layer3(side_a_min_rate=6291456, side_a_max_rate=0,
                               side_b_min_rate=6291456, side_b_max_rate=0,
                               traffic_type="lf_tcp", sta_list=[sta], side_b=upstream_port,
                               start_cx=True, prefix=f"t-")
            logging.info(f"CX with TCP traffic created between endpoint-a = {sta} and endpoint-b = upstream port.")
            time.sleep(2)
            self.create_layer3(side_a_min_rate=6291456, side_a_max_rate=0,
                               side_b_min_rate=6291456, side_b_max_rate=0,
                               traffic_type="lf_udp", sta_list=[sta], side_b=upstream_port,
                               start_cx=True, prefix=f"u-")
            logging.info(f"CX with UDP traffic created between endpoint-a = {sta} and endpoint-b = upstream port.")
            time.sleep(2)

        logging.info("Running Layer3 traffic for 40 sec ...")
        time.sleep(40)

        logging.info("Fetching CX data and adding it to the report...")
        cx_list = self.get_cx_list()
        dict_table_cx_tcp = {}
        dict_table_cx_udp = {}
        pass_fail_data = []
        overall_test = True
        start_tcp, start_udp = 1, 1
        end_tcp, end_udp = 0, 0
        for i in range(len(cx_list)):
            cx_data = self.json_get(_req_url=f"cx/{cx_list[i]}")
            cx_name = f"{cx_list[i].split('-')[1]}"

            if "L3 CX Column" not in dict_table_cx_tcp:
                dict_table_cx_tcp["L3 CX Column"] = list(cx_data[f"{cx_list[i]}"].keys())
            if "L3 CX Column" not in dict_table_cx_udp:
                dict_table_cx_udp["L3 CX Column"] = list(cx_data[f"{cx_list[i]}"].keys())
            if "TCP" in cx_data[f"{cx_list[i]}"]['type']:
                end_tcp += 1
                dict_table_cx_tcp[f"values ({cx_name})"] = list(cx_data[f"{cx_list[i]}"].values())
            else:
                end_udp += 1
                dict_table_cx_udp[f"values ({cx_name})"] = list(cx_data[f"{cx_list[i]}"].values())

            if cx_data[cx_list[i]]['bps rx a'] != 0 and cx_data[cx_list[i]]['bps rx a'] != 0:
                res = True
            else:
                overall_test = False
                res = False
            pass_fail_data.append(
                [f"{cx_list[i][:-2]}", f"{cx_data[cx_list[i]]['bps rx a']}", f"{cx_data[cx_list[i]]['bps rx b']}", res])

            # attach l3 cx data to allure
            if end_tcp - start_tcp == 3 or (i == len(cx_list) - 1 and start_tcp <= end_tcp):
                data_table_cx_tcp = tabulate(dict_table_cx_tcp, headers='keys', tablefmt='fancy_grid')
                logging.info(f"L3 cross-connects Data (TCP) ({start_tcp} - {end_tcp}): \n{data_table_cx_tcp}\n")
                allure.attach(name=f"L3 cross-connects Data (TCP) ({start_tcp} - {end_tcp})",
                              body=str(data_table_cx_tcp))
                start_tcp = end_tcp + 1
                dict_table_cx_tcp.clear()
            if end_udp - start_udp == 3 or (i == len(cx_list) - 1 and start_udp <= end_udp):
                data_table_cx_udp = tabulate(dict_table_cx_udp, headers='keys', tablefmt='fancy_grid')
                logging.info(f"L3 cross-connects Data (UDP) ({start_udp} - {end_udp}): \n{data_table_cx_udp}\n")
                allure.attach(name=f"L3 cross-connects Data (UDP) ({start_udp} - {end_udp})",
                              body=str(data_table_cx_udp))
                start_udp = end_udp + 1
                dict_table_cx_udp.clear()

        logging.info("Attaching pass/fail data to the report...")
        result_table = tabulate(pass_fail_data,
                                headers=["Data Path", "Tx Rate (bps)", "Rx Rate (bps)", "Pass/Fail"],
                                tablefmt='fancy_grid')
        logging.info(f"Test Result Table: \n{result_table}\n")
        allure.attach(name="Test Result Table", body=str(result_table))

        self.pre_cleanup()

        if overall_test is False:
            pytest.fail("DataPath check failed, Traffic didn't reported on some endpoints")
        logging.info("All Traffic reported on all endpoints, test successful!")

    def strict_forwarding(self, ssids=[], num_stations_per_ssid=1, security="wpa2", dut_data={}, passkey="[BLANK]",
                          mode="BRIDGE", side_a_min_rate=6291456, side_a_max_rate=6291456, side_b_min_rate=0,
                          side_b_max_rate=0,
                          band="twog", vlan_id=[None]):
        self.check_band_ap(band=band)
        self.pre_cleanup()
        # Dict for per ssid station list
        ssid_num_sta = {}
        sta_list = []
        k = 0
        # logic for creting dict of per ssid sta list
        for i in ssids:
            for j in range(num_stations_per_ssid):
                sta_list.append("sta000" + str(k))
                k = k + 1
            ssid_num_sta[i] = sta_list
            sta_list = []
        logging.info("DUT DATA: " + str(dut_data))
        allure.attach(name="Min Tx rate -A", body=f"{side_a_min_rate} bytes")
        allure.attach(name="Min Tx rate -B", body=f"{side_b_min_rate} bytes")
        i = 0
        sta_list = []
        for dut in self.dut_data:
            for ssid in ssids:
                if num_stations_per_ssid > 1:
                    station_result = self.client_connect(ssid=ssid, passkey=passkey, security=security, mode=mode,
                                                         band=band, vlan_id=vlan_id,
                                                         client_type=0, pre_cleanup=True,
                                                         num_sta=len(ssid_num_sta[ssid]),
                                                         dut_data=dut_data)
                    sta_list = sta_list + list(station_result.keys())
                else:
                    all_radio_5g = (self.wave2_5g_radios + self.wave1_radios + self.mtk_radios + self.ax200_radios +
                                    self.be200_radios + self.ax210_radios)
                    logging.info("All 5g radios" + str(all_radio_5g))
                    all_radio_2g = (self.wave2_2g_radios + self.wave1_radios + self.mtk_radios + self.ax200_radios +
                                    self.be200_radios + self.ax210_radios)
                    logging.info("All 2g radios" + str(all_radio_2g))
                    if band == "twog":
                        radio_prefix = all_radio_2g
                    elif band == "fiveg":
                        radio_prefix = all_radio_5g
                    logging.info("Radio: " + str(radio_prefix[i]))
                    station_result = self.client_connect_using_radio(ssid=ssid, passkey=passkey, security=security,
                                                                     mode=mode,
                                                                     band=band, vlan_id=vlan_id,
                                                                     client_type=0, radio=radio_prefix[i],
                                                                     station_name=ssid_num_sta[ssid],
                                                                     dut_data=dut_data)
                    sta = ssid_num_sta[ssid][0]
                    logging.info("sta: " + str(sta))
                    shelf = radio_prefix[i].split(".")[0]
                    resource = radio_prefix[i].split(".")[1]
                    logging.info("shelf: " + str(shelf))
                    logging.info("resource: " + str(resource))
                    sta_data = self.json_get(_req_url="port/" + str(shelf) + "/" + str(resource) + "/%s" % sta)
                    self.allure_report_table_format(dict_data=sta_data["interface"], key="Station Data",
                                                    value="Value", name="%s info" % sta)
                    if not station_result:
                        allure.attach(name="Test Result", body="TEST FAILED, due to station has no ip")
                        return False, "TEST FAILED, due to station has no ip"
                    i = i + 1
                    sta_list = sta_list + ssid_num_sta[ssid]
            logging.info("station data: " + str(sta_list))
            layer3_result = self.create_layer3(side_a_min_rate=side_a_min_rate, side_a_max_rate=side_a_max_rate,
                                               side_b_min_rate=side_b_min_rate, side_b_max_rate=side_b_max_rate,
                                               traffic_type="lf_tcp", sta_list=[sta_list[0]],
                                               side_b=sta_list[1])
            logging.info("waiting for 20 seconds")
            time.sleep(20)
            cx_list = self.get_cx_list()
            rx_data = self.json_get(_req_url=f"cx/{cx_list[0]}")
            rx_drop_a = rx_data[f"{cx_list[0]}"]["rx drop % a"]
            rx_drop_b = rx_data[f"{cx_list[0]}"]["rx drop % b"]
            bps_rx_a = rx_data[f"{cx_list[0]}"]["bps rx a"]
            bps_rx_b = rx_data[f"{cx_list[0]}"]["bps rx b"]
            table_columns = [sta_list[0], sta_list[1]]
            self.allure_report_table_format(dict_data=rx_data[f"{cx_list[0]}"], key="layer3 column names",
                                            value="Values",
                                            name="Layer-3 Data")
            table_data = {"Station Name": table_columns, "bps rx a": [bps_rx_a, bps_rx_b],
                          "rx drop %": [rx_drop_a, rx_drop_b]}
            table = tabulate(table_data, headers='keys', tablefmt='fancy_grid', showindex=True)
            logging.info(str(table))
            self.client_disconnect(clear_all_sta=True, clean_l3_traffic=True)
            if bps_rx_a == 0 and bps_rx_b == 0 and rx_drop_a == 0 and rx_drop_b == 0:
                allure.attach(name="Test Result", body="TEST PASSED" + "\n\n" + str(table))
                return True, "TEST PASS"
            else:
                allure.attach(name="Test Result",
                              body="TEST FAILED, Stations should not ping each other" + "\n\n" + str(table))
                return False, "TEST FAILED, Stations should not ping each other"

    def advanced_captive_portal(self, ssid="[BLANK]", security="wpa2", dut_data={}, passkey="[BLANK]", mode="BRIDGE",
                                band="twog", num_sta=1, vlan_id=[None], json_post_data='', get_testbed_details={},
                                tip_2x_obj=None):
        self.check_band_ap(band=band)
        self.pre_cleanup()
        pass_fail = "PASS"
        description = ""
        logging.info("DUT DATA: " + str(dut_data))
        for dut in self.dut_data:
            station_result = self.client_connect_using_radio(ssid=ssid, passkey=passkey, security=security, mode=mode,
                                                             band=band, vlan_id=vlan_id, radio="1.1.wiphy0",
                                                             client_type=0,
                                                             station_name=["sta0000"],
                                                             dut_data=dut_data)
            sta = "sta0000"
            sta_data = self.json_get(_req_url="port/1/1/%s" % sta)
            self.allure_report_table_format(dict_data=sta_data["interface"], key="Station Data",
                                            value="Value", name="%s info" % sta)
            if not station_result:
                allure.attach(name="Test Result", body="TEST FAILED, due to station has no ip")
                return "FAIL", "TEST FAILED, due to station has no ip"
            logging.info("sta " + str(sta))
            # Finding captive portal url ip
            if tip_2x_obj is not None:
                logging.info("AP idx: " + str(self.dut_data.index(dut)))
                cmd_output = tip_2x_obj.get_dut_library_object().run_generic_command(cmd="ifconfig up0v0",
                                                                                     idx=self.dut_data.index(dut),
                                                                                     attach_allure=False)
                logging.info("cmd output: " + str(cmd_output))
                ip_pattern = re.compile(r"inet addr:(\d+\.\d+\.\d+\.\d+)")
                match = ip_pattern.search(cmd_output)
                inet_ip_addr = match.group(1)
                logging.info("inet ip addr: " + str(inet_ip_addr))
            cmd = f'/home/lanforge/vrf_exec.bash {sta} curl -X POST -H "Content-Type:application/json" -d "{json_post_data}" http://{inet_ip_addr}/hotspot'
            logging.info("cmd: " + str(cmd))
            # SSH connection parameters
            hostname = get_testbed_details["traffic_generator"]["details"]["manager_ip"]
            port = get_testbed_details["traffic_generator"]["details"]["ssh_port"]
            username = 'root'
            password = 'lanforge'
            ping_host = "google.com"
            ping_count = 10
            logging.info(
                f"hostname: {hostname} port: {port} username: {username} password: {password} ping_host: {ping_host}")
            ping_command = f"/home/lanforge/vrf_exec.bash {sta} ping -c {ping_count} {ping_host}"
            validate_captive_string = '<div class="card-header">uCentral - Captive Portal</div>'
            validate_ping_string = "0% packet loss"
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(hostname, port=port, username=username, password=password)
                # Before captive portal Validate client internet connectivity
                logging.info("cmd: " + str(ping_command))
                stdin, stdout, stderr = client.exec_command(ping_command)
                before_captive_ping_output = stdout.read().decode()
                logging.info("Before_captive_ping_output: " + str(before_captive_ping_output))
                allure.attach(name="Before captive portal authentication station ping response (google.com)",
                              body=str(before_captive_ping_output))
                if "100% packet loss" in before_captive_ping_output:
                    logging.info("Before captive portal authentication client do not have internet connectivity")
                elif validate_ping_string in before_captive_ping_output:
                    pytest.fail("Before captive portal authentication client already has internet access")
                logging.info("cmd: " + str(cmd))
                stdin, stdout, stderr = client.exec_command(cmd)
                time.sleep(5)
                captive_output = stdout.read().decode()
                logging.info("Captive portal authentication logs: " + str(captive_output))
                allure.attach(name="Response from captive portal: ",
                              body=captive_output, attachment_type=allure.attachment_type.HTML)
                if validate_captive_string in captive_output and "Invalid credentials" not in captive_output:
                    logging.info("Captive portal authentication successful")
                else:
                    if "Invalid credentials" in captive_output:
                        pytest.fail("Invalid credentials")
                    pytest.fail("Captive portal authentication Failed")
                logging.info("cmd: " + str(ping_command))
                stdin, stdout, stderr = client.exec_command(ping_command)
                after_captive_ping_output = stdout.read().decode()
                logging.info("After captive portal authentication station ping response (google.com: " + str(
                    after_captive_ping_output))
                allure.attach(name="After captive portal authentication station ping response (google.com)",
                              body=str(after_captive_ping_output))
                if validate_ping_string in after_captive_ping_output:
                    logging.info("Client got internet access")
                else:
                    pytest.fail("After captive portal authentication doesn't have internet connectivity")
                # Close the SSH connection
                client.close()
            except Exception as e:
                logging.error(f"{e}")
                pass_fail = "FAIL"
                description = f"{e}"
        return pass_fail, description

    def roam_test(self, ap1_bssid="90:3c:b3:6c:46:dd", ap2_bssid="90:3c:b3:6c:47:2d", fiveg_radio="1.1.wiphy4",
                  twog_radio="1.1.wiphy5", sixg_radio="1.1.wiphy6", scan_freq="5180,5180",
                  band="twog", sniff_radio_="1.1.wiphy7", num_sta=1, security="wpa2", security_key="Openwifi",
                  ssid="OpenWifi", upstream="1.1.eth1", duration=None, iteration=1, channel="11", option="ota",
                  dut_name=["edgecore_eap101", "edgecore_eap102"], traffic_type="lf_udp", eap_method=None,
                  eap_identity=None, eap_password=None, pairwise_cipher=None, groupwise_cipher=None,
                  private_key=None, pk_passwd=None, ca_cert=None, eap_phase1=None, eap_phase2=None,
                  soft_roam=False, sta_type="11r"):

        # create monitor and start sniffer & run test in parallel
        if "1.1." in sniff_radio_:
            sniff_radio_.strip("1.1.")
        t1 = threading.Thread(target=self.start_sniffer, args=(channel, sniff_radio_, "11r-roam-test-capture", 300))
        t1.start()

        roam_obj = Roam(lanforge_ip=self.manager_ip,
                        port=self.manager_http_port,
                        band=band,
                        sniff_radio=sniff_radio_,
                        num_sta=num_sta,
                        security=security,
                        password=security_key,
                        ssid=ssid,
                        upstream=upstream,
                        duration=duration,
                        option=option,
                        iteration_based=True,
                        eap_method=eap_method,
                        eap_identity=eap_identity,
                        eap_password=eap_password,
                        pairwise_cipher=pairwise_cipher,
                        groupwise_cipher=groupwise_cipher,
                        private_key=private_key,
                        pk_passwd=pk_passwd,
                        ca_cert=ca_cert,
                        softroam=soft_roam,
                        sta_type=sta_type,
                        ieee80211w="1",
                        )
        create_sta = False
        if band == "twog":
            self.local_realm.reset_port(twog_radio)
            roam_obj.band = '2G'
            roam_obj.station_radio = twog_radio
            create_sta = roam_obj.create_clients(sta_prefix="roam")
        if band == "fiveg":
            self.local_realm.reset_port(fiveg_radio)
            roam_obj.band = '5G'
            roam_obj.station_radio = fiveg_radio
            create_sta = roam_obj.create_clients(sta_prefix="roam")
        if band == "sixg":
            self.local_realm.reset_port(sixg_radio)
            roam_obj.band = '6G'
            roam_obj.station_radio = sixg_radio
            create_sta = roam_obj.create_clients(sta_prefix="roam")
        if band == "both":
            self.local_realm.reset_port("1.1.wiphy5")
            roam_obj.station_radio = "1.1.wiphy5"
            create_sta = roam_obj.create_clients(sta_prefix="roam")
        if not create_sta:
            # stop sniffer if station is not created
            try:
                self.stop_sniffer(['11r-roam-test-capture'])
            except Exception as e:
                logging.error(f"error {e} : Packet Capture failed.")
            return False, "Stations failed to get IP address"
        time.sleep(10)

        port_data = self.json_get("/port/?fields=port+type,alias")['interfaces']

        # fetch roam station data from port data
        sta_name = ""
        for port in range(len(port_data)):
            for key, val in port_data[port].items():
                if "roam" in key:
                    sta_name = key
                    break

        #  enable over the ds in generate script if passed
        if option == "otd":
            gen_ds = 1
        else:
            gen_ds = 0

        # Parse BSSID's as a lowercase string separated by ,

        ap1_bssid = ap1_bssid.lower()
        ap2_bssid = ap2_bssid.lower()
        bssid_list = ap1_bssid + "," + ap2_bssid

        wifi_mobility_obj = WifiMobility(lfclient_host=self.manager_ip,
                                         lf_port=self.manager_http_port,
                                         ssh_port=self.manager_ssh_port,
                                         lf_user="lanforge",
                                         lf_password="lanforge",
                                         blob_test="WiFi-Mobility-",
                                         instance_name="cv-inst-0",
                                         config_name="roam_test_cfg",
                                         pull_report=True,
                                         load_old_cfg=False,
                                         raw_lines=None,
                                         raw_lines_file="",
                                         enables=None,
                                         disables=None,
                                         sets=None,
                                         cfg_options=None,
                                         sort="interleave",
                                         stations=sta_name,
                                         bssid_list=bssid_list,
                                         gen_scan_freqs=scan_freq,
                                         gen_sleep_interval="5000",
                                         gen_scan_sleep_interval="1000",
                                         gen_ds=gen_ds,
                                         duration="60000",
                                         default_sleep="250",
                                         auto_verify="10000",
                                         max_rpt_time='1000',
                                         skip_roam_self='1',
                                         loop_check='1',
                                         clear_on_start='1',
                                         show_events='1',
                                         report_dir="",
                                         graph_groups=None,
                                         test_rig="Testbed-01",
                                         test_tag="",
                                         local_lf_report_dir="../reports/",
                                         verbosity="5"
                                         )

        if wifi_mobility_obj.instance_name.endswith('-0'):
            wifi_mobility_obj.instance_name = wifi_mobility_obj.instance_name + str(random.randint(1, 999))

        t2 = threading.Thread(target=wifi_mobility_obj.run)
        t2.start()

        # wait until the completion of mobility test and sniffer
        t2.join()
        t1.join()

        # stop sniffer and attach pcap
        try:
            self.stop_sniffer(['11r-roam-test-capture'])
        except Exception as e:
            logging.error(f"error {e} : Packet Capture failed.")
        report_name, pass_fail_data = "", list()
        if wifi_mobility_obj.report_name and len(wifi_mobility_obj.report_name) >= 1:
            report_name = wifi_mobility_obj.report_name[0]['LAST']["response"].split(":::")[1].split("/")[-1] + "/"
            time.sleep(10)
            logging.info("report_name: " + str(report_name))
            self.attach_report_graphs(report_name=report_name, pdf_name="WiFi-Mobility (Roam Test) PDF Report")
        else:
            logging.error(f"PATH {wifi_mobility_obj.report_name} does not exist")

        if wifi_mobility_obj.get_exists(wifi_mobility_obj.instance_name):
            wifi_mobility_obj.delete_instance(wifi_mobility_obj.instance_name)

        # fetch csv data from report data & attach pass fail results
        if not report_name.endswith("/"):
            report_name = report_name + "/"
        if os.path.exists("../reports/" + report_name + "chart-csv-7.csv"):
            with open("../reports/" + report_name + "chart-csv-7.csv", 'rb') as csv_file:
                file_content = csv_file.read()
                allure.attach(file_content, name=f"Roam Test (11r) Pass/Fail Data",
                              attachment_type=allure.attachment_type.CSV)
            with open("../reports/" + report_name + "chart-csv-7.csv", 'r') as csv_file:
                for row in csv.reader(csv_file):
                    pass_fail_data.append(row)
        else:
            logging.info(f"{report_name} Does not exist.")

        logging.info(str(pass_fail_data))
        # prepare pass fail data to be displayed in a table
        if len(pass_fail_data) > 1:
            message = tabulate(pass_fail_data, headers="firstrow", tablefmt="rounded_grid")
        else:
            message = "Test Passed"
        # return false when any of the roam result is 'FAIL' in pass fail data
        for i in pass_fail_data[1:]:
            if i[2] == 'FAIL':
                return False, message
        else:
            return True, message


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

    # dut = {'903cb36c46ad':
    #     {'ssid_data': {
    #         0: {'ssid': 'OpenWifi', 'encryption': 'wpa2', 'password': 'OpenWifi', 'band': '5G',
    #             'bssid': '90:3C:B3:6C:46:B1'}}, 'radio_data': {
    #                                                            '5G': {'channel': 52, 'bandwidth': None,
    #                                                                   'frequency': None}}}}
    #
    # passes, result = obj.hot_config_reload_test(ssid="OpenWifi", passkey="OpenWifi", security="wpa2",
    #                                               extra_securities=[],
    #                                               num_sta=1, mode="BRIDGE", dut_data=dut,
    #                                               band="fiveg")