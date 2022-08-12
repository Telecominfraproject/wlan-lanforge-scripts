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
createstation = importlib.import_module("py-scripts.create_station")
CreateStation = createstation.CreateStation


class lf_tests(lf_libs):
    """
        lf_tools is needed in lf_tests to do various operations needed by various tests
    """
    twog_prefix = "ath10k_2g0"
    fiveg_prefix = "ath10k_5g0"
    sixg_prefix = "AX210_0"
    ax_prefix = "AX200_0"
    pcap_obj = None

    def __init__(self, lf_data={}, dut_data={}, log_level=logging.DEBUG, run_lf=False, influx_params=None):
        super().__init__(lf_data, dut_data, log_level)
        self.run_lf = run_lf
        # self.upstream_port = list(self.uplink_nat_ports.keys())[0]
        # self.skip_pcap = skip_pcap
        # self.wan_upstream = list(self.wan_ports.keys())
        # self.lan_upstream =
        self.staConnect = StaConnect2(self.manager_ip, self.manager_http_port, outfile="shivam", _cleanup_on_exit=False)

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
            upstream_port = self.upstream_port()
        elif mode == "NAT-WAN":
            upstream_port = self.upstream_port()
        elif mode == "NAT-LAN":
            upstream_port = self.upstream_port()
        elif mode == "VLAN":
            # for vlan mode vlan id should be available
            if vlan_id is None:
                upstream_port = self.upstream_port() + str(vlan_id)
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
        print(self.dut_data)
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
            print(num_sta, self.max_2g_stations)
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
        print(length_to_split)
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

    def upstream_port(self):
        """finding upstream port"""
        upstream_port = ""
        print(len(self.dut_data))
        for i in self.dut_data:
            upstream_port = i["wan_port"]
        print(upstream_port)
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

    def client_connectivity_test(self, ssid="[BLANK]", passkey="[BLANK]", dut_data={},
                                 security="open", extra_securities=[],
                                 num_sta=1, mode="BRIDGE", vlan_id=1, band="twog", ssid_channel=None,
                                 allure_attach=True, runtime_secs=40):
        # self.staConnect = StaConnect2(self.manager_ip, self.manager_http_port, debug_=self.debug)
        # setup_interfaces() interface selection return radio name along no of station on each radio, upstream port
        #
        self.add_vlan(vlan_id=vlan_id)
        data = self.setup_interfaces(band=band, vlan_id=vlan_id, mode=mode, num_sta=num_sta)
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
            print("scan ssid radio", radio.split(".")[2])
            result = self.scan_ssid(radio=radio, ssid=ssid, ssid_channel=ssid_channel)
            print("ssid scan data :- ", result)
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
            print("after-setup")
            if ssid_channel:
                pass
                # Need to start sniffer
                # print("sniff radio", data["sniff_radio"].split(".")[2])
                # self.start_sniffer(radio_channel=ssid_channel, radio=data["sniff_radio"].split(".")[2], duration=30)
            sta_connect_obj.append(obj_sta_connect)
            print("after-adding-object")
        for dut in self.dut_data:
            identifier = dut["identifier"]
            if dut_data.keys().__contains__(identifier):
                if band == "twog":
                    if dict(dut_data.get(identifier)[-1]).keys().__contains__("2G") and \
                            dict(dut_data.get(identifier)[-1])["2G"] is not None:
                        channel = dict(dut_data.get(identifier)[-1])["2G"][0]
                        self.start_sniffer(radio_channel=channel, radio=data["sniff_radio"].split(".")[2],
                                           duration=runtime_secs)
                        print("started-sniffer")
                        for obj in sta_connect_obj:
                            print(obj)
                            obj.start()
                        print("napping %f sec" % runtime_secs)
                        time.sleep(runtime_secs)
                        print("stopping-sniffer")
                        self.stop_sniffer()
                elif band == "fiveg":
                    if dict(dut_data.get(identifier)[-1]).keys().__contains__("5G") and \
                            dict(dut_data.get(identifier)[-1])["5G"] is not None:
                        channel = dict(dut_data.get(identifier)[-1])["5G"][0]
                        self.start_sniffer(radio_channel=channel, radio=data["sniff_radio"].split(".")[2],
                                           duration=runtime_secs)
                        for obj in sta_connect_obj:
                            print(obj)
                            obj.start()
                        print("napping %f sec" % runtime_secs)
                        time.sleep(runtime_secs)
                        self.stop_sniffer()
                elif band == "sixg":
                    if dict(dut_data.get(identifier)[-1]).keys().__contains__("6G") and \
                            dict(dut_data.get(identifier)[-1])["6G"] is not None:
                        channel = dict(dut_data.get(identifier)[-1])["6G"][0]
                        self.start_sniffer(radio_channel=channel, radio=data["sniff_radio"].split(".")[2],
                                           duration=runtime_secs)
                        for obj in sta_connect_obj:
                            print(obj)
                            obj.start()
                        print("napping %f sec" % runtime_secs)
                        time.sleep(runtime_secs)
                        self.stop_sniffer()
        pass_fail_result = []
        for obj in sta_connect_obj:
            print(obj.station_names)
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
            print(cx_name)
            print(obj.get_result_list())
            print(obj.l3_udp_profile.get_cx_names())
            cx_data = self.get_cx_data(cx_name=cx_name, cx_data=cx_row, allure_attach=False)
            print(cx_data)
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
            print(pass_fail_sta)
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
                print("client connection to", obj.dut_ssid, "successful. Test Passed")
                result = "PASS"
                temp_dict[result] = ""
                pass_fail_result.append(temp_dict)
            else:
                print("client connection to", obj.dut_ssid, "unsuccessful. Test Failed")
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

        print(result)
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

    def Client_Connect(self, ssid="[BLANK]", passkey="[BLANK]", security="wpa2", mode="BRIDGE", band="twog",
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
        print("scan ssid radio", client_connect.radio)
        if scan_ssid:
            self.data_scan_ssid = self.scan_ssid(radio=client_connect.radio, ssid=ssid)
        print("ssid scan data :- ", self.data_scan_ssid)
        client_connect_obj.append(client_connect)
        pass_fail = []
        for obj in client_connect_obj:
            obj.build()
            result = obj.wait_for_ip(station_list=obj.sta_list, timeout_sec=100)
            # print(self.client_connect.wait_for_ip(station_name))
            pass_fail.append(result)
            station_data_ = self.get_station_data(sta_name=obj.sta_list, rows=sta_rows,
                                                  allure_attach=False)
            station_data_all.append(station_data_)
            sta_table_dict = {}
            sta_table_dict["station name"] = list(station_data_.keys())
            for i in station_data:
                temp_list = []
                for j in obj.sta_list:
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

        logging.info("pass_fail result: " + str(pass_fail))
        if False in pass_fail:
            logging.info("Station did not get an ip")
            pytest.fail("Station did not get an ip")
        else:
            logging.info("ALL Stations got IP's")
            return station_data_all

    def scan_ssid(self, radio="", retry=1, allure_attach=True, scan_time=15, ssid=None, ssid_channel=None):
        '''This method for scan ssid data'''
        count = 0
        sta_list = []
        sta_name = str(radio.split(".")[0]) + "." + str(radio.split(".")[1]) + "." + "sta00100"
        sta_list.append(sta_name)
        print("scan station", sta_list)
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
                print(e)
            report_obj = Report()
            csv_data_table = report_obj.table2(list_data)
            # allure.attach(name="scan_ssid_data", body=csv_data_table)
            if allure_attach:
                allure.attach(name="scan_ssid_data_" + str(i + 1), body=csv_data_table)
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
        print(cx_json_data)
        try:
            for sta_ in cx_name:
                temp_dict = {}
                for i in cx_data:
                    temp_dict[i] = cx_json_data[sta_][i]
                dict_cx_data[sta_] = temp_dict
            print(dict_cx_data)
        except Exception as e:
            logging.error(e)
        print(dict_cx_data)
        cx_table_dict = {}
        cx_table_dict["cx name"] = list(dict_cx_data.keys())
        for i in cx_data:
            temp_list = []
            for j in cx_name:
                temp_list.append(dict_cx_data[j][i])
            print(i)
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
            print(data_table)
            allure.attach(name=allure_name, body=data_table)
        except Exception as e:
            logging.error(e)


if __name__ == '__main__':
    basic_1 = {
        "target": "tip_2x",
        "controller": {
            "url": "https://sec-qa01.cicd.lab.wlan.tip.build:16001",
            "username": "tip@ucentral.com",
            "password": "OpenWifi%123"
        },
        "device_under_tests": [{
            "model": "cig_wf188n",
            "supported_bands": ["2G", "5G"],
            "wan_port": "1.1.eth1",
            "supported_modes": ["BRIDGE", "NAT", "VLAN"],
            "ssid": {
                "2g-ssid": "OpenWifi",
                "5g-ssid": "OpenWifi",
                "6g-ssid": "OpenWifi",
                "2g-password": "OpenWiifi",
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
            "scenario": "dhcp-external",  # dhcp-bridge / dhcp-external
            "details": {
                "manager_ip": "192.168.200.101",
                "http_port": 8080,
                "ssh_port": 22,
                "setup": {"method": "build", "DB": "Test_Scenario_Automation"},  # method: build/load,
                "wan_ports": {
                    "1.1.eth1": {"addressing": "dhcp-server", "subnet": "172.16.0.1/16", "dhcp": {
                        "lease-first": 10,
                        "lease-count": 10000,
                        "lease-time": "6h"
                    }}},
                "lan_ports": {},

                "1.1.eth1": {"addressing": "dynamic"}},
            "lan_ports": {},
            "uplink_nat_ports": {

                # dhcp-server/{"addressing":
                # "dynamic"} /{"addressing": "static", "subnet": "10.28.2.6/16"}
            }

        }
    }

    obj = lf_tests(lf_data=dict(basic_1["traffic_generator"]), dut_data=list(basic_1["device_under_tests"]),
                   log_level=logging.DEBUG, run_lf=True)
    obj.setup_relevent_profiles()
    obj.add_vlan(vlan_ids=[100, 200, 300, 400, 500, 600])
    # obj.create_dhcp_external()obj.add_vlan(vlan_ids=[100, 200, 300, 400, 500, 600])
    # obj.get_cx_data()
    # obj.chamber_view()
    # c = obj.client_connectivity_test(ssid="OpenWifi", passkey="OpenWifi", security="wpa2", extra_securities=[],
    #                              num_sta=1, mode="BRIDGE", vlan_id=1,
    #                              band="twog", ssid_channel=11)
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
