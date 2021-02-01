
import sys
if 'py-json' not in sys.path:
    sys.path.append('../py-json')
from LANforge import LFUtils
from LANforge import lfcli_base
from LANforge.lfcli_base import LFCliBase
from LANforge.LFUtils import *
import realm
from realm import Realm
import argparse
import datetime
import time

class Layer3Test(LFCliBase):

    def __init__(self, lfclient_host="localhost", lfclient_port=8080, radio="wiphy1", sta_prefix="sta", start_id=0, num_sta=2,
                 dut_ssid="lexusdut", dut_security="open", dut_passwd="[BLANK]", upstream="eth1", name_prefix="L3Test",
                 traffic_type="lf_udp",side_a_speed="0M", side_b_speed="10M", session_id="Layer3Test", duration="1m",_debug_on=False, _exit_on_error=False,  _exit_on_fail=False):
        super().__init__(lfclient_host, lfclient_port, _debug=_debug_on, _halt_on_error=_exit_on_error, _exit_on_fail=_exit_on_fail)
        print("Test is about to start")
        self.host = lfclient_host
        self.port = lfclient_port
        self.radio = radio
        self.upstream = upstream
        self.monitor_interval = 1
        self.sta_prefix = sta_prefix
        self.sta_start_id = start_id
        self.test_duration = duration
        self.num_sta = num_sta
        self.name_prefix = name_prefix
        self.ssid = dut_ssid
        self.security = dut_security
        self.password = dut_passwd
        self.session_id = session_id
        self.traffic_type = traffic_type
        self.side_a_speed = side_a_speed
        self.side_b_speed = side_b_speed
        self.local_realm = realm.Realm(lfclient_host=self.host, lfclient_port=self.port)
        self.station_profile = self.local_realm.new_station_profile()
        self.cx_profile = self.local_realm.new_l3_cx_profile()

        self.cx_profile.host = self.host
        self.cx_profile.port = self.port
        self.cx_profile.name_prefix = self.name_prefix
        self.cx_profile.side_a_min_bps = self.local_realm.parse_speed(self.side_a_speed)
        self.cx_profile.side_a_max_bps = self.local_realm.parse_speed(self.side_a_speed)
        self.cx_profile.side_b_min_bps = self.local_realm.parse_speed(self.side_b_speed)
        self.cx_profile.side_b_max_bps = self.local_realm.parse_speed(self.side_b_speed)

        print("Test is Initialized")


    def precleanup(self):
        print("precleanup started")
        self.station_list = LFUtils.portNameSeries(prefix_=self.sta_prefix, start_id_=self.sta_start_id, end_id_=self.num_sta - 1, padding_number_=10000, radio=self.radio)
        self.cx_profile.cleanup_prefix()
        for sta in self.station_list:
            self.local_realm.rm_port(sta, check_exists=True)
            time.sleep(1)
        self.cx_profile.cleanup()

        LFUtils.wait_until_ports_disappear(base_url=self.lfclient_url, port_list=self.station_profile.station_names,
                                           debug=self.debug)
        print("precleanup done")
        pass

    def build(self):
        print("Building Test Configuration")
        self.station_profile.use_security(self.security, self.ssid, self.password)
        self.station_profile.set_number_template("00")
        self.station_profile.set_command_flag("add_sta", "create_admin_down", 1)
        self.station_profile.set_command_param("set_port", "report_timer", 1500)
        self.station_profile.set_command_flag("set_port", "rpt_timer", 1)
        self.station_profile.create(radio=self.radio, sta_names_=self.station_list, debug=self.debug)
        self.local_realm.wait_until_ports_appear(sta_list=self.station_list)
        self.cx_profile.create(endp_type=self.traffic_type, side_a=self.station_profile.station_names, side_b=self.upstream, sleep_time=0)
        print("Test Build done")
        pass

    def start(self, print_pass=False, print_fail=False):
        print("Test is starting")
        self.cx_names =[]
        self.station_profile.admin_up()
        temp_stas = self.station_profile.station_names.copy()
        temp_stas.append(self.upstream)
        if (self.local_realm.wait_for_ip(temp_stas)):
            self._pass("All stations got IPs", print_pass)
        else:
            self._fail("Stations failed to get IPs", print_fail)
            exit(1)
        self.cx_profile.start_cx()
        try:
            for i in self.cx_profile.get_cx_names():
                self.cx_names.append(i)
                while self.local_realm.json_get("/cx/" + i).get(i).get('state') != 'Run':
                    continue
        except Exception as e:
            pass
        print("Test Started")
        self.cur_time = datetime.datetime.now()
        self.end_time = self.local_realm.parse_time(self.test_duration) + self.cur_time
        print(self.end_time-self.cur_time)
        self.start_monitor()
        pass

    def my_monitor(self):
        print("Monitoring Test")
        print(self.end_time - datetime.datetime.now())
        if (datetime.datetime.now() > self.end_time):
            self.stop_monitor()
        for i in self.cx_names:
            self.add_event(message= self.cx_profile.get_cx_report()[i]['bps rx b'], name=self.session_id)
        return self.cx_profile.get_cx_report()

    def stop(self):
        print("Stopping Test")
        self.cx_profile.stop_cx()
        self.station_profile.admin_down()
        pass

    def postcleanup(self):
        self.cx_profile.cleanup()
        self.station_profile.cleanup()
        LFUtils.wait_until_ports_disappear(base_url=self.lfclient_url, port_list=self.station_profile.station_names,
                                           debug=self.debug)
        print("Test Completed")
        pass

def main():
    # This has --mgr, --mgr_port and --debug
    parser = LFCliBase.create_bare_argparse(prog="layer3_test.py", formatter_class=argparse.RawTextHelpFormatter, epilog="About This Script")

    # Adding More Arguments for custom use
    parser.add_argument('--ssid', help='--ssid of DUT', default="lexusdut")
    parser.add_argument('--passwd', help='--passwd of dut', default="[BLANK]")
    parser.add_argument('--radio', help='--radio to use on LANforge', default="wiphy1")
    parser.add_argument('--security', help='--security of dut', default="open")
    parser.add_argument('--test_duration', help='--test_duration sets the duration of the test', default="1m")
    parser.add_argument('--session_id', help='--session_id is for websocket', default="local")
    parser.add_argument('--num_client', type=int, help='--num_sta is number of stations you want to create', default=2)
    parser.add_argument('--side_a_min_speed', help='--speed you want to monitor traffic with (max is 10G)', default="0M")
    parser.add_argument('--side_b_min_speed', help='--speed you want to monitor traffic with (max is 10G)', default="10M")
    parser.add_argument('--traffic_type', help='--traffic_type is used for traffic type (lf_udp, lf_tcp)', default="lf_udp")
    args = parser.parse_args()
    print(args)

    # Start Test
    obj = Layer3Test(lfclient_host=args.mgr, lfclient_port=args.mgr_port,
                     duration=args.test_duration, session_id=args.session_id,
                     traffic_type=args.traffic_type,
                     dut_ssid=args.ssid, dut_passwd=args.passwd, dut_security=args.security, num_sta=args.num_client, side_a_speed=args.side_a_min_speed, side_b_speed=args.side_b_min_speed, radio=args.radio)
    obj.precleanup()
    obj.build()
    obj.start()
    obj.monitor()
    obj.stop()
    obj.postcleanup()

if __name__ == '__main__':
    main()