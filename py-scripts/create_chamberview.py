#!/usr/bin/env python3
"""
Note: To Run this script gui should be opened with

    path: cd LANforgeGUI_5.4.3 (5.4.3 can be changed with GUI version)
          pwd (Output : /home/lanforge/LANforgeGUI_5.4.3)
          ./lfclient.bash -cli-socket 3990

Note: Scenario names should be different, for each run of this script.
    in case of same scenario name scenario will be appended to the same name.

Note: Script for creating a chamberview scenario.
    Run this script to set/create a chamber view scenario.
    ex. on how to run this script:

    create_chamberview.py -m "localhost" -o "8080" -cs "scenario_name"
    --line "Resource=1.1 Profile=STA-AC Amount=1 Uses-1=wiphy0 Uses-2=AUTO Freq=-1
        DUT=Test DUT_Radio=Radio-1 Traffic=http VLAN="
    --line "Resource=1.1 Profile=upstream Amount=1 Uses-1=eth1 Uses-2=AUTO Freq=-1
        DUT=Test DUT_Radio=Radio-1 Traffic=http VLAN="

    ********************************      OR        ********************************

    create_chamberview.py -m "localhost" -o "8080" -cs "scenario_name"
    --raw_line "profile_link 1.1 STA-AC 10 'DUT: temp Radio-1' tcp-dl-6m-vi wiphy0,AUTO -1"
    --raw_line "profile_link 1.1 upstream 1 'DUT: temp Radio-1' tcp-dl-6m-vi eth1,AUTO -1"

Output:
    You should see build scenario with the given arguments at the end of this script.
    To verify this:
        open Chamber View -> Manage scenario
"""
import sys
import os
import importlib
import argparse
import time
import re

if sys.version_info[0] != 3:
    print("This script requires Python 3")
    exit(1)

sys.path.append(os.path.join(os.path.abspath(__file__ + "../../../")))

cv_test_manager = importlib.import_module("py-json.cv_test_manager")
cv = cv_test_manager.cv_test


class CreateChamberview(cv):
    def __init__(self,
                 lfmgr="localhost",
                 port="8080",
                 ):
        super().__init__(
            lfclient_host=lfmgr,
            lfclient_port=port,
        )
        self.lfmgr = lfmgr
        self.port = port

    def clean_cv_scenario(
            self,
            cv_type="Network-Connectivity",
            scenario_name=None):
        self.rm_cv_text_blob(cv_type, scenario_name)

    def setup(self,
              create_scenario="",
              line="",
              raw_line=None):

        if raw_line:
            print("creating %s scenario" % create_scenario)
            for create_lines in raw_line:
                self.pass_raw_lines_to_cv(create_scenario, create_lines[0])

        # check for lines
        if line:
            scenario_name = create_scenario
            line = line
            Resource = "1.1"
            Profile = "STA-AC"
            Amount = "1"
            DUT = "DUT"
            DUT_Radio = "Radio-1"
            Uses1 = "wiphy0"
            Uses2 = "AUTO"
            Traffic = "http"
            Freq = "-1"
            VLAN = ""

            for item in line:
                if " " in item[0]:
                    item[0] = (re.split(' ', item[0]))
                elif "," in item[0]:
                    item[0] = (re.split(',', item[0]))
                else:
                    print("Wrong arguments entered !")
                    exit(1)

                print("creating %s scenario" % scenario_name)
                for sub_item in item[0]:
                    sub_item = sub_item.split("=")
                    if sub_item[0] == "Resource" or str(
                            sub_item[0]) == "Res" or sub_item[0] == "R":
                        Resource = sub_item[1]
                    elif sub_item[0] == "Profile" or sub_item[0] == "Prof" or sub_item[0] == "P":
                        Profile = sub_item[1]
                    elif sub_item[0] == "Amount" or sub_item[0] == "Sta" or sub_item[0] == "A":
                        Amount = sub_item[1]
                    elif sub_item[0] == "Uses-1" or sub_item[0] == "U1" or sub_item[0] == "U-1":
                        Uses1 = sub_item[1]
                    elif sub_item[0] == "Uses-2" or sub_item[0] == "U2" or sub_item[0] == "U-2":
                        Uses2 = sub_item[1]
                    elif sub_item[0] == "Freq" or sub_item[0] == "Freq" or sub_item[0] == "F":
                        Freq = sub_item[1]
                    elif sub_item[0] == "DUT" or sub_item[0] == "dut" or sub_item[0] == "D":
                        DUT = sub_item[1]
                    elif sub_item[0] == "DUT_Radio" or sub_item[0] == "dr" or sub_item[0] == "DR":
                        DUT_Radio = sub_item[1]
                    elif sub_item[0] == "Traffic" or sub_item[0] == "Traf" or sub_item[0] == "T":
                        Traffic = sub_item[1]
                    elif sub_item[0] == "VLAN" or sub_item[0] == "Vlan" or sub_item[0] == "V":
                        VLAN = sub_item[1]
                    else:
                        continue

                self.add_text_blob_line(scenario_name,
                                        Resource,
                                        Profile,
                                        Amount,
                                        DUT,
                                        DUT_Radio,
                                        Uses1,
                                        Uses2,
                                        Traffic,
                                        Freq,
                                        VLAN
                                        )  # To manage scenario
        if not line and not raw_line:
            raise Exception("scenario creation failed")

        return True

    def build(self, scenario_name):
        self.sync_cv()  # chamberview sync
        time.sleep(2)
        self.apply_cv_scenario(scenario_name)  # Apply scenario
        self.show_text_blob(None, None, False)  # Show changes on GUI
        self.apply_cv_scenario(scenario_name)  # Apply scenario
        self.build_cv_scenario()  # build scenario
        tries = 0
        while True:
            self.get_popup_info_and_close()
            if not self.get_cv_is_built():
                # It can take a while to build a large scenario, so wait-time
                # is currently max of 5 minutes.
                print("Waiting %i/300 for Chamber-View to be built." % tries)
                tries += 1
                if tries > 300:
                    break
                time.sleep(1)
            else:
                break
        print("completed building %s scenario" % scenario_name)


def main():
    parser = argparse.ArgumentParser(
        prog='create_chamberview.py',
        formatter_class=argparse.RawTextHelpFormatter,
        description="""
        For Two line scenario use --line twice as shown in example, for multi line scenario
        use --line argument to create multiple lines
        \n
           create_chamberview.py -m "localhost" -o "8080" -cs "scenario_name"
             --line "Resource=1.1 Profile=STA-AC Amount=1 Uses-1=wiphy0 Uses-2=AUTO Freq=-1
                    DUT=Test DUT_Radio=Radio-1 Traffic=http VLAN="
             --line "Resource=1.1 Profile=upstream Amount=1 Uses-1=eth1 Uses-2=AUTO Freq=-1
                    DUT=Test DUT_Radio=Radio-1 Traffic=http VLAN="
           ********************************      OR        ********************************
           create_chamberview.py -m "localhost" -o "8080" -cs "scenario_name"
             --raw_line "profile_link 1.1 STA-AC 10 'DUT: temp Radio-1' tcp-dl-6m-vi wiphy0,AUTO -1"
             --raw_line "profile_link 1.1 upstream 1 'DUT: temp Radio-1' tcp-dl-6m-vi eth1,AUTO -1"

           """)
    parser.add_argument(
        "-m",
        "--lfmgr",
        type=str,
        help="address of the LANforge GUI machine (localhost is default)")
    parser.add_argument(
        "-o",
        "--port",
        type=int,
        default=8080,
        help="IP Port the LANforge GUI is listening on (8080 is default)")
    parser.add_argument(
        "-cs",
        "--create_scenario",
        "--create_lf_scenario",
        type=str,
        help="name of scenario to be created")
    parser.add_argument("-l", "--line", action='append', nargs='+',
                        help="line number", default=[])
    parser.add_argument("-rl", "--raw_line", action='append', nargs=1,
                        help="raw lines", default=[])
    parser.add_argument(
        "-ds",
        "--delete_scenario",
        default=False,
        action='store_true',
        help="delete scenario (by default: False)")
    args = parser.parse_args()

    Create_Chamberview = CreateChamberview(lfmgr=args.lfmgr,
                                           port=args.port,
                                           )
    if args.delete_scenario:
        Create_Chamberview.clean_cv_scenario(
            cv_type="Network-Connectivity",
            scenario_name=args.create_scenario)

    Create_Chamberview.setup(create_scenario=args.create_scenario,
                             line=args.line,
                             raw_line=args.raw_line)
    Create_Chamberview.build(args.create_scenario)


if __name__ == "__main__":
    main()
