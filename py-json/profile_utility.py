# !/usr/bin/env python3
import sys
import os
import importlib
import pandas as pd

if sys.version_info[0] != 3:
    print("This script requires Python 3")
    exit(1)

import argparse
import time

sys.path.append(os.path.join(os.path.abspath(__file__ + "../../../")))

realm = importlib.import_module("py-json.realm")
Realm = realm.Realm
LFUtils = importlib.import_module("py-json.LANforge.LFUtils")


class ProfileUtility(Realm):
    def __init__(self,
                 lfclient_host,
                 lfclient_port,
                 debug_=False):
        super().__init__(lfclient_host, lfclient_port, debug_=debug_)
        self.host = lfclient_host
        self.port = lfclient_port

    def add_profile(self, profile_name=None, profile_type=None, profile_flags=None, vlan_id=100):
        """Add profile"""
        profile_type_data = {"as_is": 0, "sta": 1, "bridged_ap": 2, "routed_ap": 3, "upstream": 4, "monitor": 5,
                             "mobile_sta": 6, "rdd": 7, "client": 8, "bond": 9, "peer": 10, "uplink": 11, "vlan": 12}
        profile_flags_data = {"DHCP-SERVER": "0x1", "NAT": "0x100"}
        data = {
            "name": None,
            "profile_type": None,
            "profile_flags": None
        }
        if profile_name is not None:
            data["name"] = profile_name
        if profile_type is not None:
            if profile_type in profile_type_data:
                data["profile_type"] = profile_type_data[profile_type]
            # vlan id valid for valn profile
            if profile_type.lower() == "vlan":
                data["vid"] = vlan_id
        if profile_flags is not None:
            if profile_flags in profile_flags_data:
                data["profile_flags"] = profile_flags_data[profile_flags]
        print(data)
        response = self.json_post("/cli-json/add_profile", data)
        return response

    def remove_profile(self, name=None):
        """Remove profile"""
        try:
            response = self.json_post("/cli-json/rm_profile", {"name": name})
        except Exception as e:
            print(e)
        return response

    def show_profile(self):
        """Show All Profiles"""
        response = self.json_post("/cli-json/show_profile", {"name": "all"})
        return ""

    def check_profile(self, profile_name):
        return True



def main():
    obj = ProfileUtility(lfclient_host="10.28.3.32", lfclient_port=8080)
    y = obj.show_profile()
    print(y)


if __name__ == "__main__":
    main()
