#!/usr/bin/env python3

import sys
if sys.version_info[0] != 3:
    print("This script requires Python 3")
    exit(1)

if 'py-json' not in sys.path:
    sys.path.append('../py-json')

from LANforge.lfcli_base import LFCliBase
from LANforge.LFUtils import *
from LANforge import LFUtils
import argparse
import realm

class TestGroup(LFCliBase):
    def __init__(self, host, port,
                 group_name=None,
                 add_cx_list=[],
                 rm_cx_list=[],
                 tg_action=None,
                 cx_action=None,
                 list_groups=None,
                 show_group=None):

        self.local_realm = realm.Realm(lfclient_host=host, lfclient_port=port)
        self.tg_profile = self.local_realm.new_test_group_profile()
        if group_name is None and list_groups is None and (tg_action is not None or cx_action is not None or
                                   add_cx_list is not None or rm_cx_list is not None or show_group is not None):
            raise ValueError("Group name must be set if manipulating test groups")
        else:
            self.tg_profile.group_name = group_name

        self.tg_action   = tg_action
        self.cx_action   = cx_action
        self.list_groups = list_groups
        self.show_group  = show_group
        self.add_cx_list = add_cx_list
        self.rm_cx_list  = rm_cx_list

    def do_cx_action(self):
        if self.cx_action == 'start':
            print("Starting %s" % self.tg_profile.group_name)
            self.tg_profile.start_group()
        elif self.cx_action == 'stop':
            print("Stopping %s" % self.tg_profile.group_name)
            self.tg_profile.stop_group()
        elif self.cx_action == 'quiesce':
            print("Quiescing %s" % self.tg_profile.group_name)
            self.tg_profile.quiesce_group()

    def do_tg_action(self):
        if self.tg_action == 'add':
            print("Creating %s" % self.tg_profile.group_name)
            self.tg_profile.create_group()
        if self.tg_action == 'del':
            print("Removing %s" % self.tg_profile.group_name)
            if self.tg_profile.check_group_exists():
                self.tg_profile.remove_group()
            else:
                print("%s not found, no action taken" % self.tg_profile.group_name)

    def show_info(self):
        if self.list_groups:
            print("Current Test Groups: ")
            for group in self.tg_profile.list_groups():
                print(group)
        if self.show_group:
            print("show_group not yet implemented")

    def update_cxs(self):
        if len(self.add_cx_list) > 0:
            for cx in self.add_cx_list:
                self.tg_profile.add_cx(cx)
                self.tg_profile.cx_list.append(cx)
        if len(self.rm_cx_list) > 0:
            for cx in self.rm_cx_list:
                self.tg_profile.rm_cx(cx)
                if cx in self.tg_profile.cx_list:
                    self.tg_profile.cx_list.remove(cx)


def main():
    parser = LFCliBase.create_bare_argparse(
        prog='testgroup.py',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''Control and query test groups\n''',
        description='''testgroup.py
    --------------------
    Generic command example:
    
    ''')

    parser.add_argument('--group_name', help='specify the name of the test group to use', default=None)
    parser.add_argument('--list_groups', help='list all existing test groups', action='store_true', default=False)

    tg_group = parser.add_mutually_exclusive_group()
    tg_group.add_argument('--add_group', help='add new test group', action='store_true', default=False)
    tg_group.add_argument('--del_group', help='delete test group', action='store_true', default=False)
    parser.add_argument('--show_group', help='show connections in current test group', action='store_true', default=False)

    cx_group = parser.add_mutually_exclusive_group()
    cx_group.add_argument('--start_group', help='start all cxs in chosen test group', default=None)
    cx_group.add_argument('--stop_group', help='stop all cxs in chosen test group', default=None)
    cx_group.add_argument('--quiesce_group', help='quiesce all cxs in chosen test groups', default=None)

    parser.add_argument('--add_cx', help='add cx to chosen test group', nargs='*',  default=[])
    parser.add_argument('--remove_cx', help='remove cx from chosen test group', nargs='*', default=[])

    args = parser.parse_args()

    tg_action = None
    cx_action = None

    if args.add_group:
        tg_action = 'add'
    elif args.del_group:
        tg_action = 'del'

    if args.start_group:
        cx_action = 'start'
    elif args.stop_group:
        cx_action = 'stop'
    elif args.quiesce_group:
        cx_action = 'quiesce'

    tg = TestGroup(host=args.mgr, port=args.mgr_port,
              group_name=args.group_name,
              add_cx_list=args.add_cx, rm_cx_list=args.remove_cx, cx_action=cx_action,
              tg_action=tg_action, list_groups=args.list_groups, show_group=args.show_group)

    tg.do_tg_action()
    tg.update_cxs()
    tg.do_cx_action()
    tg.show_info()


if __name__ == "__main__":
    main()