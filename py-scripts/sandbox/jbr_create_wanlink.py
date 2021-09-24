#!/usr/bin/env python3
'''
NAME: jbr_create_wanlink.py

PURPOSE: create a wanlink

EXAMPLE:
$ ./jbr_create_wanlink.py --host ct521a-jana --wl_name snail

To enable using lf_json_autogen in other parts of the codebase, set LF_USE_AUTOGEN=1:
$ LF_USE_AUTOGEN=1 ./jbr_jag_test.py --test set_port --host ct521a-lion

NOTES:


TO DO NOTES:

'''
import sys

if sys.version_info[0] != 3:
    print("This script requires Python3")
    exit()

sys.path.insert(1, "../../py-json")
import argparse
import pprint
from LANforge.lf_json_autogen import LFSession
from LANforge.lf_json_autogen import LFJsonCommand
from LANforge.lf_json_autogen import LFJsonQuery


# import LANforge.lfcli_base
# from LANforge.lfcli_base import LFCliBase

# ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- #

# ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- #
def main():
    parser = argparse.ArgumentParser(
        prog=__file__,
        formatter_class=argparse.RawTextHelpFormatter,
        description='tests creating wanlink')
    parser.add_argument("--host", help='specify the GUI to connect to, assumes port 8080')
    parser.add_argument("--wl_name", help='name of the wanlink to create')
    parser.add_argument("--resource", help='LANforge resource')
    parser.add_argument("--debug", help='turn on debugging', action="store_true")

    args = parser.parse_args()
    if not args.wl_name:
        print("No wanlink name provided")
        exit(1)

    session = LFSession(lfclient_url="http://%s:8080" % args.host,
                        debug=args.debug,
                        connection_timeout_sec=2.0,
                        stream_errors=True,
                        stream_warnings=True,
                        exit_on_error=True)
    command: LFJsonCommand
    command = session.get_command()
    query: LFJsonQuery
    query = session.get_query()


    command.post_add_rdd(resource=args.resource,
                         port="rd0a",
                         peer_ifname="rd0b",
                         report_timer=1000,
                         shelf=1,
                         debug_=args.debug)

    command.post_add_rdd(resource=args.resource,
                         port="rd1a",
                         peer_ifname="rd1b",
                         report_timer=1000,
                         shelf=1,
                         debug_=args.debug)

    endp_a = args.wl_name + "-A"
    endp_b = args.wl_name + "-B"
    command.post_add_wl_endp(alias=endp_a,
                             resource=args.resource,
                             port="rd0a",
                             shelf=1,
                             debug_=args.debug)
    command.post_add_wl_endp(alias=endp_b,
                             resource=args.resource,
                             port="rd1a",
                             shelf=1,
                             debug_=args.debug)
    command.post_add_cx(alias=args.wl_name,
                        rx_endp=endp_a,
                        tx_endp=endp_b,
                        test_mgr="default_tm",
                        debug_=args.debug)
    ewarn_list = []
    result = query.get_wl(eid_list=(args.wl_name),
                          wait_sec=0.2,
                          timeout_sec=2.0,
                          errors_warnings=ewarn_list,
                          debug=args.debug)
    pprint.pprint(result)
    result = query.get_wl_endp(eid_list=(args.wl_name+"-A", args.wl_name+"-B"),
                               debug=args.debug)
    pprint.pprint(result)


if __name__ == "__main__":
    main()
#
