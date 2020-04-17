#!/bin/bash

# Run some automated GUI tests, save the results
# Example of how to run this and override LFMANAGER default settings.  Other values can
# be over-ridden as well.
#
#  LFMANAGER=192.168.100.156 ./basic_regression.bash
#
# Run subset of tests
#  LFMANAGER=192.168.100.156 DEFAULT_ENABLE=0 DO_SHORT_AP_STABILITY_RESET=1 ./basic_regression.bash
#
#

AP_AUTO_CFG_FILE=${AP_AUTO_CFG_FILE:-test_configs/AP-Auto-ap-auto-32-64-dual.txt}
WCT_CFG_FILE=${WCT_CFG_FILE:-test_configs/WCT-64sta.txt}
DPT_CFG_FILE=${DPT_CFG_FILE:-test_configs/dpt-pkt-sz.txt}
SCENARIO_CFG_FILE=${SCENARIO_CFG_FILE:-test_configs/64_sta_scenario.txt}

# LANforge target machine
LFMANAGER=${LFMANAGER:-localhost}

# LANforge GUI machine (may often be same as target)
GMANAGER=${GMANAGER:-localhost}
GMPORT=${GMPORT:-3990}
MY_TMPDIR=${MY_TMPDIR:-/tmp}

# Test configuration (10 minutes by default, in interest of time)
STABILITY_DURATION=${STABILITY_DURATION:-600}
TEST_RIG_ID=${TEST_RIG_ID:-Unspecified}

# Tests to run
DEFAULT_ENABLE=${DEFAULT_ENABLE:-1}
DO_DPT_PKT_SZ=${DO_DPT_PKT_SZ:-$DEFAULT_ENABLE}
DO_WCT_DL=${DO_WCT_DL:-$DEFAULT_ENABLE}
DO_WCT_UL=${DO_WCT_UL:-$DEFAULT_ENABLE}
DO_WCT_BI=${DO_WCT_BI:-$DEFAULT_ENABLE}
DO_SHORT_AP_BASIC_CX=${DO_SHORT_AP_BASIC_CX:-$DEFAULT_ENABLE}
DO_SHORT_AP_TPUT=${DO_SHORT_AP_TPUT:-$DEFAULT_ENABLE}
DO_SHORT_AP_STABILITY_RESET=${DO_SHORT_AP_STABILITY_RESET:-$DEFAULT_ENABLE}
DO_SHORT_AP_STABILITY_RADIO_RESET=${DO_SHORT_AP_STABILITY_RADIO_RESET:-$DEFAULT_ENABLE}
DO_SHORT_AP_STABILITY_NO_RESET=${DO_SHORT_AP_STABILITY_NO_RESET:-$DEFAULT_ENABLE}

DATESTR=$(date +%F-%T)
RSLTS_DIR=${RSLTS_DIR:-basic_regression_results_$DATESTR}


# Probably no config below here
AP_AUTO_CFG=ben
WCT_CFG=ben
DPT_CFG=ben
SCENARIO=64sta
RPT_TMPDIR=${MY_TMPDIR}/lf_reports

mkdir -p $RSLTS_DIR

set -x
# Load scenario file
../lf_testmod.pl --mgr $LFMANAGER --action set --test_type Network-Connectivity --test_name $SCENARIO --file $SCENARIO_CFG_FILE

# Load AP-Auto config file
../lf_testmod.pl --mgr $LFMANAGER --action set --test_name AP-Auto-$AP_AUTO_CFG --file $AP_AUTO_CFG_FILE

# Load Wifi Capacity config file
../lf_testmod.pl --mgr $LFMANAGER --action set --test_name Wifi-Capacity-$WCT_CFG --file $WCT_CFG_FILE

# Load Dataplane config file
../lf_testmod.pl --mgr $LFMANAGER --action set --test_name dataplane-test-latest-$DPT_CFG --file $DPT_CFG_FILE

# Make sure GUI is synced up with the server
../lf_gui_cmd.pl --manager $GMANAGER --port $GMPORT --cmd "cli show_text_blob"

# Pause to let GUI finish getting data from the server
sleep 10

# Tell GUI to load and build the scenario
../lf_gui_cmd.pl --manager $GMANAGER --port $GMPORT --scenario $SCENARIO

# Clean out temp report directory
if [ -d $RPT_TMPDIR ]
then
    rm -fr $RPT_TMPDIR/*
fi

# Do dataplane pkt size test
echo "Checking if we should run Dataplane packet size test."
if [ "_$DO_DPT_PKT_SZ" == "_1" ]
then
    ../lf_gui_cmd.pl --manager $GMANAGER --port $GMPORT --ttype "Dataplane" --tname dpt-ben  --tconfig $DPT_CFG \
        --modifier_key "Test Rig ID:" --modifier_val "$TEST_RIG_ID" \
        --modifier_key "Show Low-Level Graphs" --modifier_val true \
        --rpt_dest $RPT_TMPDIR > $MY_TMPDIR/basic_regression_log.txt 2>&1
    mv $RPT_TMPDIR/* $RSLTS_DIR/dataplane_pkt_sz
    mv $MY_TMPDIR/basic_regression_log.txt $RSLTS_DIR/dataplane_pkt_sz/test_automation.txt
fi

# Do capacity test
echo "Checking if we should run WCT Download test."
if [ "_$DO_WCT_DL" == "_1" ]
then
    ../lf_gui_cmd.pl --manager $GMANAGER --port $GMPORT --ttype "WiFi Capacity" --tname wct-ben  --tconfig $WCT_CFG \
        --modifier_key "Test Rig ID:" --modifier_val "$TEST_RIG_ID" \
        --modifier_key "RATE_DL" --modifier_val "1Gbps" \
        --modifier_key "RATE_UL" --modifier_val "0" \
        --rpt_dest $RPT_TMPDIR > $MY_TMPDIR/basic_regression_log.txt 2>&1
    mv $RPT_TMPDIR/* $RSLTS_DIR/wifi_capacity_dl
    mv $MY_TMPDIR/basic_regression_log.txt $RSLTS_DIR/wifi_capacity_dl/test_automation.txt
fi

echo "Checking if we should run WCT Upload test."
if [ "_$DO_WCT_UL" == "_1" ]
then
    ../lf_gui_cmd.pl --manager $GMANAGER --port $GMPORT --ttype "WiFi Capacity" --tname wct-ben  --tconfig $WCT_CFG \
        --modifier_key "Test Rig ID:" --modifier_val "$TEST_RIG_ID" \
        --modifier_key "RATE_UL" --modifier_val "1Gbps" \
        --modifier_key "RATE_DL" --modifier_val "0" \
        --rpt_dest $RPT_TMPDIR > $MY_TMPDIR/basic_regression_log.txt 2>&1
    mv $RPT_TMPDIR/* $RSLTS_DIR/wifi_capacity_ul
    mv $MY_TMPDIR/basic_regression_log.txt $RSLTS_DIR/wifi_capacity_ul/test_automation.txt
fi

echo "Checking if we should run WCT Bi-Direction test."
if [ "_$DO_WCT_BI" == "_1" ]
then
    ../lf_gui_cmd.pl --manager $GMANAGER --port $GMPORT --ttype "WiFi Capacity" --tname wct-ben  --tconfig $WCT_CFG \
        --modifier_key "Test Rig ID:" --modifier_val "$TEST_RIG_ID" \
        --modifier_key "RATE_UL" --modifier_val "1Gbps" \
        --modifier_key "RATE_DL" --modifier_val "1Gbps" \
        --modifier_key "Protocol:" --modifier_val "TCP-IPv4" \
        --rpt_dest $RPT_TMPDIR > $MY_TMPDIR/basic_regression_log.txt 2>&1
    mv $RPT_TMPDIR/* $RSLTS_DIR/wifi_capacity_bi
    mv $MY_TMPDIR/basic_regression_log.txt $RSLTS_DIR/wifi_capacity_bi/test_automation.txt
fi


# Run basic-cx test
echo "Checking if we should run Short-AP Basic CX test."
if [ "_$DO_SHORT_AP_BASIC_CX" == "_1" ]
then
    ../lf_gui_cmd.pl --manager $GMANAGER --port $GMPORT --ttype "AP-Auto" --tname ap-auto-ben --tconfig $AP_AUTO_CFG \
        --rpt_dest $RPT_TMPDIR > $MY_TMPDIR/basic_regression_log.txt 2>&1
    mv $RPT_TMPDIR/* $RSLTS_DIR/ap_auto_basic_cx
    mv $MY_TMPDIR/basic_regression_log.txt $RSLTS_DIR/ap_auto_basic_cx/test_automation.txt
fi

# Run Throughput, Dual-Band, Capacity test in a row, the Capacity will use results from earlier
# tests.
echo "Checking if we should run Short-AP Throughput test."
if [ "_$DO_SHORT_AP_TPUT" == "_1" ]
then
    ../lf_gui_cmd.pl --manager $GMANAGER --port $GMPORT --ttype "AP-Auto" --tname ap-auto-ben --tconfig $AP_AUTO_CFG \
        --modifier_key "Basic Client Connectivity" --modifier_val false \
        --modifier_key "Throughput vs Pkt Size" --modifier_val true \
        --modifier_key "Dual Band Performance" --modifier_val true \
        --modifier_key "Capacity" --modifier_val true \
        --rpt_dest $RPT_TMPDIR > $MY_TMPDIR/basic_regression_log.txt 2>&1
    mv $RPT_TMPDIR/* $RSLTS_DIR/ap_auto_capacity
    mv $MY_TMPDIR/basic_regression_log.txt $RSLTS_DIR/ap_auto_capacity/test_automation.txt
fi

# Run Stability test (single port resets, voip, tcp, udp)
echo "Checking if we should run Short-AP Stability Reset test."
if [ "_$DO_SHORT_AP_STABILITY_RESET" == "_1" ]
then
    ../lf_gui_cmd.pl --manager $GMANAGER --port $GMPORT --ttype "AP-Auto" --tname ap-auto-ben --tconfig $AP_AUTO_CFG \
        --modifier_key "Basic Client Connectivity" --modifier_val false \
        --modifier_key "Stability" --modifier_val true \
        --modifier_key "Stability Duration:" --modifier_val $STABILITY_DURATION \
        --rpt_dest  $RPT_TMPDIR > $MY_TMPDIR/basic_regression_log.txt 2>&1
    mv $RPT_TMPDIR/* $RSLTS_DIR/ap_auto_stability_reset_ports
    mv $MY_TMPDIR/basic_regression_log.txt $RSLTS_DIR/ap_auto_stability_reset_ports/test_automation.txt
fi

# Run Stability test (radio resets, voip, tcp, udp)
echo "Checking if we should run Short-AP Stability Radio Reset test."
if [ "_$DO_SHORT_AP_STABILITY_RADIO_RESET" == "_1" ]
then
    ../lf_gui_cmd.pl --manager $GMANAGER --port $GMPORT --ttype "AP-Auto" --tname ap-auto-ben --tconfig $AP_AUTO_CFG \
        --modifier_key "Basic Client Connectivity" --modifier_val false \
        --modifier_key "Stability" --modifier_val true \
        --modifier_key "Stability Duration:" --modifier_val $STABILITY_DURATION \
        --modifier_key "Reset Radios" --modifier_val true \
        --rpt_dest  $RPT_TMPDIR > $MY_TMPDIR/basic_regression_log.txt 2>&1
    mv $RPT_TMPDIR/* $RSLTS_DIR/ap_auto_stability_reset_radios
    mv $MY_TMPDIR/basic_regression_log.txt $RSLTS_DIR/ap_auto_stability_reset_radios/test_automation.txt
fi

# Run Stability test (no resets, no voip, tcp, udp)
echo "Checking if we should run Short-AP Stability No-Reset test."
if [ "_$DO_SHORT_AP_STABILITY_NO_RESET" == "_1" ]
then
    ../lf_gui_cmd.pl --manager $GMANAGER --port $GMPORT --ttype "AP-Auto" --tname ap-auto-ben --tconfig $AP_AUTO_CFG \
        --modifier_key "Basic Client Connectivity" --modifier_val false \
        --modifier_key "Stability" --modifier_val true \
        --modifier_key "Stability Duration:" --modifier_val $STABILITY_DURATION \
        --modifier_key "VOIP Call Count:" --modifier_val 0 \
        --modifier_key "Concurrent Ports To Reset:" --modifier_val 0 \
        --rpt_dest  $RPT_TMPDIR > $MY_TMPDIR/basic_regression_log.txt 2>&1
    mv $RPT_TMPDIR/* $RSLTS_DIR/ap_auto_stability_no_reset
    mv $MY_TMPDIR/basic_regression_log.txt $RSLTS_DIR/ap_auto_stability_no_reset/test_automation.txt
fi

echo "Done with regression test."
