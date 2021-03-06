#!/bin/bash
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
#  Check for large files and purge many of the most inconsequencial       #
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
# set -x
# set -e
# these are default selections
selections=()
deletion_targets=()
show_menu=1
verbose=0
quiet=0
starting_dir="$PWD"

USAGE="$0 # Check for large files and purge many of the most inconsequencial
 -a   # automatic: disable menu and clean automatically
 -b   # remove extra kernels and modules
 -c   # remove all core files
 -d   # remove old LANforge downloads
 -h   # help
 -k   # remove ath10k crash files
 -l   # remove old files from /var/log, truncate /var/log/messages
 -m   # remove orphaned fileio items in /mnt/lf
 -q   # quiet
 -r   # compress .csv data in /home/lanforge
 -t   # remove /var/tmp files
 -v   # verbose

"

eyedee=`id -u`
if (( eyedee != 0 )); then
    echo "$0: Please become root to use this script, bye"
    exit 1
fi

debug() {
    if [[ x$verbose = x ]] || (( $verbose < 1 )); then return; fi
    echo ": $1"
}

note() {
    if (( $quiet > 0 )); then return; fi
    echo "# $1"
}

function contains () {
    if [[ x$1 = x ]] || [[ x$2 = x ]]; then
        echo "contains wants ARRAY and ITEM arguments: if contains name joe; then...  }$"
        exit 1
    fi
    # these two lines below are important to not modify
    local tmp="${1}[@]"
    local array=( ${!tmp} )

    # if [[ x$verbose = x1 ]]; then
    #    printf "contains array %s\n" "${array[@]}"
    # fi
    if (( ${#array[@]} < 1 )); then
        return 1
    fi
    local item
    for item in "${array[@]}"; do
        # debug "contains testing $2 == $item"
        [[ "$2" = "$item" ]] && return 0
    done
    return 1
}

#opts=""
opts="abcdhklmqrtv"
while getopts $opts opt; do
  case "$opt" in
    a)
      verbose=0
      quiet=1
      selections+=($opt)
      show_menu=0
      ;;
    b)
      selections+=($opt)
      ;;
    c)
      selections+=($opt)
      ;;
    d)
      selections+=($opt)
      ;;
    h)
      echo "$USAGE"
      exit 0
      ;;
    k)
      selections+=($opt)
      ;;
    l)
      selections+=($opt)
      ;;
    m)
      selections+=($opt)
      ;;
    r)
      selections+=($opt)
      ;;
    q)
      quiet=1
      verbose=0
      ;;
    t)
      selections+=($opt)
      ;;
    v)
      quiet=0
      verbose=1
      ;;
    *)
      echo "unknown option: $opt"
      echo "$USAGE"
      exit 1
      ;;
  esac
done

#if (( ${#selections} < 1 )); then
#  echo "$USAGE"
#  exit 0
#fi

HR=" ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- -----"
function hr() {
  echo "$HR"
}

declare -A totals=(
    [b]=0
    [c]=0
    [d]=0
    [k]=0
    [l]=0
    [m]=0
    [r]=0
    [t]=0
)
declare -A desc=(
    [b]="kernel files"
    [c]="core files"
    [d]="lf downloads"
    [k]="lf/ath10 files"
    [l]="/var/log"
    [m]="/mnt/lf files"
    [n]="DNF cache"
    [r]="/home/lanforge/report_data"
    [t]="/var/tmp"
)
declare -A surveyors_map=(
    [b]="survey_kernel_files"
    [c]="survey_core_files"
    [d]="survey_lf_downloads"
    [k]="survey_ath10_files"
    [l]="survey_var_log"
    [m]="survey_mnt_lf_files"
    [n]="survey_dnf_cache"
    [r]="survey_report_data"
    [t]="survey_var_tmp"
)

declare -A cleaners_map=(
    [b]="clean_old_kernels"
    [c]="clean_core_files"
    [d]="clean_lf_downloads"
    [k]="clean_ath10_files"
    [l]="clean_var_log"
    [m]="clean_mnt_lf_files"
    [n]="clean_dnf_cache"
    [r]="compress_report_data"
    [t]="clean_var_tmp"
)

kernel_to_relnum() {
    #set -euxv
    local hunks=()
    # 1>&2 echo "KERNEL RELNUM:[$1]"
    local my1="${1/*[^0-9+]-/}" # Dang, this is not intuitive to a PCRE user
    #1>&2 echo "KERNEL [$1] REGEX:[$my1]"
    if [[ $my1 =~ ^[^0-9] ]]; then
        1>&2 echo "BAD SERIES: [$1]"
        exit 1
    fi
    IFS="." read -ra hunks <<< "$my1"
    IFS=
    local tmpstr
    local max_width=8
    local last_len=0
    local expandos=()
    for i in 0 1 2; do
        if (( $i < 2 )); then
            #1>&2 echo "HUNK $i: [${hunks[$i]}]"
            expandos+=( $(( 100 + ${hunks[$i]} )) )
        else
            tmpstr="00000000${hunks[i]}"
            last_len=$(( ${#tmpstr} - $max_width ))
            expandos+=( ${tmpstr:$last_len:${#tmpstr}} )
            #1>&2 echo "TRIMMED ${tmpstr:$last_len:${#tmpstr}}"
        fi
    done

    set +x
    #1>&2 echo "EXPANDO: ${expandos[0]}${expandos[1]}${expandos[2]}"
    echo "k${expandos[0]}${expandos[1]}${expandos[2]}"

}

clean_old_kernels() {
    note "Cleaning old CT kernels..."
    local f
    if (( ${#removable_packages[@]} > 0 )); then
        for f in "${removable_packages[@]}"; do
            echo "$f\*"
        done | xargs /usr/bin/rpm -hve
    fi
    if (( ${#removable_kernels[@]} > 0 )); then
        for f in "${removable_kernels[@]}"; do
            echo "$f"
        done | xargs rm -f
    fi

    if (( ${#removable_libmod_dirs[@]} > 0 )); then
        printf "        removable_libmod_dirs[/lib/modules/%s]\n" "${removable_libmod_dirs[@]}"
        for f in "${removable_libmod_dirs[@]}"; do
            echo "/lib/modules/$f"
        done | xargs rm -rf
    fi
}

clean_core_files() {
    note "Cleaning core files..."
    if (( ${#core_files[@]} < 1 )); then
        debug "No core files ?"
        return 0
    fi
    local counter=0
    for f in "${core_files[@]}"; do
        echo -n "-"
        rm -f "$f"
        counter=$(( counter + 1 ))
        if (( ($counter % 100) == 0 )); then
            sleep 0.2
        fi
    done
    echo ""
}

clean_lf_downloads() {
    if (( ${#lf_downloads[@]} < 1 )); then
        note "No /home/lanforge/downloads files to remove"
        return 0
    fi
    note "Clean LF downloads..."
    if (( $verbose > 0 )); then
        echo "Would Delete: "
        printf "[%s] " "${lf_downloads[@]}" | sort
    fi
    cd /home/lanforge/Downloads
    for f in "${lf_downloads[@]}"; do
        [[ "$f" = "/" ]] && echo "Whuuut? this is not good, bye." && exit 1
        # echo "Next:[$f]"
        sleep 0.02
        rm -f "$f"
    done
    cd "$starting_dir"
}

clean_ath10_files() {
    note "clean_ath10_files WIP"
    local f
    while read f; do
        echo "removing $f"
        rm -f "$f"
    done < <( find /home/lanforge -type f -iname "ath10*")
}

clean_var_log() {
    note "Vacuuming journal..."
    journalctl --vacuum-size 1M
    if (( ${#var_log_files[@]} < 1 )); then
        note "No notable files in /var/log to remove"
        return
    fi
    local vee=""
    if (( $verbose > 0 )); then
        printf "%s\n" "${var_log_files[@]}"
        vee="-v"
    fi
    cd /var/log
    while read file; do
        if [[ $file = /var/log/messages ]]; then
            echo "" > /var/log/messages
        else
            rm -f $vee "$file"
        fi
    done <<< "${var_log_files[@]}"
    cd "$starting_dir"
}

clean_dnf_cache() {
    local yum="dnf"
    which --skip-alias dnf &> /dev/null
    (( $? < 0 )) && yum="yum"
    debug "Purging $yum cache"
    $yum clean all
}

clean_mnt_lf_files() {
    note "clean mnt lf files WIP"
    if (( $verbose > 0 )); then
        printf "%s\n" "${mnt_lf_files[@]}"
    fi
}

compress_report_data() {
    note "compress report data..."
    # local csvfiles=( $( find /home/lanforge -iname "*.csv"  -print0 ))
    while read f; do
        (( $verbose > 0 )) && echo "    compressing $f"
        gzip -9 "$f"
    done < <(find /home/lanforge -iname "*.csv")
}

clean_var_tmp() {
    note "clean var tmp"
    if (( $verbose > 0 )); then
        printf "    %s\n" "${var_tmp_files[@]}"
        sleep 1
    fi
    for f in "${var_tmp_files[@]}"; do
        rm -f "$f"
        sleep 0.2
    done
}

kernel_files=()         # temp
lib_module_dirs=()      # temp
declare -A kernel_sort_names
declare -A pkg_sort_names
declare -A libmod_sort_names
removable_kernels=()    # these are for CT kernels
removable_libmod_dirs=() # these are for CT kernels
removable_packages=()   # these are for Fedora kernels
removable_pkg_series=()
survey_kernel_files() {
    unset removable_kernels
    unset removable_libmod_dirs
    unset removable_packages
    unset lib_module_dirs
    unset kernel_sort_names
    unset kernel_sort_serial
    unset pkg_sort_names
    unset libmod_sort_names
    declare -A kernel_sort_names=()
    declare -A pkg_sort_names=()
    declare -A libmod_sort_names=()
    local ser
    local file
    debug "Surveying Kernel files"
    mapfile -t kernel_files < <(find /boot -maxdepth 1 -type f -a \( \
        -iname "System*" -o -iname "init*img" -o -iname "vm*" -o -iname "ct*" \) \
        2>/dev/null | grep -v rescue | sort)
    mapfile -t lib_module_dirs < <(find /lib/modules -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
    local booted=`uname -r`

    note "** You are running kernel $booted **"
    # set -veux
    local file
    local fiile
    for file in "${kernel_files[@]}"; do
        # echo "kernel_file [$file]"
        [[ $file =~ /boot/initramfs* ]] && continue
        [[ $file =~ *.fc*.x86_64 ]] && continue
        fiile=$( basename $file )
        fiile=${fiile%.img}

        if [[ $fiile =~ $booted ]]; then
            debug "    ignoring booted CT kernel $file"
            sleep 2
            continue
        else
            ser=$( kernel_to_relnum ${fiile#*ct} )
            kernel_sort_serial[$ser]=1
            # debug "file[$file] ser[$ser]"
            kernel_sort_names["$file"]="$ser"
            removable_kernels+=($file)
        fi
    done
    sleep 2
    local booted_ser=$( kernel_to_relnum $booted )
    if (( ${#kernel_sort_names[@]} > 0 )); then
        declare -A ser_files
        for file in "${!kernel_sort_names[@]}"; do
            ser="${kernel_sort_names[$file]}"
        done
        debug "Removable CT kernels:"
        while read ser; do
            (( $verbose > 0 )) && printf "    kernel file [%s]\n" "${kernel_sort_names[$ser]}"
            removable_kernels+=(${kernel_sort_names["$ser"]})
        done < <(echo  "${!kernel_sort_names[@]}" | sort | head -n -1)
    fi

    debug "Module directories elegible for removal: "
    for file in "${lib_module_dirs[@]}"; do
        file=${file#/lib/modules/}
        # debug "/lib/modules/ ... $file"
        if [[ $file =~ $booted ]]; then
            debug "     Ignoring booted module directory $file"
            continue
        elif [[ $file = *.fc??.x86_64 ]]; then
            debug "     Ignoring Fedora module directory $file"
            continue
        else
            ser=$( kernel_to_relnum $file )
            # debug "     eligible [$ser] -> $file"
            libmod_sort_names[$ser]="$file"
        fi
    done

    if (( $verbose > 0 )) && (( ${#libmod_sort_names[@]} > 0 )); then
        # debug "Removable libmod dirs: "
        while read ser; do
            file="${libmod_sort_names[$ser]}"
            # debug "     $ser -> $file"
            if [[ $file =~ $booted ]]; then
                debug "     Ignoring booted $booted module directory $file"
                continue
            fi
            removable_libmod_dirs+=( "$file" )
            # echo "    [$ser][${libmod_sort_names[$ser]}] -> $file"
        done < <( printf "%s\n" "${!libmod_sort_names[@]}" | sort | uniq)
        # we don't need to sort these ^^^ because they were picked out near line 419
    fi
    #if (( $verbose > 0 )); then
    #    printf " removable_libmod_dirs: %s\n" "${removable_libmod_dirs[@]}"
    #fi
    # set +veux

    local boot_image_sz=$(du -hc "${kernel_files[@]}" | awk '/total/{print $1}')
    local lib_dir_sz=$(du -hc "${lib_module_dirs[@]}" | awk '/total/{print $1}')
    totals[b]="kernels: $boot_image_sz, modules: $lib_dir_sz"

    local pkg
    local k_pkgs=()
    removable_pkg_series=()

    # need to avoid most recent fedora kernel
    if [ ! -x /usr/bin/rpm ]; then
        note "Does not appear to be an rpm system."
        return 0
    fi
    local ur=$( uname -r )
    local kern_pkgs=( $( rpm -qa 'kernel*' | sort ) )
    local ser
    local zpkg
    declare -A pkg_to_ser
    for pkg in "${kern_pkgs[@]}"; do
        if [[ $pkg = kernel-tools-* ]] \
            || [[ $pkg = kernel-headers-* ]] \
            || [[ $pkg = kernel-devel-* ]] ; then
            continue
        fi
        if [[ $pkg =~ $booted ]]; then
            debug "     ignoring current kernel [$pkg]"
            continue
        fi
        k_pkgs+=( $pkg )
    done

    for pkg in "${k_pkgs[@]}"; do
        zpkg="$pkg"
        zpkg=${pkg##kernel-modules-extra-}
        zpkg=${pkg##kernel-modules-}
        zpkg=${pkg##kernel-core-}
        zpkg=${pkg%.fc??.x86_64}

        if [[ $zpkg =~ $booted ]]; then
            continue
        fi
        kernel_series=$( kernel_to_relnum ${zpkg##kernel-} )

        pkg_to_ser[$pkg]="$kernel_series"
        pkg_sort_names[$kernel_series]=1
    done

    while read ser; do
        # debug "    can remove series [$ser] "
        removable_pkg_series+=($ser)
    done < <( printf "%s\n" "${!pkg_sort_names[@]}" | sort | head -n -1)

    for pkg in "${k_pkgs[@]}"; do
        pkg=${pkg%.fc??.x86_64}
        ser=$( kernel_to_relnum $pkg )
        for zpkg in "${removable_pkg_series[@]}"; do
            if (( $ser == $zpkg )); then
                removable_packages+=($pkg)
            fi
        done
    done

    set +x
    if (( $quiet < 1 )); then
        if (( ${#removable_packages[@]} > 0 )); then
            echo "Removable packages "
            printf "    %s\n" "${removable_packages[@]}"
        fi
        if (( ${#removable_kernels[@]} > 0 )); then
            echo "Removable kernel files "
            printf "    %s\n" "${removable_kernels[@]}"
        fi
        if (( ${#removable_libmod_dirs[@]} > 0 )); then
            echo "Removable /lib/module directories "
            printf "    %s\n" "${removable_libmod_dirs[@]}"
        fi
    fi
} # ~survey_kernel_files

# Find core files
core_files=()
survey_core_files() {
    debug "Surveying core files"
    cd /
    mapfile -t core_files < <(ls /core* /home/lanforge/core* 2>/dev/null) 2>/dev/null
    if [[ $verbose = 1 ]] && (( ${#core_files[@]} > 0 )); then
        printf "    %s\n" "${core_files[@]}" | head
    fi
    if (( ${#core_files[@]} > 0 )); then
        totals[c]=$(du -hc "${core_files[@]}" | awk '/total/{print $1}')
    fi
    #set +x
    [[ x${totals[c]} = x ]] && totals[c]=0
    cd "$starting_dir"
}

# downloads
lf_downloads=()
survey_lf_downloads() {
    debug "Surveying /home/lanforge downloads"
    [ ! -d "/home/lanforge/Downloads" ] && note "No downloads folder " && return 0
    cd /home/lanforge/Downloads
    mapfile -t lf_downloads < <(ls *gz *z2 *-Installer.exe *firmware* kinst_* *Docs* 2>/dev/null)
    totals[d]=$(du -hc "${lf_downloads[@]}" | awk '/total/{print $1}')
    [[ x${totals[d]} = x ]] && totals[d]=0
    cd "$starting_dir"
}

# Find ath10k crash residue
ath10_files=()
survey_ath10_files() {
    debug "Surveying ath10 crash files"
    mapfile -t ath10_files < <(ls /home/lanforge/ath10* 2>/dev/null)
    totals[k]=$(du -hc "${ath10_files}" 2>/dev/null | awk '/total/{print $1}')
    [[ x${totals[k]} = x ]] && totals[k]=0
}

# stuff in var log
var_log_files=()
survey_var_log() {
    debug "Surveying var log"
    mapfile -t var_log_files < <(find /var/log -type f -size +35M \
        -not \( -path '*/journal/*' -o -path '*/sa/*' -o -path '*/lastlog' \) 2>/dev/null)
    totals[l]=$(du -hc "${var_log_files}" 2>/dev/null | awk '/total/{print $1}' )
    [[ x${totals[l]} = x ]] && totals[l]=0
}

# stuff in var tmp
var_tmp_files=()
survey_var_tmp() {
    debug "Surveying var tmp"
    mapfile -t var_tmp_files < <(find /var/tmp -type f 2>/dev/null)
    totals[t]=$(du -sh "${var_tmp_files}" 2>/dev/null | awk '/total/{print $1}' )
    [[ x${totals[t]} = x ]] && totals[t]=0
}

# Find size of /mnt/lf that is not mounted
mnt_lf_files=()
survey_mnt_lf_files() {
    [ ! -d /mnt/lf ] && return 0
    debug "Surveying mnt lf"
    mapfile -t mnt_lf_files < <(find /mnt/lf -type f --one_filesystem 2>/dev/null)
    totals[m]=$(du -xhc "${mnt_lf_files[@]}" 2>/dev/null | awk '/total/{print $1}')
    [[ x${totals[m]} = x ]] && totals[m]=0
}

survey_dnf_cache() {
    local yum="dnf"
    which --skip-alias dnf &> /dev/null
    (( $? < 0 )) && yum="yum"
    debug "Surveying $yum cache"
    totals[n]=$(du -hc '/var/cache/{dnf,yum}' 2>/dev/null | awk '/total/{print $1}')
}

## Find size of /lib/modules
# cd /lib/modules
# mapfile -t usage_libmod < <(du -sh *)

# Find how many kernels are installed
# cd /boot
# mapfile -t boot_kernels < <(ls init*)
# boot_usage=`du -sh .`

report_files=()
survey_report_data() {
    debug "Surveying for lanforge report data"
    cd /home/lanforge
    # set -veux
    local fsiz=0
    local fnum=$( find -type f -a -name '*.csv' 2>/dev/null ||: | wc -l )
    # if (( $verbose > 0 )); then
        # hr
        # find -type f -a -name '*.csv' 2>/dev/null ||:
        # hr
        # sleep 10
        # if (( $fnum > 0 )); then
        #     hr
        #     find -type f -a -name '*.csv' -print0 2>/dev/null ||: | xargs -0 du -hc
        #     hr
        #     sleep 10
        # fi
    # fi
    if (( $fnum > 0 )); then
        fsiz=$( find -type f -name '*.csv' -print0 2>/dev/null | xargs -0 du -hc | awk '/total/{print $1}')
    fi
    # set +veux
    totals[r]="CSV: $fnum files, $fsiz"
    [[ x${totals[r]} = x ]] && totals[r]=0
    # report_files=("CSV files: $fnum tt $fsiz")
    cd "$starting_dir"
}


# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
#       gather usage areas
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
survey_areas() {
    local area
    note "Surveying..."
    for area in "${!surveyors_map[@]}"; do
        if (( $quiet < 1 )) && (( $verbose < 1 )); then
            echo -n "#"
        fi
        ${surveyors_map[$area]}
    done
    if (( $quiet < 1 )) && (( $verbose < 1 )); then
        echo ""
    fi
}

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
#       report sizes here                                                 #
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
disk_usage_report() {
    for k in "${!totals[@]}"; do
        echo -e "\t${desc[$k]}:\t${totals[$k]}"
    done
}
survey_areas
disk_usage_report

if (( ${#core_files[@]} > 0 )); then
    hr
    note "${#core_files[@]} Core Files detected:"
    filestr=""
    declare -A core_groups
    # set -e
    # note that the long pipe at the bottom of the loop is the best way to get
    # the system to operate with thousands of core files
    while read group7; do
        (( $verbose > 0 )) && echo -n '+'
        group7="${group7%, *}"
        group7="${group7//\'/}"
        [[ ${core_groups[$group7]+_} != _ ]] && core_groups[$group7]=0
        core_groups[$group7]=$(( ${core_groups[$group7]} + 1 ))
    done < <(echo "${core_files[@]}" | xargs file | awk -F": " '/execfn:/{print $7}')
    echo ""
    echo "These types of core files were found:"
    for group in "${!core_groups[@]}"; do
        echo "${core_groups[$group]} files of $group"
    done | sort -n
    hr
    (( ${#core_files[@]} > 0 )) && selections+=("c")
fi

#echo "Usage of /mnt: $usage_mnt"
#echo "Usage of /lib/modules: $usage_libmod"
#echo "Boot usage: $boot_usage"

#if (( ${#boot_kernels[@]} > 1 )); then
#    echo "Boot ramdisks:"
#    hr
#    printf '     %s\n' "${boot_kernels[@]}"
#    hr
#fi

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
#   delete extra things now                                               #
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #

if contains "selections" "a" ; then
    note "Automatic deletion will include: "
    printf "%s\n" "${selections[@]}"
    debug "Doing automatic cleanup"
    for z in "${selections[@]}"; do
        debug "Will perform ${desc[$z]}"
        ${cleaners_map[$z]}
    done
    survey_areas
    disk_usage_report
    exit 0
fi

if (( ${#selections[@]} > 0 )) ; then
    debug "Doing selected cleanup: "
    printf "    %s\n" "${selections[@]}"
    sleep 1
    for z in "${selections[@]}"; do
        debug "Performing ${desc[$z]}"
        ${cleaners_map[$z]}
        selections=("${selections[@]/$z}")
    done
    survey_areas
    disk_usage_report
else
    debug "No selections present"
fi

# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
#   ask for things to remove if we are interactive                        #
# ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- #
choice=""
refresh=0
while [[ $choice != q ]]; do
    hr
    #abcdhklmqrtv
    echo "Would you like to delete? "
    echo "  b) old kernels                : ${totals[b]}"
    echo "  c) core crash files           : ${totals[c]}"
    echo "  d) old LANforge downloads     : ${totals[d]}"
    echo "  k) ath10k crash files         : ${totals[k]}"
    echo "  l) old /var/log files         : ${totals[l]}"
    echo "  m) orphaned /mnt/lf files     : ${totals[m]}"
    echo "  n) purge dnf/yum cache        : ${totals[n]}"
    echo "  r) compress .csv files        : ${totals[r]}"
    echo "  t) clean /var/tmp             : ${totals[t]}"
    echo "  q) quit"
    read -p "> " choice
    refresh=0
    case "$choice" in
    b )
        clean_old_kernels
        refresh=1
        ;;
    c )
        clean_core_files
        refresh=1
        ;;
    d )
        clean_lf_downloads
        refresh=1
        ;;
    k )
        clean_ath10_files
        refresh=1
        ;;
    l )
        clean_var_log
        refresh=1
        ;;
    m )
        clean_mnt_lf_files
        refresh=1
        ;;
    r )
        compress_report_data
        refresh=1
        ;;
    t )
        clean_var_tmp
        refresh=1
        ;;
    q )
        break
        ;;
    * )
        echo "not an option [$choice]"
        ;;
    esac
    if (( $refresh > 0 )) ; then
        survey_areas
        disk_usage_report
    fi
done


echo bye
