#!/bin/bash

# Script path setup
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE}")
SCRIPT_DIR=$(dirname -- "$SCRIPT_PATH")
SCRIPT_BASENAME=$(basename -- "$SCRIPT_PATH" .sh)
# Constants
ESC=$'\e'
BOLD="${ESC}[1m"
RESET="${ESC}[0m"
RED="${ESC}[31m"
GREEN="${ESC}[32m"
BLUE="${ESC}[34m"
UNDERLINE="${ESC}[4m"

# IMPORTS
source "${SCRIPT_DIR}/lib/isValidIP.sh"
source "${SCRIPT_DIR}/lib/isPrivateIP.sh"

declare -A CONFIG=(
  [logLvl]=1
  [mailTo]="strato-report@freenet.de" # not used
  [mailSubj]="[strato-report] New Connection Detected" # not used
)

declare -A FILES=(
  [ignoreIPs]="${SCRIPT_DIR}/ignore_ips.txt"
  [ignoreDomains]="${SCRIPT_DIR}/ignore_domains.txt"
  [log]="${SCRIPT_DIR}/${SCRIPT_BASENAME}.log" # not used
  [ufwLog]="/var/log/ufw.log" # not used
)

# defaults for cli args
INTERACTIVE=0
TIME_SPAN="today"
declare -A IP_FILTER
declare -A PORT_FILTER

# global arrays for results
declare -A ALIEN_SRC_IPS_MAP
declare -A ALIEN_DST_IPS_MAP
declare -a OUT_LOGS 
declare -a IN_LOGS
declare -A OUT_PORTS_MAP 
declare -A IN_PORTS_MAP
declare -A PRE_FILTER_IPS

function parseArguments() {

  #local args="${@}"

  while [[ ${#} -gt 0 ]]; do
    case ${1} in
    -i | --interactive)
      INTERACTIVE=1
      shift
      ;;
    -t | --time)
      TIME_SPAN="${2}"
      shift 2
      ;;
    -p | --port)
      PORT_FILTER[$2]=1
      shift 2
      ;;
    --ip)
      IP_FILTER[$2]=1
      shift 2
      ;;
    *)
      echo "Unknown option: ${1}"
      exit 1
      ;;
    esac
  done
}

function initPreFilterIPs() {
	# TASK:
	# Initialize associative array preFilterIPs for O(1) lookup

	# REQUIRES:
	# preFilterIPs (associative array)

  local -n preFilterIPs=PRE_FILTER_IPS
  local -n ignoreIPsFile=FILES[ignoreIPs]
  local -n ignoreDomainsFile=FILES[ignoreDomains]
  local logLvl=${CONFIG[logLvl]}
  local ip
  local domain
  local domainIP

	# parse ignoreIPsFile
	if [[ -f ${ignoreIPsFile} ]]; then
		while IFS= read -r ip; do
			if [[ -n ${ip} ]]; then
        preFilterIPs[$ip]=1 # add ip from file to map
      fi
		done <"${ignoreIPsFile}"
  else
    echo "${RED}File not found ${ignoreIPsFile}${RESET}"
	fi
  # parse ignoreDomainsFile
  if [[ -f ${ignoreDomainsFile} ]]; then
		while IFS= read -r domain; do
			if [[ -n ${domain} ]]; then
        domainIP=$(dig +short +timeout=2 ${domain})
        if [[ -n ${domainIP} ]]; then
          preFilterIPs[$domainIP]=1 # add ip from file to map
        fi
      fi
		done <"${ignoreDomainsFile}"
  else
    echo -e "${RED}File not found ${ignoreDomainsFile}${RESET}"
  fi

  if [[ ${logLvl} -gt 0 ]]; then
    echo "---"
    echo "The following IPs are excluded:"
    for ip in "${!preFilterIPs[@]}"; do
      echo -e "${GREEN}${ip}${RESET}"
    done
    echo
  fi
}

function printAvailableDomains() {
	local -n alienDstIPsMap=ALIEN_DST_IPS_MAP
  local ip
  local domain
  local failedToResolve=()

  # resolved
  echo
  echo -e "${BOLD}Outgoing domains:${RESET}"
  for ip in "${!alienDstIPsMap[@]}"; do
    domain=$(dig +short -x ${ip})
    if [[ -z ${domain} ]]; then
      failedToResolve+=("${ip}")
    else
      echo -e "${GREEN}${domain}${RESET}"
    fi
  done

  # failed to resolve
  if [[ ${#failedToResolve[@]} -gt 0 ]]; then
    echo -e "${BOLD}Failed to resolve:${RESET}"
    for ip in "${failedToResolve[@]}"; do
      echo "${GREEN}${ip}${RESET}"
    done
  fi
}

# Clear all data structures
function initData() {
	ALIEN_SRC_IPS_MAP=()
	ALIEN_DST_IPS_MAP=()
	OUT_LOGS=()
	IN_LOGS=()
	OUT_PORTS_MAP=()
	IN_PORTS_MAP=()
}

function printAvailableIPs() {

	local -n alienSrcIPsMap=ALIEN_SRC_IPS_MAP
	local -n alienDstIPsMap=ALIEN_DST_IPS_MAP

	echo -e "${BOLD}Incoming IPs:${RESET}"
	printf '%s\n' "${!alienSrcIPsMap[@]}" | sort

	echo -e "\n${BOLD}Outgoing IPs:${RESET}"
	printf '%s\n' "${!alienDstIPsMap[@]}" | sort
}

function printAvailablePorts() {

	local -n inPortsMap=IN_PORTS_MAP
	local -n outPortsMap=OUT_PORTS_MAP

	echo -e "${BOLD}Local ports:${RESET}"
	printf '%s\n' "${!inPortsMap[@]}" | sort

	echo -e "\n${BOLD}Remote ports:${RESET}"
	printf '%s\n' "${!outPortsMap[@]}" | sort
}

function parseLogs() {

	# USE:
	# parseLogs <preFilterIPs>

	# TASK:
	# Read journal logs into variables:
	# - ALIEN_SRC_IPS_MAP
	# - ALIEN_DST_IPS_MAP
	# - inPortsMap
	# - outPortsMap
	# - IN_LOGS
	# - OUT_LOGS
  local -n inPortsMap=IN_PORTS_MAP
  local -n outPortsMap=OUT_PORTS_MAP
	local -n timeSpan=TIME_SPAN
	local -n preFilterIPs=PRE_FILTER_IPS
  local -n outLogs=OUT_LOGS
  local -n inLogs=IN_LOGS
  local -n alienSrcIPsMap=ALIEN_SRC_IPS_MAP
  local -n alienDstIPsMap=ALIEN_DST_IPS_MAP

	#echo "Parsing logs with timeSpan=${timeSpan} preFilterIPs=${preFilterIPs[@]}"

	initData

	# Read and parse journal logs
	while IFS= read -r line; do

		local _interfaceIn
		local _interfaceOut
		local _srcIP
		local _destIP
		local _srcPort
		local _destPort

		# Extract interfaces first to determine direction
		if [[ ${line} =~ OUT=([^ ]+) ]]; then
			_interfaceOut=${BASH_REMATCH[1]}
		else
			_interfaceOut=""
		fi

		if [[ ${line} =~ IN=([^ ]+) ]]; then
			_interfaceIn=${BASH_REMATCH[1]}
		else
			_interfaceIn=""
		fi

		# Extract IP and port information only if needed based on direction
		if [[ ${_interfaceOut} && -z ${_interfaceIn} ]]; then
			# OUTGOING
			[[ ${line} =~ DST=([^ ]+) ]] && _destIP=${BASH_REMATCH[1]}   # set _destIP
			[[ ${line} =~ DPT=([^ ]+) ]] && _destPort=${BASH_REMATCH[1]} # set _destPort

			if ! isPrivateIP "$_destIP" && [[ -z ${preFilterIPs[$_destIP]} ]]; then
				# _destIP is not private and is not pre filtered
				outLogs+=("$line")
				alienDstIPsMap[$_destIP]=1
				outPortsMap[$_destPort]=1
			fi

		elif [[ ${_interfaceIn} && -z ${_interfaceOut} ]]; then
			# INCOMING
			[[ $line =~ SRC=([^ ]+) ]] && _srcIP=${BASH_REMATCH[1]}    # set _srcIP
			[[ $line =~ DPT=([^ ]+) ]] && _destPort=${BASH_REMATCH[1]} # set _destPort

			if [[ -z ${preFilterIPs[$_srcIP]} ]]; then
				# _srcIP is not pre filtered
				inLogs+=("${line}")
				alienSrcIPsMap[$_srcIP]=1
				inPortsMap[$_destPort]=1
			fi

		else
			echo "ERROR: unhandled case: $line"
		fi
	done < <(sudo journalctl --identifier=kernel --grep "UFW ALLOW" --since "${timeSpan}" --no-pager)
}

function printMatchLogs() {

	# use:
	# printMatchLogs <direction> <PORT_FILTER> <IP_FILTER> <logs>

	# <direction> # "in", "out", "both"

	# 1. loops over detected alien ips
	# 2. loops over each line in the logs

	# args:
	local -n log=${1}
	# locals from globals:
	local -n portFilter=PORT_FILTER
	local -n ipFilter=IP_FILTER
	# locals
	local logLvl=1
	local printedHeader=0
	local report=""
  local filteredByIP
  local filteredByPort
  local src
  local dst
  local dpt

	# log
	if [[ ${logLvl} -gt 0 ]]; then
		report+="Log lines: ${#log[@]}\n"
		report+="Port filter [${#portFilter[@]}]:\n"
		for port in "${!portFilter[@]}"; do report+="${port}\n"; done
		report+="IP filter [${#ipFilter[@]}]:\n"
		for ip in "${!ipFilter[@]}"; do report+="${ip}\n"; done
	fi

	report+="\n"

	for line in "${log[@]}"; do
		filteredByPort=0
		filteredByIP=0

		[[ ${line} =~ SRC=([^ ]+) ]] && src=${BASH_REMATCH[1]} # set _srcIP
		[[ ${line} =~ DST=([^ ]+) ]] && dst=${BASH_REMATCH[1]} # set _destIP
		[[ ${line} =~ DPT=([^ ]+) ]] && dpt=${BASH_REMATCH[1]} # set _destPort

		if [[ ${logLvl} -gt 1 ]]; then
			report+="src: ${src}\n"
			report+="dst: ${dst}\n"
			report+="dpt: ${dpt}\n"
		fi

		# check if filtered by port
		if [[ ${#portFilter[@]} -eq 0 ]]; then
			filteredByPort=1 # show line if no ip filter is set
		else
			if [[ -v portFilter[$dpt] ]]; then
				filteredByPort=1
			fi
		fi

		# check if filtered by ip
		if [[ ${#ipFilter[@]} -eq 0 ]]; then
			filteredByIP=1 # show line if no ip filter is set
		else
			if [[ -v ipFilter[$dst] || -v ipFilter[$src] ]]; then
				filteredByIP=1
			fi
		fi

		if [[ ${filteredByIP} -eq 1 && $filteredByPort -eq 1 ]]; then
			# print line
			if [[ ${printedHeader} -eq 0 ]]; then
				:
				# print header
				#printf '\n%sConnections %s %s%s%s (Port %s):\n' "${BOLD}" "$direction" "${RED}" "$ip" "${RESET}" "$portFilter"
				#printedHeader=1
			fi
			# print log line
			#printf '%s\n' "$line"
			report+="${line}\n"
		fi
	done

	echo -e "${report}" | less --chop-long-lines --use-color # --status-column

}

function changeTimeSpan() {
	# USE:
	# changeTimeSpan TIME_SPAN

	local -n timeSpan=TIME_SPAN

	#clear
	echo -e "${BOLD}Change Time Span${RESET}"
	echo "----------------"
	echo -e "Current time span: ${GREEN}$TIME_SPAN${RESET}"
	echo
	echo "Examples of valid time spans:"
	echo "- today"
	echo "- yesterday"
	echo "- \"2 hours ago\""
	echo "- \"3 days ago\""
	echo "- \"1 week ago\""
	echo
	read -p "Enter new time span (or Enter to cancel): " new_span

	if [[ -n $new_span ]]; then
		# Test if the time span is valid
		if systemd-analyze timestamp "$new_span" >/dev/null 2>&1; then
		#if systemd-analyze timestamp "$new_span"; then
			timeSpan="${new_span}"
			echo -e "\nTime span updated to: ${GREEN}${timeSpan}${RESET}"
			return 0
		else
			echo -e "\n${RED}Invalid time span format${RESET}"
			return 1
		fi
	fi
}

function interactiveMode() {

	local -n ipFilter=IP_FILTER
	local -n portFilter=PORT_FILTER
	local -n timeSpan=TIME_SPAN
	local -n alienSrcIPsMap=ALIEN_SRC_IPS_MAP
	local -n alienDstIPsMap=ALIEN_DST_IPS_MAP
	local -n inPortsMap=IN_PORTS_MAP
	local -n outPortsMap=OUT_PORTS_MAP
	local -n inLogs=IN_LOGS
	local -n outLogs=OUT_LOGS

	local direction="both"
  local cmd=""
  local port=""
  local ip=""
  local newDirection=""
  local newPort=""
  local newIP=""

	while true; do
		#clear
		echo
		echo -e "${BOLD}UFW Log Monitor - Interactive Mode${RESET}"
		echo "----------------------------------------"
		#echo -e "Time span: ${GREEN}${timeSpan}${RESET}"
		#echo -e "Direction: ${GREEN}${direction}${RESET}"
		#echo -e "Port filter:"
		#for port in "${!portFilter[@]}"; do echo -e "- ${GREEN}${port}${RESET}"; done
		#echo -e "IP filter:"
		#for ip in "${!ipFilter[@]}"; do echo -e "- ${GREEN}${ip}${RESET}"; done
		#echo
		#echo -e "${BOLD}Available Commands:${RESET}"

		echo
		# TIME & DIRECTION
		echo -e "${UNDERLINE}TIME & DIRECTION${RESET}"
		echo -e "${GREEN}1${RESET})  Set time (${GREEN}${timeSpan}${RESET})"
		echo -e "${GREEN}2${RESET})  Set direction (${GREEN}${direction}${RESET})"
		# PORT FILTER
		echo -e "${UNDERLINE}PORT FILTER${RESET}"
		for port in "${!portFilter[@]}"; do echo -e "- ${GREEN}${port}${RESET}"; done
		echo -e "${GREEN}3${RESET})  Add port"
		echo -e "${GREEN}4${RESET})  Remove port"
		# IP FILTER
		echo -e "${UNDERLINE}IP FILTER${RESET}"
		for ip in "${!ipFilter[@]}"; do echo -e "- ${GREEN}${ip}${RESET}"; done
		echo -e "${GREEN}5${RESET})  Add IP"
		echo -e "${GREEN}6${RESET})  Remove IP"
		# PRINT RESULTS
		echo -e "${UNDERLINE}PRINT RESULTS${RESET}"
		echo -e "${GREEN}7${RESET})  Print available IPs"
		echo -e "${GREEN}8${RESET})  Print available ports"
    echo -e "${GREEN}9${RESET})  Print available domains"
		echo -e "${GREEN}10${RESET}) Print matching logs"
		echo -e "${GREEN}11${RESET}) Print Variables"
		echo
		read -p ">> " cmd
		echo
		echo

		case ${cmd} in
		1)
			# Set time
			changeTimeSpan && parseLogs
			;;
		2)
			# Set direction
			echo
			echo -e "${BOLD}Set direction:${RESET}"
			echo
			echo -e "${GREEN}1${RESET}) Incoming"
			echo -e "${GREEN}2${RESET}) Outgoing"
			echo -e "${GREEN}3${RESET}) Both"
			echo
			read -p ">> " newDirection
			echo

			case ${newDirection} in
				1)
					direction="incoming"
				;;
				2)
					direction="outgoing"
				;;
				3)
					direction="both"
				;;
			esac
			;;
		3)
			# Add port to filter
			printAvailablePorts
			read -p "Port to filter (or Enter to cancel): " newPort
			if [[ -n ${newPort} ]]; then
				portFilter[$newPort]=1
			fi
			;;
		4)
			# Remove port from filter
			printf '\n%s\n' "${!portFilter[@]}" | sort
			read -p "Port to remove from filter (or Enter to cancel): " rm_port
			unset portFilter["$rm_port"]
			;;
		5)
			# Add IP to filter
			printAvailableIPs
			read -p "IP to filter (or Enter to cancel): " newIP
			if [[ -n ${newIP} ]]; then
				ipFilter[$newIP]=1
			fi
			;;
		6)
			# Remove ip from filter
			printf '\n%s\n' "${!ipFilter[@]}" | sort
			read -p "Port to remove from filter (or Enter to cancel): " rm_ip
			unset ipFilter["$rm_ip"]
			;;
		7)
			# Print available IP addresses
			#clear
			echo -e "${BOLD}Available IP Addresses${RESET}"
			echo "--------------------"
			printAvailableIPs
			read -p "Press Enter to continue..."
			;;
		8)
			# Print available ports
			#clear
			echo -e "${BOLD}Available ports${RESET}"
			echo "--------------------"
			printAvailablePorts
			read -p "Press Enter to continue..."
			;;
		9)
			# Print available domains
			#clear
			echo -e "${BOLD}Available domains${RESET}"
			echo "--------------------"
			printAvailableDomains
			read -p "Press Enter to continue..."
			;;
		10)
			# Print matching logs
			case ${direction} in
				incoming)
					printMatchLogs inLogs
				;;
				outgoing)
					printMatchLogs outLogs
				;;
				both)
					_both=("${inLogs[@]}" "${outLogs[@]}")
					printMatchLogs _both
					#printMatchLogs $("${inLogs[@]}" "${outLogs[@]}")
				;;
			esac
			;;
		11)
			# Print Variables

			# alienSrcIPsMap
			echo -e "\n${UNDERLINE}alienSrcIPsMap${RESET}\n"
			for item in "${!alienSrcIPsMap[@]}"; do echo $item; done
			echo ""
			# alienDstIPsMap
			echo -e "\n${UNDERLINE}alienDstIPsMap${RESET}\n"
			for item in "${!alienDstIPsMap[@]}"; do echo $item; done
			echo ""
			# outPortsMap
			echo -e "\n${UNDERLINE}outPortsMap${RESET}\n"
			for item in "${!outPortsMap[@]}"; do echo $item; done
			echo ""
			# inPortsMap
			echo -e "\n${UNDERLINE}inPortsMap${RESET}\n"
			for item in "${!inPortsMap[@]}"; do echo $item; done
			echo ""
			# outLogs
			echo -e "\n${UNDERLINE}outLogs${RESET}\n"
			for item in "${outLogs[@]}"; do echo $item; done
			echo ""
			# inLogs
			echo -e "\n${UNDERLINE}inLogs${RESET}\n"
			for item in "${inLogs[@]}"; do echo $item; done
			echo ""
			;;
		q | Q)
			exit 0
			;;
		*)
			echo "Invalid command"
			sleep 1
			;;
		esac
	done
}

function main() {
  # Main script execution
  # Initialize by processing logs for the first time
  local -n outLogs=OUT_LOGS
  local -n inLogs=IN_LOGS
  local -n alienSrcIPsMap=ALIEN_SRC_IPS_MAP
  local -n alienDstIPsMap=ALIEN_DST_IPS_MAP

  parseArguments "${@}"
  initPreFilterIPs
  parseLogs

  # Main output logic
  # Continue with either interactive or normal mode
  if ((INTERACTIVE)); then
    interactiveMode
  else
    if ((${#alienDstIPsMap[@]} > 0)); then
      printf '%s\n' "--------" "${BOLD}OUTGOING${RESET}" "--------"
      printMatchLogs outLogs
    else
      echo "No suspicious outgoing connections found"
    fi

    if ((${#alienSrcIPsMap[@]} > 0)); then
      printf '%s\n' "--------" "${BOLD}INCOMING${RESET}" "--------"
      printMatchLogs inLogs
    else
      echo "No suspicious incoming connections found"
    fi
  fi
}

main "${@}"