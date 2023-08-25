#!/bin/zsh

# Based on Nmap - visit https://nmap.org/ - you can also find the terms of the 'Nmap Public Source License' at https://svn.nmap.org/nmap/LICENSE
# Nmap Fan Edition 'Smart One-Click Scan' CLI Frontend - Zsh Script created by Renzo Donegani aka RezVIKONG - you can find me on LinkedIn at https://www.linkedin.com/in/renzodonegani

ScriptVersion="0.9b"

# Text Color Formatting
TextFormatBOLD="\e[1m"
TextFormatItalics="\e[3m"
TextFormatUnderline="\e[4m"
TextFormatBlinking="\e[5m"
TextBackground="\e[7m"
TextColorRED="\e[31m"
TextColorGreen="\e[32m"
TextColorGold="\e[33m"
TextColorPurple="\e[35m"
TextColorBlue="\e[36m"
TextEndFormat="\e[0m"

# Check and require sudo rights - because Nmap with sudo permissions can create full RAW packets
if [[ $(sudo -n true &> /dev/null; echo $?) -ne 0 ]]; then
  echo "${TextFormatBOLD}${TextFormatUnderline}${TextColorRED}This script requires SUDO Rights. Please run it as 'sudo ./script.sh' - otherwise Nmap will not be able to create RAW Packets and there will be some limited features or errors${TextEndFormat}"
  exit 1 # Exit with an error code
fi


echo "${TextFormatBlinking}${TextFormatBOLD}${TextColorBlue}"'  ________      ______ ______      ________      ________                 ________      ________
 |\   __  \    |\   __ \ __  \    |\   __  \    |\   __  \               |\   ____\    |\   ____\
 \ \  \\ \  \   \ \  \\ \__\ \  \   \ \  \_\  \   \ \  \_\  \     ______   \ \  \___|_   \ \  \___|_
  \ \  \\ \  \   \ \  \|__|\ \  \   \ \   __  \   \ \   ____\   |\_____\   \ \   ____\   \ \   ____\
   \ \  \\ \  \   \ \  \    \ \  \   \ \  \ \  \   \ \  \___|   \|_____|    \ \  \___|    \ \  \___|_
    \ \__\\ \__\   \ \__\    \ \__\   \ \__\ \__\   \ \__\                   \ \__\        \ \_______\
     \|__|\|__|    \|__|     \|__|    \|__|\|__|    \|__|                    \|__|         \|_______|'"${TextEndFormat}"

echo "${TextFormatBOLD}${TextColorBlue}\nBased on Nmap - visit https://nmap.org/ - you can also find the terms of the 'Nmap Public Source License' at https://svn.nmap.org/nmap/LICENSE ${TextEndFormat}\n"

echo "${TextFormatBOLD}${TextColorGold}\nNmap Fan Edition 'Smart One-Click Scan' CLI Frontend - Zsh Script created by ${TextFormatUnderline}Renzo Donegani${TextEndFormat} ${TextFormatBOLD}${TextColorGold}aka RezVIKONG - you can find me on LinkedIn at https://www.linkedin.com/in/renzodonegani ${TextEndFormat}\n\n${TextColorGold}This script has been created to perform a 'Smart One-Click Scan' of a typical Windows-Linux-MacOS Target in less than 45 Minutes.\n\nFeatures included:\n- Recursive Basic FW/IPS Evasion \n- Tuned Scan Timings\n- Smart Top TCP and UDP Destination Ports\n- Custom IP Payload Size\n- Not Intrusive NSE scan by default\n- Custom Source Port Scan\n- Results Reports in XML and RTF with Full Scan Details\n- SearchSploit NmapXML Ingestion - visit https://www.exploit-db.com/searchsploit \n- a lot of Colours :D ${TextEndFormat}"

echo "${TextFormatItalics}\nScript Version $ScriptVersion ${TextEndFormat}\n"

echo "${TextFormatBOLD}${TextColorGreen}\nPlease enter one or more Targets separated by a single white space (IPv4/CIDR/FQDN Accepted): ${TextEndFormat}"
read -u 0 TargetInput
echo "${TextFormatBOLD}${TextColorRED}You entered $TargetInput${TextEndFormat}"
echo "${TextFormatBOLD}${TextColorGreen}Do you want to continue? (y/n)${TextEndFormat}"
read -u 0 answer
if [[ $answer == "y" || $answer == "Y" ]]; then
  echo "Continuing..."
else
  echo "Aborting..."
  exit 1
fi
Targets=(${(s: :)TargetInput})


# if the Target is a PRIVATE IPv4 or PRIVATE IPv4 CIDR the Host Discovery is intended on common TCP LAN Ports - Port Sequence on Host Discovery is ALWAYS from the Lower to the Higher because Nmap manage to do so
TCPvsInternet="-PS21,25,53,80,110,143,443,445,465,587,993,995,1194,1723,5060"
TCPvsLAN="-PS21,22,23,25,53,80,110,135,139,143,161,162,389,443,445,465,587,993,995,1194,1433,1521,1723,3306,3389,4433,5040,5060,5355,5432,5985,6379,8080,27017"

# TCP SYN (-PS) or ACK (-PA) for Host Discovery with Multiple Source Ports - sometimes Firewalls do not filter packets coming from specific Source Ports (Miscofiguration caused by some Admins)
# Qualys ID 34000 - The host responded 4 times to 4 TCP SYN probes sent to destination port 25 using source port 80. However, it did not respond at all to 4 TCP SYN probes sent to the same destination port using a random source port.
# NOTE: unfortunately the parameter --scanflags doesn't work with Ping Scan but only with Port Scans such as -sS -sA, so to do a Host Discovery using TCP SYN-ACK flags (both enabled) we should create a NSE script
for Target in {1..${#Targets[@]}}; do

	# NOTE: a standard -T2 scan (Port Scan 65535 TCP ports + UDP 36 ports + OS + Version Scan + NSE) on 1 LAN IP needs more than 20 HOURS to complete [Nmap done: 1 IP address (1 host up) scanned in 74075.20 seconds]
	# NOTE: with the same parameters mentioned before, a scan as "-T2 --min-rate 10 --max-rate 100" needs a little more than 5 HOURS to complete - the EXACTLY SAME Scan Time as "-T3 --min-rate 0.01 --max-rate 100 --max-parallelism 1" BUT having '--min-rate 0.01' give Nmap the ability to slow down to 1 Packet every 100 Seconds if the network becomes temporarily unrielable or in the case of rate limiting by a FW/IPS.
	# NOTE: Parallelism >1 is only available to -T3 -T4 -T5 timings - but keep in mind that with an high parallelism Nmap could send that --max-parallelism amount in a very short time frame (as a burst of a couple packets sent)
	# NOTE: by using a --max-parallelism as low as 1 (no parallel port scan) we create a Destination Port Pattern EASILY NOTICEABLE with both -T2 and -T3 timings because Nmap scan the same Destination Port consecutively 2 times and it does the same for the next ports - instead with a BALANCE between '--max-parallelism' and '--max-rate' the Destination Port Pattern is a lot more variable and we can also improve total scan time.
	# NOTE: an Optimized scan (see below $NmapScanParameters) with timing "-T3 --min-rate 0.01 --max-rate 49 --max-parallelism 49" takes 45 MINUTES to complete and has a nice random Destination Port Pattern and time between probes.
	ScanTiming="-T3 --min-rate 0.01 --max-rate 49 --max-parallelism 49"
	
	RndPortSocket=$((50000 + RANDOM % 15001))
	SrcPrtSocket=(80 53 20 $RndPortSocket)
	
	for run in {1..${#SrcPrtSocket[@]}}; do
		sleep 5
		if [[ ${SrcPrtSocket[$run]} -eq 80 ]]; then
			HostDiscovParam="-PS80 -PA80"
		elif [[ ${SrcPrtSocket[$run]} -le 49151 ]]; then
			HostDiscovParam="-PS20,443,$((50000 + RANDOM % 15001)) -PA53,$((50000 + RANDOM % 15001))"
		# checking if the Target matches a regular expression that represents a valid PRIVATE IPv4 address with an optional subnet mask
		elif [[ ${SrcPrtSocket[$run]} -gt 49151 && ${Targets[$Target]} =~ ^(((127\\.0\\.0\\.1)|(192\\.168\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(172\\.(1[6-9]|2[0-9]|3[0-1])\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(10\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))(\/([0-9]|1[0-9]|2[0-9]|3[0-2]))?)$ ]]; then
			ScanTiming="-T1 --max-rate 0.04"
			HostDiscovParam="$TCPvsLAN"
		else
			ScanTiming="-T1 --max-rate 0.04"
			HostDiscovParam="$TCPvsInternet"
		fi
		
		ScanLogDir="NmapScan/Target_${${Targets[$Target]}//\//_}/Date_$(date '+%Y-%m-%d')/Time_$(date '+%H-%M')/SrcPrtSocket_${SrcPrtSocket[$run]}"
		mkdir -p "$ScanLogDir"
		
		# NOTE: to known what ports are for the standard Nmap '--top-ports 1000' run 'sudo nmap -v3 -sS -sU --top-ports 1000 -oG -' for more info also visit https://nmap.org/book/performance-port-selection.html
		# I'm using TCP --top-ports 4260 and UDP --top-ports 100 but since Nmap doesn't take 2 different --top-ports parameters, I need to create a variable containing the relative top ports list.
		TopPortsTCP="T:${${$(sudo nmap -v3 -sS --top-ports 4260 -oG - 2>/dev/null)#*TCP\(*;}%%\)*}"
		TopPortsUDP="U:${${$(sudo nmap -v3 -sU --top-ports 100 -oG - 2>/dev/null)#*UDP\(*;}%%\)*}"
		CustomTopPortsTCPnUDP="-p $TopPortsTCP,$TopPortsUDP"
		
		# NOTE: the use of 'URG' & 'PSH' TCP flags can be useful for applications that need to send time-sensitive or out-of-band data, such as telnet or SSH. However, this can also be a sign of malicious activity, such as port scanning or denial-of-service attacks, as it can cause unexpected behavior or overload on the server. Therefore, some firewalls or intrusion prevention systems may block or filter packets containing those flags (--scanflags URGPSH).
		# NOTE: Fragmentation (-f) is generally NOT supported by Version Detection and the Nmap Scripting Engine because they rely on your host's TCP stack to communicate with target services.
		# NOTE: Decois (-D) do not work with Version Detection or TCP Connect scan (-sT).
		# NOTE: According to one study that used CAIDA’s Anonymized Internet Traces dataset from January 2019 to analyze network traffic characteristics of different applications, some of the results are as follows:
		# The mean IP payload dimension in TCP packets was 536 bytes for web browsing (HTTP), 1033 bytes for video streaming (YouTube), 1025 bytes for file transfer (FTP), 1059 bytes for email (SMTP), 1017 bytes for social networking (Facebook), 1013 bytes for instant messaging (WhatsApp), 1015 bytes for voice over IP (Skype), and 1021 bytes for online gaming (Fortnite).
		# The mean IP payload dimension in UDP packets was 1357 bytes for video streaming (YouTube), 1022 bytes for file transfer (FTP), 1019 bytes for social networking (Facebook), 1013 bytes for instant messaging (WhatsApp), 1015 bytes for voice over IP (Skype), and 1019 bytes for online gaming (Fortnite).
		NmapScanParameters="sudo nmap -sS -sU $CustomTopPortsTCPnUDP $ScanTiming --noninteractive --randomize-host -v3 --reason --packet-trace --resolve-all $HostDiscovParam --source-port ${SrcPrtSocket[$run]} --max-retries 2 --data-length $((950 + RANDOM % 50)) -oX ./$ScanLogDir/XMLOutput.xml --stats-every 30s --traceroute -sV -O --osscan-guess --script (not (intrusive or brute or dos or exploit or broadcast or external or fuzzer or malware)) ${Targets[$Target]}"
		
		echo "\nExecuting${TextFormatBOLD}${TextColorPurple} $NmapScanParameters\n\n${TextEndFormat}${TextFormatBOLD}START Nmap Scan Round $run on Target ${Targets[$Target]} with Source Port ${SrcPrtSocket[$run]} and Host Discovery Destination Ports Parameter $HostDiscovParam\n${TextEndFormat}" | sudo tee "./$ScanLogDir/TeeOutput.rtf"
		# NOTE: (z) is a zsh-specific feature that allows more flexibility and control over how the variable is split and expanded. It can handle complex cases such as quoting, escaping, globbing, and parameter expansion. However, it may not be compatible with other shells or scripts that expect a different syntax.
		${(z)NmapScanParameters} | sudo tee -a "./$ScanLogDir/TeeOutput.rtf"
		echo "${TextFormatBOLD}${TextColorGold}\n\nENDED Nmap Scan Round $run on Target ${Targets[$Target]} with Source Port ${SrcPrtSocket[$run]} and Host Discovery Destination Ports Parameter $HostDiscovParam\nYou can find the XML and RTF Reports inside Folder $ScanLogDir \n\n${TextEndFormat}" | sudo tee -a "./$ScanLogDir/TeeOutput.rtf"
		
		# if the current Target seems down (0 hosts up) the variable HostDiscoveryDOWN is equal to 1
		cat "./$ScanLogDir/TeeOutput.rtf" | grep -E "0 host(s)? up" > /dev/null; HostDiscoveryDOWN=$((1-?))
		# if the current Target has at least 1 IP up (n+1 hosts up) then search for available Exploits with SearchSploit and BREAK the current loop and go to the Next Target instead of trying a new scan with different Source Port or Timings.
		if [[ $HostDiscoveryDOWN -eq 0 ]]; then
			if [[ -n $(command -v searchsploit) ]]; then
  			sudo searchsploit -v --nmap "./$ScanLogDir/XMLOutput.xml" | sudo tee "./$ScanLogDir/SearchSploit.txt"
			# NOTE: importing Nmap XML into Metasploit is not very usefull because the command 'vulns' does NOT give suggestions related to the data imported - so it is better to carefully analyse TeeOutput.rtf
			echo "${TextFormatBOLD}${TextFormatBlinking}${TextBackground}${TextColorGold}You can find SearchSploit Results and also Nmap XML and RTF Reports inside Folder $ScanLogDir \n\n${TextEndFormat}"
			fi	
			break
		fi
	done
done

# *** TO DO NEXT *** 
# N.1 Wazuh/Snort Nmap scan Detection Bypass
#
# N.2 Emulate a DNS SYN-ACK Reply over TCP with Data Length over 512 bytes and Emulate HTTPS SYN-ACK Reply with (--data) containing a Certificate
# TCP SYN-ACK flags - both enabled - ONLY possible with (-sS --scanflags SYNACK) but not very usefull because Nmap is in Port Scan mode and not in Host Discovery - so to do Host Discovery that way we must create a custom NSE script
# 
# N.3 Implement Port Knocking 
# To unlock SSH (port 22), first port-knock with one of the following sequences:
# - 100, 200, 300 (all TCP)
# - 571, 290, 911, 115 (all TCP)
# - 1234, 5678, 9012 (all TCP)
# - 7000, 8000, 9000 (all TCP)
# - 8881, 7777, 9991 (all TCP)
# - 1000, 2000, 3000 (all UDP)
# - 1234, 5678, 9012 (all UDP) 
# To unlock Telnet (port 23), first port-knock with 1000, 2000, 3000, 4000 (all UDP)
# To unlock RDP (port 3389), first port-knock with 1111:tcp, 2222:udp, 3333:tcp, 4444:udp, 5555:tcp
# To unlock HTTPS (port 443), first port-knock with 1000, 2000, 3000 (all TCP)
# To unlock VPN (port 1194), first port-knock with 1111, 2222, 3333, 4444 (all UDP)
