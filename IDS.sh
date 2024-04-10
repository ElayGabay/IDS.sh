#!/bin/bash


source IDS_Config.conf 

# Set up trap to clean up background processes when Ctrl+C is pressed
trap 'kill $(jobs -p); exit' SIGINT &>/dev/null

# Colors for the script
GREEN=$(tput setaf 2)
RESET=$(tput sgr0)

function INSTALL_FIGLET() {
    # Downloading and using figlet 
    if ! command -v figlet &> /dev/null; then
        sudo apt-get install -y figlet &> /dev/null 
    fi
     echo -e "\e[31m$(figlet IDS :0)\e[0m"
}

function INSTALL_APP () {
    # Downloading Wireshark+Tshark
    if ! command -v tshark &>/dev/null; then 
        echo -e "${GREEN}[@]Downloading Tshark....${RESET}"
        sudo apt-get install -y wireshark &>/dev/null
    fi
	
    if [[ -z $(sudo find ~ -type f -name vt) ]]; then
        echo -e "${GREEN}[@]Downloading vt-cli....${RESET}"
        wget https://github.com/VirusTotal/vt-cli/releases/download/1.0.0/Linux64.zip -P . &>/dev/null
        unzip Linux64.zip -d . &>/dev/null
        sudo rm -r Linux64.zip
        ./vt init --apikey "$API_KEY" &>/dev/null
        echo -e "${GREEN}[@]Download finished for vt-cli.${RESET}"
    else
        echo -e "${GREEN}[*] VT-cli is installed${RESET}"
    fi
}

function MAINDIR () {
    LOCATE_IDS=$(sudo find / -type d -name IDS 2>/dev/null)
    echo -e "${GREEN}[@]Creating main directory named IDS${RESET}"
    # Creating the main directory
    sudo mkdir -m 777 IDS
    cd IDS 
}

function TSHARK_ALERT {
    # Creating the Alerts.text file and giving him permissions
    touch Alerts.txt
    sudo chmod +x Alerts.txt
    echo -e "${GREEN}[@]Downloading IP list from "$URL"${RESET}"
    curl -s "$URL" -o ./top10-2.txt 
    clear
    INSTALL_FIGLET
    # Grep variable that makes a file with IP and URLs to be like this: host 1.1.1.1 or host 0.0.0.0 or host "IP"
    TSHARK_GREP=$(awk '{if (NR==1) print "host "$1; else print "or host "$1}' top10-2.txt | sort -u | tr '\n' ' ')

    # Capturing network traffic to a log.pcap and also alerts.txt to display and analysis
    tshark &>/dev/null -i "$INTERFACE" -w Log.pcap -t ad "$TSHARK_GREP"  &
    tshark &>/dev/null -i "$INTERFACE" -t ad "$TSHARK_GREP"  >> Alerts.txt &
}

function EXTRACT_FILES() {
    local PCAP_FILE=$(sudo find / -type f -name Log.pcap 2>/dev/null)
    local EXTRACTED_DIR="./extracted_files"
    local LOG_FILE="log_file.txt"
    
    # Create log_file.txt if it doesn't exist
    touch "$LOG_FILE"

    while true; do 
        # Export objects from pcap
        tshark -r "$PCAP_FILE" --export-objects http,"$EXTRACTED_DIR" &>/dev/null

        # Delete files larger than 1MB
        find "$EXTRACTED_DIR" -type f -size +1M -delete

        # Simplified file deduplication logic
        for FILE in "$EXTRACTED_DIR"/*; do
            if [ -f "$FILE" ]; then
                MD5_HASH=$(md5sum < "$FILE" | cut -d ' ' -f1)
                DUPLICATES=$(find "$EXTRACTED_DIR" -type f -exec md5sum {} + | grep "$MD5_HASH" | cut -d ' ' -f2-)
                FIRST_FILE=true
                for DUP_FILE in $DUPLICATES; do
                    if [ "$FIRST_FILE" = true ]; then
                        FIRST_FILE=false
                    else
                        rm "$DUP_FILE"
                    fi
                done
            fi
        done

        # Write MD5 hash of each file to log_file.txt
        for FILE in "$EXTRACTED_DIR"/*; do
            if [ -f "$FILE" ]; then
                FILE_NAME=$(basename "$FILE")
                MD5_HASH=$(md5sum < "$FILE" | cut -d ' ' -f1)
                # Check if the MD5 hash already exists in the log file
                if ! grep -q "$MD5_HASH" "$LOG_FILE"; then
                    echo "File name: $FILE_NAME" >> "$LOG_FILE"
                    echo "MD5hash: $MD5_HASH" >> "$LOG_FILE"
                    SCAN_OUTPUT=$(./vt scan file "$FILE" | awk '{print $2}' )
                    ./vt analysis "$SCAN_OUTPUT" >> "$LOG_FILE"
                    echo -e "-------------------------------------------------------------------------" >> "$LOG_FILE"
                fi
            fi
        done

        # Wait for 3 seconds before next extraction
        sleep 3
    done
}

# Main function to call the other functions 
function MAIN () {
    MAINDIR
    INSTALL_APP
    TSHARK_ALERT
    EXTRACT_FILES &
    # Tail to the Alerts.txt to display on the screen in live mode 
    tail -f Alerts.txt
    wait &>/dev/null
}

MAIN
