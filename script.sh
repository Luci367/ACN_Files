#!/bin/bash

TEXT_RESET='\e[0m'
TEXT_YELLOW='\e[0;33m'
TEXT_RED_B='\e[1;31m'

sudo apt-get update -y
echo -e $TEXT_YELLOW
echo 'APT update finished...'
echo -e $TEXT_RESET

sudo apt-get upgrade -y
echo -e $TEXT_YELLOW
echo 'APT upgrade finished...'
echo -e $TEXT_RESET

sudo apt-get install git -y
sudo apt-get texlive -y
sudo apt install tshark -y

sudo apt-get autoremove -y
echo -e $TEXT_YELLOW
echo 'APT auto remove finished...'
echo -e $TEXT_RESET

if [ -f /var/run/reboot-required ]; then
    echo -e $TEXT_RED_B
    echo 'Reboot required! Kindly restart your machine before proceding with installation.'
    echo -e $TEXT_RESET
    exit 1
fi

echo "**************************************************************************"
echo "Installing Mininet-WiFi (which contains Mininet), wireshark, scapy and ryu"
echo "**************************************************************************"
sudo apt-get remove mininet -y
sudo pip uninstall --yes mininet
sudo rm -r mininet
echo -e $TEXT_YELLOW
echo 'Mininet uninstall finished...'
echo -e $TEXT_RESET


git clone https://github.com/intrig-unicamp/mininet-wifi
cd mininet-wifi/
cd util/
sudo ./install.sh -Wlnfv6
echo -e $TEXT_YELLOW
echo 'Mininet-WiFi install finished...'
echo -e $TEXT_RESET

sudo apt-get install wireshark -y 
sudo pkg-reconfigure wireshark-common
sudo usermod -aG wireshark $(whoami)
echo -e $TEXT_YELLOW
echo 'Wireshark install finished...'
echo -e $TEXT_RESET

pip install scapy
pip install PyX
pip install IPython
echo -e $TEXT_YELLOW
echo 'Scapy install finished...'
echo -e $TEXT_RESET

sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get install virtualenv python3.9 python3.9-distutils

#create the virtualenv 
virtualenv -p`which python3.9` ryu-python3.9-venv
source ryu-python3.9-venv/bin/activate
echo $VIRTUAL_ENV #check if we are indeed in the virtual environment
pip install ryu
pip uninstall eventlet
pip install eventlet==0.30.2


echo -e $TEXT_YELLOW
echo 'Ryu install finished...'
echo -e $TEXT_RESET