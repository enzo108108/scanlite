# Create a simple db to dump wireless network data


## Commands to enable wireless interface




### Using iXconfig

sudo ifconfig wlan0 down


sudo iwconfig wlan0 mode monitor

sudo iwconfig wlan0 up

### Using aircrack-ng

ifconfig wlan0 down
airmon-ng check kill

airmon-ng start wlan0mon

sudo sudo airodump-ng wlan0mon

airmon-ng stop wlan0mon / or restart!

###

ifconfig
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up

sudo airmon-ng check kill
sudo airmon-ng start wlan0
sudo aerodump-ng wlan0mon

# Launch the script

* Configure venv with `uv venv -p 3.12.11` and `uv pip install -r requirements.txt`
* From folder: `sudo /full/location/python scan.py -i interfacemon`