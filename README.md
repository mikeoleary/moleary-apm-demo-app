## moleary-apm-demo-app

### Purpose
This is a demo app you can run to show features of F5 APM

### Install

#### Ubuntu (to be improved)
```bash
sudo apt-get update
sudo apt-get install python3 python3-venv -y
sudo mkdir /opt/soap-auth-demo/
# copy the main file here. Name it soap-auth-demo.py for the sake of keeping the systemd unit file correct.
# copy the requirements.txt file here.
cd /opt/soap-auth-demo
sudo python3 -m venv venv
source venv/bin/activate
# sudo -i
# source venv/bin/activate
pip install -r requirements.txt
python3 soap-auth-demo.py
```

### Documentation
See https://michaeloleary.net/big-ip/demo-apm-app

### Screenshot
![Home Page Screenshot](/images/screenshot-home-page.png)
