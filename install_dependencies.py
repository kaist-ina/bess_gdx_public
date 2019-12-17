#!/usr/bin/env python
import os

def execute(command):
  print(command)
  os.system(command)

execute("sudo apt-get install -y software-properties-common")
execute("sudo apt-add-repository -y ppa:ansible/ansible")
execute("sudo apt-get update")
execute("sudo apt-get install -y ansible")
execute("ansible-playbook -K -t package -i localhost, -c local env/bess.yml")
print("Reboot Required.")
