#!/usr/bin/env python
import os
import subprocess
import sys
import time

### Helper Functions ###
def check_driver_exist(drv):
  lsmod = subprocess.check_output('lsmod')
  lsmod = lsmod.split('\n')
  for i in range(1,len(lsmod)):
    line = lsmod[i].split(' ')
    if line[0] == drv:
      return True
  return False

def current_nr_hugepages(node_id):
  output = subprocess.check_output(("cat /sys/devices/system/node/node%d/hugepages/hugepages-2048kB/nr_hugepages" % node_id).split())
  return int(output)

def setup_hugepages_for_numa(node_id, nr_hugepage):
  print("Numa node %d..." % node_id)
  
  if current_nr_hugepages(node_id) == nr_hugepage:
    print("  nr_hugepages is already set for NUMA %d" % node_id)
    return

  echo = subprocess.Popen(('echo %d' % nr_hugepage).split(), stdout=subprocess.PIPE)
  tee = subprocess.Popen(('sudo tee /sys/devices/system/node/node%d/hugepages/hugepages-2048kB/nr_hugepages' % node_id).split(), stdin=echo.stdout, stdout=subprocess.PIPE)
  echo.stdout.close()
  ret = tee.communicate()[0]
  echo.wait()
  if int(ret) != nr_hugepage:
    print("Fail to configure hugepages for NUMA %d" % node_id)
    exit(1)

def create_dir(path):
  print("Creating %s..." % path)
  if os.path.exists(path):
    print("  %s exists." % path)
  else:
    cmd = "mkdir %d" % path
    print("  " + cmd)
    os.system(cmd)
    print("  %s created." % path)

def is_hugetlbfs_mounted(hugepage_path):
  mount = subprocess.check_output("mount")
  mount = mount.split('\n')
  for i in range(len(mount)):
    line = mount[i].split(' ')
    if (len(line) < 6):
      continue
    if line[2] == hugepage_path:
      if line[4] == 'hugetlbfs':
        return True
      else:
        os.system("sudo umount %s" % hugepage_path)
  return False

def mount_hugetlbfs(hugepage_path):
  print("Mounting Hugetlbfs...")
  if is_hugetlbfs_mounted(hugepage_path):
    print("  Hugetlbfs is already mounted.")
    return
  cmd = "sudo mount -t hugetlbfs nodev %s" % hugepage_path

def check_nic_exists(nic_name):
  print("Checking for %s" % nic_name)
  ifconfig = subprocess.check_output('ifconfig')
  ifconfig = ifconfig.split('\n\n')
  for i in range(len(ifconfig)):
    nic = ifconfig[i]
    nic = nic.split(' ')
    if nic[0] == nic_name:
      return;
  print("  %s interface is not detected." % nic_name)
  print("Failed.")
  exit(1)

def iface_down(port_name):
  cmd = "sudo ifconfig %s down" % port_name
  print("  " + cmd)
  os.system(cmd)

def install_uio():
  print("Checking uio...")
  if check_driver_exist('uio'):
    print("  uio is already installed.")
  else:
    cmd = "sudo modprobe uio"
    print("  " + cmd)
    os.system(cmd)
    print("  uio is successfully installed!")

  print("Checking igb_uio...")
  if check_driver_exist('igb_uio'):
    print("  igb_uio is already installed.")
  elif os.path.exists('deps/dpdk-17.05/build/kmod/igb_uio.ko'):
    cmd = "sudo insmod deps/dpdk-17.05/build/kmod/igb_uio.ko"
    print("  " + cmd)
    os.system(cmd)
    print("  igb_uio is successfully installed.")
  else:
    print("igb_uio.ko does not exsit.")
    exit(1)

def dev_bind(pci_id, driver):
  if not check_driver_exist(driver):
    print("[%s] Driver does not exists" % driver)
    exit(1)
  cmd = "sudo bin/dpdk-devbind.py -b %s %s" % (driver, pci_id)
  print("  " + cmd)
  os.system(cmd)

def clear_dpdk_compatible():
  print("Checking dpdk-compatible ports...")
  devbind = subprocess.check_output(['bin/dpdk-devbind.py','--status'])
  devbind = devbind.split('\n\n')
  dpdk_compatible = devbind[0].split('\n')
  if dpdk_compatible[-1] != "<none>":
    for i in range(3, len(dpdk_compatible)):
      line = dpdk_compatible[i].split(' ')
      pci_id = line[0]
      print("  %s ==> ixgbe" % pci_id)
      dev_bind(pci_id, "ixgbe")

def bind_ports(port_name):
  print("Binding %s..." % port_name)
  devbind = subprocess.check_output(['bin/dpdk-devbind.py','--status'])
  devbind = devbind.split('\n\n')
  kernel_compatible = devbind[1].split('\n')
  if kernel_compatible[-1] != "<none>":
    for i in range(2, len(kernel_compatible)):
      line = kernel_compatible[i].split(' ')
      if ("if=" + port_name) in line:
        pci_id = line[0]
	print("  %s(%s) ==> igb_uio" % (port_name, pci_id))
	dev_bind(pci_id, "igb_uio")
	return
  print("  Cannot find %s" % port_name)
  print("Failed.")
  exit(1)

###                      ###
### Configuration start! ###
###                      ###

# Recovery Phase #
# If bess module is already installed, remove it.
if check_driver_exist("bess"):
  cmd = "sudo rmmod bess"
  print(cmd)
  os.system(cmd)

# clear DPDK drivers
clear_dpdk_compatible()

# Install Phase #
# check whether bess is compiled.
if not os.path.exists('core/kmod/bess.ko'):
  cmd = "./build.py"
  print(cmd)
  os.system(cmd)

# hugepage setup
setup_hugepages_for_numa(0, 1024)
print("Success!!\n")
setup_hugepages_for_numa(1, 1024)
print("Success!!\n")

# mount hugetlb file system
create_dir("/mnt/huge")
print("Success!!\n")

mount_hugetlbfs("/mnt/huge")
print("Success!!")

# Kernel module compile & install bess module
if not check_driver_exist("bess"):
  print('\n' + 'No bess kernel module is detected.')
  os.chdir("core/kmod")
  cmd = "./install"
  print(cmd)
  os.system(cmd)
  os.chdir("../..")
else:
  print("BESS kernel module already exsits.")

#install uio
install_uio()
print("Success!!!\n")

#check whether xe1 and xe2 are alive.
time.sleep(1)
check_nic_exists("xe1")
print("Success!!!\n")
check_nic_exists("xe2")
print("Success!!!\n")

iface_down("xe1")
print("Success!!!\n")
iface_down("xe2")
print("Success!!!\n")

bind_ports("xe1")
print("Success!!!\n")
bind_ports("xe2")
print("Success!!!\n")

# execute bessctl
os.system("bessctl/bessctl")
