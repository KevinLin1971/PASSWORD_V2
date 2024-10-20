import os
import platform
import usb.core
import usb.util
import plistlib
import subprocess

def get_usb_mount_point(vendor_id, serial_number):
    system = platform.system()
    if system == 'Darwin':  # macOS
        mount_base = '/Volumes'
        # 列出所有 USB 設備
        all_devices = list(usb.core.find(find_all=True))
        for device in all_devices:
            try:
                manufacturer = usb.util.get_string(device, device.iManufacturer)
                product = usb.util.get_string(device, device.iProduct)
                device_serial_number = usb.util.get_string(device, device.iSerialNumber)
                
                if serial_number == device_serial_number:
                    # 假設 USB 驅動器掛載在 /Volumes 目錄下，根據序列號和名稱匹配
                    for item in os.listdir(mount_base):
                        mount_path = os.path.join(mount_base, item)
                        if os.path.ismount(mount_path):
                            # 確認該掛載點是否對應於目標序列號的 USB 設備
                            diskutil_cmd = f'diskutil info -plist "{mount_path}"'
                            result = subprocess.run(diskutil_cmd, shell=True, stdout=subprocess.PIPE, text=True).stdout
                            if result:
                                info = plistlib.loads(result.encode('utf-8'))
                                if 'DeviceIdentifier' in info and 'VolumeUUID' in info:
                                    # 這裡我們假設序列號能對應到 DeviceIdentifier
                                    if serial_number in info.get('DeviceIdentifier', ''):
                                        print(f'找到匹配的 VolumeUUID: {info["VolumeUUID"]}')
                                        return mount_path
            except Exception as e:
                # 如果無法獲取某些屬性，我們就跳過這個設備
                pass
    elif system == 'Linux':
        mount_base = '/media'
        # 列出所有 USB 設備
        cmd = "lsblk -o NAME,TRAN,SERIAL,VENDOR,MOUNTPOINT"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
        devices_info = result.stdout
        for line in devices_info.splitlines():
            if vendor_id in line and serial_number in line:
                mount_path = re.search(r'\S+$', line).group()
                if os.path.ismount(mount_path):
                    return mount_path
    else:
        raise Exception('不支持的操作系統')
    return None

vendor_id = input("請輸入目標 USB 廠商 ID: ")
serial_number = input("請輸入目標 USB 序列號: ")
usb_mount = get_usb_mount_point(vendor_id, serial_number)

if usb_mount:
    print(f'USB 驅動器掛載在: {usb_mount}')
    for root, dirs, files in os.walk(usb_mount):
        level = root.replace(usb_mount, '').count(os.sep)
        indent = ' ' * 4 * level
        print(f'{indent}{os.path.basename(root)}/')
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            if f.endswith('.txt'):
                print(f'{subindent}{f}')
else:
    print('未找到 USB 驅動器的掛載點。')
