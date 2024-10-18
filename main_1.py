import usb.core
import usb.util
import sys
import os
import subprocess
import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
from PyQt6 import QtWidgets, QtCore
from PyQt6.QtWidgets import QLineEdit

# 授權的廠商 ID 和產品 ID（十進制格式）
AUTHORIZED_VENDORS = [4703]  # 替換為合法的廠商 ID（十進制）
AUTHORIZED_PRODUCTS = [0]     # 替換為合法的產品 ID（十進制）

# 獲取 Windows 系統上 USB 設備的序列號
def get_usb_serial_number_windows(vendor_id, product_id):
    import wmi
    c = wmi.WMI()
    for usb in c.Win32_USBHub():
        # 獲取 DeviceID 以分割廠商和產品 ID
        device_parts = usb.DeviceID.split('&')
        if len(device_parts) < 3:
            continue
        current_vendor_id = f"0x{int(device_parts[1], 16):04x}"
        current_product_id = f"0x{int(device_parts[2], 16):04x}"
        if current_vendor_id.lower() == vendor_id.lower() and current_product_id.lower() == product_id.lower():
            # 獲取序列號
            serial_number = usb.PNPDeviceID.split('\\')[-1]
            return serial_number
    return None

# 獲取 Linux 系統上 USB 設備的序列號
def get_usb_serial_number_linux(vendor_id, product_id):
    import pyudev
    context = pyudev.Context()
    for device in context.list_devices(subsystem='usb', DEVTYPE='usb_device'):
        if device.attributes.get('idVendor') == str(vendor_id).zfill(4) and \
           device.attributes.get('idProduct') == str(product_id).zfill(4):
            serial = device.attributes.get('serial')
            if serial:
                return serial.decode()
    return None

# 獲取 macOS 系統上 USB 設備的序列號
def get_usb_serial_number_macos(vendor_id_dec, product_id_dec):
    try:
        cmd = ['ioreg', '-p', 'IOUSB', '-l', '-w', '0']
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)

        # 使用更寬鬆的正則表達式
        pattern = re.compile(
            r'"USB Serial Number"\s*=\s*"(.*?)".*?'  # 先匹配 USB Serial Number
            r'"idVendor"\s*=\s*(\d+).*?'  # 再匹配 idVendor
            r'"idProduct"\s*=\s*(\d+)',  # 最後匹配 idProduct
            re.IGNORECASE | re.DOTALL
        )

        matches = pattern.finditer(output)

        for match in matches:
            usb_serial = match.group(1)  # 先獲取 USB Serial Number
            idVendor = int(match.group(2))
            idProduct = int(match.group(3))

            if idVendor == vendor_id_dec and idProduct == product_id_dec:
                print(f"找到設備：Vendor ID: {idVendor}, Product ID: {idProduct}, Serial: {usb_serial}")
                return usb_serial

        print(f"未找到匹配的設備：Vendor ID: {vendor_id_dec}, Product ID: {product_id_dec}")
        return None

    except subprocess.CalledProcessError as e:
        print(f"執行 ioreg 時出錯：{e.output}")
        return None
    except Exception as e:
        print(f"意外錯誤：{e}")
        return None

# 根據操作系統選擇適當的方法獲取 USB 序列號
def get_usb_serial_number(vendor_id, product_id):
    if sys.platform.startswith('win'):
        return get_usb_serial_number_windows(vendor_id, product_id)
    elif sys.platform.startswith('linux'):
        return get_usb_serial_number_linux(vendor_id, product_id)
    elif sys.platform.startswith('darwin'):
        return get_usb_serial_number_macos(vendor_id, product_id)
    else:
        raise NotImplementedError("不支持的平台")

# 獲取 Windows 系統上 USB 設備的掛載點
def get_mount_point_windows(vendor_id, product_id):
    import win32api
    drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
    for drive in drives:
        try:
            drive_info = win32api.GetVolumeInformation(drive)
            # 根據需要添加更多檢查
            return drive
        except:
            continue
    return None

# 獲取 Linux 系統上 USB 設備的掛載點
def get_mount_point_linux():
    import psutil
    partitions = psutil.disk_partitions()
    for partition in partitions:
        if 'removable' in partition.opts or 'usb' in partition.device:
            return partition.mountpoint
    return None

# 獲取 macOS 系統上 USB 設備的掛載點
def get_mount_point_macos():
    try:
        cmd = ['mount']
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        lines = output.splitlines()
        for line in lines:
            if 'disk' in line and 'external' in line:
                # 提取掛載點
                parts = line.split(' on ')
                if len(parts) >= 2:
                    mount_point = parts[1].split(' (')[0]
                    return mount_point
        return None
    except subprocess.CalledProcessError as e:
        print(f"執行 mount 命令時出錯：{e.output}")
        return None
    except Exception as e:
        print(f"意外錯誤：{e}")
        return None

# 根據操作系統選擇適當的方法獲取 USB 掛載點
def get_mount_point():
    if sys.platform.startswith('win'):
        return get_mount_point_windows(None, None)
    elif sys.platform.startswith('linux'):
        return get_mount_point_linux()
    elif sys.platform.startswith('darwin'):
        return get_mount_point_macos()
    else:
        return None

# 從 USB 設備讀取密鑰
def read_key_from_usb(usb_path):
    key_file_path = os.path.join(usb_path, 'key.dat')
    if os.path.exists(key_file_path):
        with open(key_file_path, 'rb') as f:
            key = f.read()
        return key
    else:
        raise FileNotFoundError("USB 上未找到密鑰文件。")

# 根據密碼和硬體信息派生加密密鑰
def derive_key(password, vendor_id, product_id, serial_number):
    # 將十六進制ID轉回字符串格式（帶0x前綴）
    vendor_id_hex = vendor_id.lower()
    product_id_hex = product_id.lower()
    # 結合硬體識別資訊
    combined_salt = (vendor_id_hex + product_id_hex + serial_number).encode()

    # 使用 PBKDF2HMAC 來派生加密金鑰
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=combined_salt,  # 使用硬體資訊作為鹽
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# 執行文件解密操作
def decrypt_file_action(encrypted_file_path, decrypted_file_path, key):
    fernet = Fernet(key)
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

# 檢測並讀取授權的 USB 設備
def detect_and_read_usb():
    # 使用 pyusb 查找所有連接的USB裝置
    devices = usb.core.find(find_all=True)
    for device in devices:
        vendor_id = device.idVendor      # 十進制
        product_id = device.idProduct    # 十進制
        serial_number = get_usb_serial_number(vendor_id, product_id)
        if is_authorized_device(vendor_id, product_id, serial_number):
            usb_path = get_mount_point()
            if usb_path:
                try:
                    key = read_key_from_usb(usb_path)
                    return vendor_id, product_id, serial_number, key
                except Exception as e:
                    print(f'密鑰讀取失敗: {str(e)}')
    raise Exception('未檢測到授權的 USB 裝置。')

# 文件解密器 GUI 類
class FileDecryptor(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.usb_info = None

    # 初始化 GUI
    def init_ui(self):
        self.setWindowTitle('機密文件解密程式')

        layout = QtWidgets.QVBoxLayout()

        self.status_label = QtWidgets.QLabel('檢測 USB 裝置...')
        layout.addWidget(self.status_label)

        self.password_label = QtWidgets.QLabel('輸入密碼:')
        layout.addWidget(self.password_label)

        self.password_input = QtWidgets.QLineEdit()
        # 根據PyQt版本設置EchoMode
        if hasattr(QtWidgets.QLineEdit, 'Password'):
            self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)  # PyQt5
        else:
            self.password_input.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)  # PyQt6
        layout.addWidget(self.password_input)

        self.decrypt_button = QtWidgets.QPushButton('解密文件')
        self.decrypt_button.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decrypt_button)

        self.setLayout(layout)

        QtCore.QTimer.singleShot(1000, self.detect_usb)

    # 檢測 USB 設備
    def detect_usb(self):
        try:
            vendor_id, product_id, serial_number, usb_key = detect_and_read_usb()
            self.usb_info = {
                'vendor_id_dec': vendor_id,
                'product_id_dec': product_id,
                'serial_number': serial_number,
                'key': usb_key
            }
            self.status_label.setText(f'授權 USB 檢測成功: {vendor_id} / {product_id} / 序列號: {serial_number}')
        except Exception as e:
            self.status_label.setText(str(e))

    # 執行文件解密
    def decrypt_file(self):
        if not self.usb_info:
            QtWidgets.QMessageBox.warning(self, '警告', '未檢測到授權的 USB 裝置。')
            return
        password = self.password_input.text()
        if not password:
            QtWidgets.QMessageBox.warning(self, '警告', '請輸入密碼。')
            return
        try:
            # 使用原始十六進制ID來派生密鑰
            vendor_id_hex = f"0x{self.usb_info['vendor_id_dec']:04x}"
            product_id_hex = f"0x{self.usb_info['product_id_dec']:04x}"
            key = derive_key(password, vendor_id_hex, product_id_hex, self.usb_info['serial_number'])
            encrypted_file = QtWidgets.QFileDialog.getOpenFileName(self, '選擇加密文件')[0]
            if not encrypted_file:
                return
            decrypted_file = os.path.splitext(encrypted_file)[0] + '_decrypted' + os.path.splitext(encrypted_file)[1]
            decrypt_file_action(encrypted_file, decrypted_file, key)
            QtWidgets.QMessageBox.information(self, '成功', f'文件已成功解密至 {decrypted_file}')
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, '錯誤', f'解密失敗: {str(e)}')

# 檢查設備是否授權
def is_authorized_device(vendor_id_dec, product_id_dec, serial_number):
    # 在此處您可以進一步驗證序列號是否在授權列表中
    # 目前僅驗證vendor_id和product_id是否在授權列表中
    return (vendor_id_dec in AUTHORIZED_VENDORS) and \
           (product_id_dec in AUTHORIZED_PRODUCTS) and \
           (serial_number is not None)

if __name__ == '__main__':
    #app = QtWidgets.QApplication(sys.argv)
    #window = FileDecryptor()
    #window.show()
    #sys.exit(app.exec())

    r = get_usb_serial_number_macos(4703, 0)
    print(r)
