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
from PyQt6 import QtWidgets
from PyQt6.QtWidgets import QLineEdit

# 授權的廠商 ID 和產品 ID
AUTHORIZED_VENDORS = ['0x125f']  # 替換為合法的廠商 ID
AUTHORIZED_PRODUCTS = ['0x0']  # 替換為合法的產品 ID


def get_usb_serial_number_windows(vendor_id, product_id):
    import wmi
    c = wmi.WMI()
    for usb in c.Win32_USBHub():
        if hex(int(usb.DeviceID.split('&')[1], 16)) == vendor_id and \
           hex(int(usb.DeviceID.split('&')[2], 16)) == product_id:
            # 獲取序列號
            serial_number = usb.PNPDeviceID.split('\\')[-1]
            return serial_number
    return None


def get_usb_serial_number_linux(vendor_id, product_id):
    import pyudev
    context = pyudev.Context()
    for device in context.list_devices(subsystem='usb', DEVTYPE='usb_device'):
        if device.attributes.get('idVendor') == vendor_id[2:] and \
           device.attributes.get('idProduct') == product_id[2:]:
            return device.attributes.get('serial').decode()
    return None


def get_usb_serial_number_macos(vendor_id, product_id):
    """
    獲取macOS上特定USB裝置的序列號。

    參數:
        vendor_id (str): USB裝置的廠商ID，格式為'0xXXXX'
        product_id (str): USB裝置的產品ID，格式為'0xXXXX'

    返回:
        str: USB裝置的序列號，如果未找到則返回None
    """
    try:
        # 執行ioreg命令來獲取USB裝置的詳細資訊
        cmd = ['ioreg', '-p', 'IOUSB', '-l', '-w', '0']
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)

        # 將廠商ID和產品ID轉換為十六進制字符串（不帶0x前綴）
        vendor_id_hex = vendor_id.lower().replace('0x', '')
        product_id_hex = product_id.lower().replace('0x', '')

        # 使用正則表達式來查找匹配的USB裝置
        # 序列號通常在"iSerial"屬性中
        pattern = re.compile(
            rf'"idVendor" = <0x{vendor_id_hex}>\s*'
            rf'"idProduct" = <0x{product_id_hex}>\s*'
            r'(?:.*\n)*?.*"iSerial" = "(.*?)"',
            re.IGNORECASE
        )

        match = pattern.search(output)
        if match:
            serial_number = match.group(1)
            return serial_number
        else:
            return None

    except subprocess.CalledProcessError as e:
        print(f"Error executing ioreg: {e.output}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None


def is_authorized_device(vendor_id, product_id, serial_number):
    # 可以根據需求進一步驗證序列號
    return (vendor_id in AUTHORIZED_VENDORS) and \
           (product_id in AUTHORIZED_PRODUCTS) and \
           (serial_number is not None)


def get_mount_point_windows(vendor_id, product_id):
    import win32api
    drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
    for drive in drives:
        try:
            drive_info = win32api.GetVolumeInformation(drive)
            # 這裡可以根據驅動器信息進行進一步驗證
            return drive
        except:
            continue
    return None


def get_mount_point_linux():
    import psutil
    partitions = psutil.disk_partitions()
    for partition in partitions:
        if 'removable' in partition.opts or 'usb' in partition.device:
            return partition.mountpoint
    return None


def get_mount_point_macos():
    """
    獲取macOS上USB裝置的掛載點。
    """
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
        print(f"Error executing mount: {e.output}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None


def get_usb_serial_number(vendor_id, product_id):
    if sys.platform.startswith('win'):
        return get_usb_serial_number_windows(vendor_id, product_id)
    elif sys.platform.startswith('linux'):
        return get_usb_serial_number_linux(vendor_id, product_id)
    elif sys.platform.startswith('darwin'):
        return get_usb_serial_number_macos(vendor_id, product_id)
    else:
        raise NotImplementedError("Unsupported platform")


def get_mount_point():
    if sys.platform.startswith('win'):
        return get_mount_point_windows()
    elif sys.platform.startswith('linux'):
        return get_mount_point_linux()
    elif sys.platform.startswith('darwin'):
        return get_mount_point_macos()
    else:
        return None


def read_key_from_usb(usb_path):
    key_file_path = os.path.join(usb_path, 'key.dat')
    if os.path.exists(key_file_path):
        with open(key_file_path, 'rb') as f:
            key = f.read()
        return key
    else:
        raise FileNotFoundError("USB 上未找到密鑰文件。")


def derive_key(password, vendor_id, product_id, serial_number):
    # 結合硬體識別資訊
    combined_salt = (vendor_id + product_id + serial_number).encode()

    # 使用 PBKDF2HMAC 來派生加密金鑰
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=combined_salt,  # 使用硬體資訊作為鹽
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def decrypt_file_action(encrypted_file_path, decrypted_file_path, key):
    fernet = Fernet(key)
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)


def detect_and_read_usb():
    # 使用 pyusb 查找所有連接的USB裝置
    devices = usb.core.find(find_all=True)
    for device in devices:
        vendor_id = hex(device.idVendor)
        product_id = hex(device.idProduct)
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


class FileDecryptor(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.usb_info = None

    def init_ui(self):
        self.setWindowTitle('機密文件解密程式')

        layout = QtWidgets.QVBoxLayout()

        self.status_label = QtWidgets.QLabel('檢測 USB 裝置...')
        layout.addWidget(self.status_label)

        self.password_label = QtWidgets.QLabel('輸入密碼:')
        layout.addWidget(self.password_label)

        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)  # PyQt6 的引用方式
        layout.addWidget(self.password_input)

        self.decrypt_button = QtWidgets.QPushButton('解密文件')
        self.decrypt_button.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decrypt_button)

        self.setLayout(layout)

    def detect_usb(self):
        try:
            vendor_id, product_id, serial_number, usb_key = detect_and_read_usb()
            self.usb_info = {
                'vendor_id': vendor_id,
                'product_id': product_id,
                'serial_number': serial_number,
                'key': usb_key
            }
            self.status_label.setText(f'授權 USB 檢測成功: {vendor_id} / {product_id} / 序列號: {serial_number}')
        except Exception as e:
            self.status_label.setText(str(e))

    def decrypt_file(self):
        if not self.usb_info:
            QtWidgets.QMessageBox.warning(self, '警告', '未檢測到授權的 USB 裝置。')
            return
        password = self.password_input.text()
        if not password:
            QtWidgets.QMessageBox.warning(self, '警告', '請輸入密碼。')
            return
        try:
            key = derive_key(password, self.usb_info['vendor_id'], self.usb_info['product_id'], self.usb_info['serial_number'])
            encrypted_file = QtWidgets.QFileDialog.getOpenFileName(self, '選擇加密文件')[0]
            if not encrypted_file:
                return
            decrypted_file = os.path.splitext(encrypted_file)[0] + '_decrypted' + os.path.splitext(encrypted_file)[1]
            decrypt_file_action(encrypted_file, decrypted_file, key)
            QtWidgets.QMessageBox.information(self, '成功', f'文件已成功解密至 {decrypted_file}')
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, '錯誤', f'解密失敗: {str(e)}')


if __name__ == '__main__':
    #app = QtWidgets.QApplication(sys.argv)
    #window = FileDecryptor()
    #window.show()
    #sys.exit(app.exec())

    vvendor_id, product_id, serial_number, usb_key = detect_and_read_usb()
    usb_info = {
        'vendor_id': vendor_id,
        'product_id': product_id,
        'serial_number': serial_number,
        'key': usb_key
    }
