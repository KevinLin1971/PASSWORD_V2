import sys
import os
import subprocess
import re
import usb.core
import usb.util
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

class USBDeviceManager:
    def __init__(self, authorized_vendors=None, authorized_products=None):
        self.authorized_vendors = authorized_vendors or []
        self.authorized_products = authorized_products or []

    def get_usb_devices(self):
        """獲取所有連接的 USB 裝置"""
        return usb.core.find(find_all=True)

    def get_usb_serial_number(self, vendor_id, product_id):
        """獲取特定 USB 裝置的序列號"""
        if sys.platform.startswith('darwin'):  # macOS
            return self._get_usb_serial_number_macos(vendor_id, product_id)
        else:
            raise NotImplementedError("目前只支援 macOS 平台")

    def _get_usb_serial_number_macos(self, vendor_id_dec, product_id_dec):
        try:
            cmd = ['ioreg', '-p', 'IOUSB', '-l', '-w', '0']
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)

            pattern = re.compile(
                r'"USB Serial Number"\s*=\s*"(.*?)".*?'
                r'"idVendor"\s*=\s*(\d+).*?'
                r'"idProduct"\s*=\s*(\d+)',
                re.IGNORECASE | re.DOTALL
            )

            matches = pattern.finditer(output)

            for match in matches:
                usb_serial = match.group(1)
                idVendor = int(match.group(2))
                idProduct = int(match.group(3))

                if idVendor == vendor_id_dec and idProduct == product_id_dec:
                    return usb_serial

            return None

        except Exception as e:
            print(f"獲取 USB 序列號時發生錯誤：{e}")
            return None

    def get_mount_point(self):
        """獲取 USB 裝置的掛載點"""
        if sys.platform.startswith('darwin'):  # macOS
            return self._get_mount_point_macos()
        else:
            raise NotImplementedError("目前只支援 macOS 平台")

    def _get_mount_point_macos(self):
        try:
            cmd = ['mount']
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            lines = output.splitlines()

            for line in lines:
                if 'Volumes' in line and 'PassWord' in line:
                    parts = line.split(' on ')
                    if len(parts) >= 2:
                        mount_point = parts[1].split(' (')[0]
                        return mount_point
            return None
        except Exception as e:
            print(f"獲取掛載點時發生錯誤：{e}")
            return None

    def write_data_to_usb(self, data, filename):
        """寫入數據到 USB 裝置"""
        mount_point = self.get_mount_point()
        if mount_point:
            file_path = os.path.join(mount_point, filename)
            try:
                with open(file_path, 'wb') as f:
                    f.write(data)
                print(f"數據已成功寫入到 {file_path}")
            except Exception as e:
                print(f"寫入數據時發生錯誤：{e}")
        else:
            print("未找到可用的 USB 裝置掛載點")

    def find_authorized_device(self):
        """尋找授權的 USB 裝置"""
        devices = self.get_usb_devices()
        for device in devices:
            vendor_id = device.idVendor
            product_id = device.idProduct
            if vendor_id in self.authorized_vendors and product_id in self.authorized_products:
                serial_number = self.get_usb_serial_number(vendor_id, product_id)
                if serial_number:
                    return {
                        'vendor_id': vendor_id,
                        'product_id': product_id,
                        'serial_number': serial_number
                    }
        return None

    def generate_and_save_key(self, vendor_id, product_id, serial_number):
        """根據 USB 設備信息生成金鑰並保存到 key.txt"""
        # 組合設備信息
        device_info = f"{vendor_id}:{product_id}:{serial_number}"
        
        # 使用 PBKDF2HMAC 生成金鑰，使用 serial_number 作為鹽值
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=serial_number.encode(),  # 使用 serial_number 作為鹽值
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(device_info.encode()))
        
        # 保存金鑰到 key.txt
        mount_point = self.get_mount_point()
        if mount_point:
            key_path = os.path.join(mount_point, "key.txt")
            with open(key_path, "wb") as f:
                f.write(key)
            print(f"金鑰已保存到 {key_path}")
            return key
        else:
            print("未找到 USB 設備掛載點，無法保存金鑰")
            return None

    def read_key_from_usb(self):
        """從 USB 設備的 key.txt 讀取金鑰"""
        mount_point = self.get_mount_point()
        if mount_point:
            key_path = os.path.join(mount_point, "key.txt")
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    return f.read()
            else:
                print("key.txt 不存在")
                return None
        else:
            print("未找到 USB 設備掛載點")
            return None

    def encrypt_file(self, file_path):
        """加密文件"""
        key = self.read_key_from_usb()
        if key:
            fernet = Fernet(key)
            with open(file_path, "rb") as file:
                file_data = file.read()
            encrypted_data = fernet.encrypt(file_data)
            encrypted_file_path = file_path + ".encrypted"
            with open(encrypted_file_path, "wb") as file:
                file.write(encrypted_data)
            print(f"文件已加密並保存為 {encrypted_file_path}")
        else:
            print("無法讀取金鑰，加密失敗")

    def decrypt_file(self, encrypted_file_path):
        """解密文件"""
        key = self.read_key_from_usb()
        if key:
            fernet = Fernet(key)
            with open(encrypted_file_path, "rb") as file:
                encrypted_data = file.read()
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
                decrypted_file_path = encrypted_file_path.replace(".encrypted", ".decrypted")
                with open(decrypted_file_path, "wb") as file:
                    file.write(decrypted_data)
                print(f"文件已解密並保存為 {decrypted_file_path}")
            except:
                print("解密失敗，可能是金鑰不正確")
        else:
            print("無法讀取金鑰，解密失敗")

# 使用示例
if __name__ == '__main__':
    authorized_vendors = [4703]
    authorized_products = [0]

    usb_manager = USBDeviceManager(authorized_vendors, authorized_products)
    
    # 尋找授權的 USB 裝置
    authorized_device = usb_manager.find_authorized_device()
    if authorized_device:
        print(f"找到授權的 USB 裝置：")
        print(f"廠商 ID: {authorized_device['vendor_id']}")
        print(f"產品 ID: {authorized_device['product_id']}")
        print(f"序列號: {authorized_device['serial_number']}")

        
        
        # 生成並保存金鑰
        key = usb_manager.generate_and_save_key(
            authorized_device['vendor_id'],
            authorized_device['product_id'],
            authorized_device['serial_number']
        )
        
        key = usb_manager.read_key_from_usb()

        if key:
            # 加密文件示例
            file_to_encrypt = input("請輸入要加密的文件路徑：")
            usb_manager.encrypt_file(file_to_encrypt)

            # 解密文件示例
            file_to_decrypt = input("請輸入要解密的文件路徑：")
            usb_manager.decrypt_file(file_to_decrypt)
    else:
        print("未找到授權的 USB 裝置")