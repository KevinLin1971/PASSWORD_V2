# 第一次運行時會生成 secret.key 文件
# 之後運行會讀取 secret.key 文件中的密鑰進行加密
# 讀取 USB 設備信息,然後將信息加密後寫入到 authorized_devices.json 文件中,已方便下次運行時讀取已授權的設備

import json
import os
from PySide6 import QtWidgets
from PySide6.QtCore import QSize, Qt, Signal, QTimer
from PySide6.QtWidgets import QVBoxLayout, QPushButton, QLabel, QListWidget, QStyledItemDelegate, QMessageBox, QInputDialog, QDialog, QTextEdit, QApplication
from PySide6.QtGui import QPainter, QColor
import usb.core
import usb.util
from cryptography.fernet import Fernet
from mnemonic import Mnemonic
import base64
import sys

# 確保 Data 目錄存在
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Data')
os.makedirs(DATA_DIR, exist_ok=True)

class USBDeviceItemDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        super().paint(painter, option, index)
        if index.row() > 0:
            painter.save()
            painter.setPen(QColor(200, 200, 200))
            painter.drawLine(option.rect.topLeft(), option.rect.topRight())
            painter.restore()

class MnemonicDialog(QDialog):
    def __init__(self, mnemonic, parent=None):
        super().__init__(parent)
        self.setWindowTitle("重要信息 - 請保存您的助記詞")
        self.setMinimumSize(400, 300)

        layout = QVBoxLayout(self)

        # 創建一個只讀的文本區域來顯示助記詞
        self.textEdit = QTextEdit(self)
        self.textEdit.setPlainText(mnemonic)
        self.textEdit.setReadOnly(True)
        layout.addWidget(self.textEdit)

        # 添加一個複製按鈕
        copyButton = QPushButton("複製助記詞", self)
        copyButton.clicked.connect(self.copy_mnemonic)
        layout.addWidget(copyButton)

        # 添加一個確認按鈕
        confirmButton = QPushButton("我已安全保存助記詞", self)
        confirmButton.clicked.connect(self.accept)
        layout.addWidget(confirmButton)

    def copy_mnemonic(self):
        QApplication.clipboard().setText(self.textEdit.toPlainText())

class USBSelector(QtWidgets.QWidget):
    show_message_signal = Signal(str, str)  # 自定義信號，參數為(標題, 內容)

    def __init__(self):
        super().__init__()
        self.init_ui()
        self.usb_devices = []
        self.fernet, self.mnemonic = self.setup_encryption()
        self.setMinimumWidth(400)  # 設置最小寬度為 400 像素

        # 連接信號到槽
        self.show_message_signal.connect(self.show_message)

        # 使用 QTimer 來延遲發送信號，確保主視窗已經顯示
        QTimer.singleShot(100, self.check_and_show_message)

    def init_ui(self):
        self.setWindowTitle("USB 選擇器")
        layout = QVBoxLayout()

        self.label = QLabel("請選擇 USB 裝置")
        layout.addWidget(self.label)

        self.device_list = QListWidget()
        self.device_list.setItemDelegate(USBDeviceItemDelegate())
        layout.addWidget(self.device_list)

        self.refresh_button = QPushButton("重新整理裝置列表")
        self.refresh_button.clicked.connect(self.refresh_devices)
        layout.addWidget(self.refresh_button)

        self.select_button = QPushButton("選擇 USB 裝置")
        self.select_button.clicked.connect(self.select_usb_device)
        layout.addWidget(self.select_button)

        self.setLayout(layout)

    def setup_encryption(self):
        key_file = os.path.join(DATA_DIR, "secret.key")
        mnemonic_file = os.path.join(DATA_DIR, "mnemonic.txt")
        
        if os.path.exists(key_file) and os.path.exists(mnemonic_file):
            # 如果密鑰文件和助記詞文件都存在，讀取它們
            with open(key_file, "rb") as file:
                key = file.read()
            key = base64.urlsafe_b64encode(base64.urlsafe_b64decode(key))
            with open(mnemonic_file, "r", encoding="utf-8") as file:
                mnemonic = file.read().strip()
            return Fernet(key), mnemonic
        else:
            # 如果密鑰文件或助記詞文件不存在，設置一個標誌
            self.need_key_generation = True
            # 返回 None 值，稍後再生成
            return None, None

    def check_and_show_message(self):
        if hasattr(self, 'need_key_generation') and self.need_key_generation:
            self.show_message_signal.emit("密鑰不存在", "未找到密鑰文件。您想要重新產生新的密鑰還是使用助記詞恢復？")

    def show_message(self, title, message):
        reply = QMessageBox.question(self, title, message,
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.Yes)
        if reply == QMessageBox.StandardButton.Yes:
            self.generate_new_key()
        else:
            self.recover_from_mnemonic()

    def generate_new_key(self):
        mnemo = Mnemonic("english")
        mnemonic = mnemo.generate(strength=256)  # 生成24個單詞的助記詞
        seed = mnemo.to_seed(mnemonic)
        key = base64.urlsafe_b64encode(seed[:32])  # 使用種子的前32字節，並進行base64編碼
        
        # 只保存密鑰，不保存助記詞
        with open(os.path.join(DATA_DIR, "secret.key"), "wb") as file:
            file.write(key)
        
        self.fernet = Fernet(key)
        self.mnemonic = mnemonic
        
        # 顯示助記詞對話框
        dialog = MnemonicDialog(mnemonic, self)
        dialog.exec()

    def recover_from_mnemonic(self):
        mnemonic, ok = QInputDialog.getText(self, "恢復密鑰", "請輸入您的助記詞（24個單詞，用空格分隔）：")
        if ok:
            mnemo = Mnemonic("english")
            if mnemo.check(mnemonic):
                seed = mnemo.to_seed(mnemonic)
                key = base64.urlsafe_b64encode(seed[:32])
                
                # 只保存密鑰，不保存助記詞
                with open(os.path.join(DATA_DIR, "secret.key"), "wb") as file:
                    file.write(key)
                
                self.fernet = Fernet(key)
                self.mnemonic = mnemonic
                QMessageBox.information(self, "成功", "密鑰已成功恢復。")
            else:
                QMessageBox.warning(self, "錯誤", "無效的助記詞。請確保您輸入了正確的24個單詞。")
                self.recover_from_mnemonic()  # 重試
        else:
            # 使用者取消了輸入，我們可以選擇退出程序或重新開始流程
            reply = QMessageBox.question(self, "取消操作", "您取消了助記詞輸入。是否要重新產生新的密鑰？",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                         QMessageBox.StandardButton.Yes)
            if reply == QMessageBox.StandardButton.Yes:
                self.generate_new_key()
            else:
                sys.exit()  # 退出程序

    def refresh_devices(self):
        self.device_list.clear()
        self.usb_devices = []
        
        try:
            all_devices = list(usb.core.find(find_all=True))
            print(f"找到 {len(all_devices)} 個 USB 設備")

            for device in all_devices:
                try:
                    cfg = device.get_active_configuration()
                    intf = cfg[(0,0)]
                    
                    if intf.bInterfaceClass == 8:
                        try:
                            serial_number = usb.util.get_string(device, device.iSerialNumber)
                        except:
                            serial_number = "未知"

                        try:
                            product_name = usb.util.get_string(device, device.iProduct)
                        except:
                            product_name = "未知產品"

                        self.usb_devices.append(device)
                        
                        item = QtWidgets.QListWidgetItem()
                        item.setText(f"{product_name}\n廠商 ID: {device.idVendor:04x}, 產品 ID: {device.idProduct:04x}, 序號: {serial_number}")
                        item.setSizeHint(QSize(item.sizeHint().width(), 50))  # 增加高度以容納分隔線
                        
                        self.device_list.addItem(item)
                        
                        print(f"設備: {product_name}, 廠商 ID: {device.idVendor:04x}, 產品 ID: {device.idProduct:04x}, 序號: {serial_number}")
                except Exception as e:
                    print(f"獲取設備信息時發生錯誤：{str(e)}")
                    continue

            if not self.usb_devices:
                self.label.setText("未找到大容量存儲 USB 設備")
            else:
                self.label.setText(f"找到 {len(self.usb_devices)} 個大容量存儲 USB 設備")

        except Exception as e:
            self.label.setText(f"刷新設備列表時發生錯誤：{str(e)}")
            print(f"錯誤詳情：{str(e)}")

    def select_usb_device(self):
        selected_index = self.device_list.currentRow()
        if selected_index >= 0:
            selected_device = self.usb_devices[selected_index]
            self.save_authorized_device(selected_device.idVendor, selected_device.idProduct)
            self.label.setText(f"已選擇裝置: 廠商 ID: {selected_device.idVendor:04x}, 產品 ID: {selected_device.idProduct:04x}")
        else:
            self.label.setText("請先選擇一個 USB 裝置")

    def save_authorized_device(self, vendor_id, product_id):
        device_info = {
            'vendor_id': vendor_id,
            'product_id': product_id
        }
        encrypted_data = self.fernet.encrypt(json.dumps(device_info).encode())
        
        try:
            with open(os.path.join(DATA_DIR, 'authorized_devices.json'), 'wb') as f:
                f.write(encrypted_data)
            print("設備信息已加密並保存到 Data/authorized_devices.json")
        except Exception as e:
            print(f"保存設備信息時發生錯誤：{e}")

if __name__ == "__main__":
    try:
        app = QtWidgets.QApplication(sys.argv)
        selector = USBSelector()
        selector.show()
        print("視窗已顯示")
        sys.exit(app.exec())
    except Exception as e:
        print(f"發生錯誤: {e}")
        import traceback
        traceback.print_exc()
