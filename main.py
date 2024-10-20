import sys
import json
import usb.core
import os
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                               QComboBox, QListWidget, QTextEdit, QSplitter, QMessageBox, 
                               QInputDialog, QMenuBar, QMenu, QStatusBar, QPushButton, 
                               QDialog, QListWidgetItem)
from PySide6.QtCore import Qt, QTimer
import subprocess

# 導入 USBSelector 類
from setupUSB import USBSelector

class USBSettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setWindowTitle("USB 設定")
        self.setGeometry(200, 200, 400, 300)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.deviceList = QListWidget()
        self.updateDeviceList()
        layout.addWidget(self.deviceList)

        buttonLayout = QHBoxLayout()
        addButton = QPushButton("新增")
        deleteButton = QPushButton("刪除")
        addButton.clicked.connect(self.addDevice)
        deleteButton.clicked.connect(self.deleteDevice)
        buttonLayout.addWidget(addButton)
        buttonLayout.addWidget(deleteButton)

        layout.addLayout(buttonLayout)
        self.setLayout(layout)

    def updateDeviceList(self):
        self.deviceList.clear()
        for device in self.parent.registered_devices:
            try:
                manufacturer = device.get('manufacturer', 'Unknown')
                product = device.get('product', 'Unknown')
                identifier = device.get('device') or device.get('serial_number', 'Unknown')
                item_text = f"{manufacturer} {product} ({identifier})"
                item = QListWidgetItem(item_text)
                item.setData(Qt.UserRole, device)
                self.deviceList.addItem(item)
            except Exception as e:
                print(f"處理設備時出錯: {e}")
                print(f"設備數據: {device}")

    def addDevice(self):
        self.parent.update_usb_selector()
        self.updateDeviceList()

    def deleteDevice(self):
        currentItem = self.deviceList.currentItem()
        if currentItem:
            device = currentItem.data(Qt.UserRole)
            identifier = device.get('device') or device.get('serial_number', 'Unknown')
            reply = QMessageBox.question(self, '刪除設備', f"確定要刪除設備 {device.get('product', 'Unknown')} ({identifier}) 嗎？",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.parent.registered_devices.remove(device)
                self.parent.save_registered_devices()
                self.updateDeviceList()
                self.parent.update_usb_selector_content()

class USBFileViewer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Data')
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        self.device_json_path = os.path.join(self.data_dir, 'device.json')
        self.registered_devices = self.load_registered_devices()
        self.initUI()
        self.update_usb_selector_content()  # 立即更新 USB 選擇器內容
        QTimer.singleShot(100, self.check_registered_devices)

    def initUI(self):
        self.setWindowTitle('USB 檔案檢視器')
        self.setGeometry(100, 100, 800, 600)

        # 創建中央小部件
        centralWidget = QWidget()
        self.setCentralWidget(centralWidget)

        # 創建主佈局
        mainLayout = QHBoxLayout(centralWidget)

        # 創建左側佈局
        leftLayout = QVBoxLayout()

        # USB 來源選擇下拉選單
        self.usbSelector = QComboBox()
        self.usbSelector.addItem("選擇 USB 裝置")
        leftLayout.addWidget(self.usbSelector)

        # USB 檔案列表
        self.fileList = QListWidget()
        leftLayout.addWidget(self.fileList)

        # 將左側佈局放入一個 widget 中
        leftWidget = QWidget()
        leftWidget.setLayout(leftLayout)

        # 創建右側文件內容顯示區
        self.fileContent = QTextEdit()
        self.fileContent.setReadOnly(True)

        # 創建分割器並添加左右兩個部分
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(leftWidget)
        splitter.addWidget(self.fileContent)
        splitter.setSizes([300, 500])  # 設置初始大小

        # 將分割器添加到主佈局
        mainLayout.addWidget(splitter)

        # 創建菜單欄
        self.createMenuBar()

        # 創建狀態欄
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)

        # 連接信號和槽
        self.usbSelector.currentIndexChanged.connect(self.onUSBSelected)
        self.fileList.itemClicked.connect(self.onFileSelected)

    def createMenuBar(self):
        menuBar = self.menuBar()
        menuBar.setNativeMenuBar(False)  # 強制菜單欄顯示在窗口內部

        # 檔案菜單
        fileMenu = menuBar.addMenu('檔案')
        exitAction = fileMenu.addAction('退出')
        exitAction.triggered.connect(self.close)

        # 設定菜單
        settingsMenu = menuBar.addMenu('設定')
        usbSettingsAction = settingsMenu.addAction('USB設定')
        usbSettingsAction.triggered.connect(self.showUSBSettings)

        # 幫助菜單
        helpMenu = menuBar.addMenu('幫助')
        aboutAction = helpMenu.addAction('關於')
        aboutAction.triggered.connect(self.showAbout)

    def load_registered_devices(self):
        try:
            with open(self.device_json_path, 'r') as f:
                devices = json.load(f)
                print(f"從 {self.device_json_path} 讀取了 {len(devices)} 個設備")
                print(f"設備數據: {devices}")  # 添加這行來打印設備數據
                return devices
        except FileNotFoundError:
            print(f"未找到 {self.device_json_path} 文件")
            return []
        except json.JSONDecodeError:
            print(f"{self.device_json_path} 文件格式不正確")
            return []

    def save_registered_devices(self):
        with open(self.device_json_path, 'w') as f:
            json.dump(self.registered_devices, f, indent=4)
        print(f"已將 {len(self.registered_devices)} 個設備保存到 {self.device_json_path}")

    def check_registered_devices(self):
        if not self.registered_devices:
            reply = QMessageBox.question(self, '註冊 USB', '沒有註冊的 USB 設備。是否要註冊一個新的 USB 設備？',
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.showUSBSettings()
        # 移除這裡的 else 語句，因為我們已經在 __init__ 中更新了選擇器內容

    def update_usb_selector_content(self):
        self.usbSelector.clear()
        self.usbSelector.addItem("選擇 USB 裝置")
        for device in self.registered_devices:
            try:
                manufacturer = device.get('manufacturer', 'Unknown')
                product = device.get('product', 'Unknown')
                identifier = device.get('device') or device.get('serial_number', 'Unknown')
                self.usbSelector.addItem(f"{manufacturer} {product} ({identifier})")
            except Exception as e:
                print(f"處理設備時出錯: {e}")
                print(f"設備數據: {device}")
        print(f"已更新 USB 選擇器，共 {len(self.registered_devices)} 個設備")

    def showUSBSettings(self):
        dialog = USBSettingsDialog(self)
        dialog.exec()

    def showAbout(self):
        QMessageBox.about(self, "關於", "USB 檔案檢視器\n版本 1.0\n作者：您的名字")

    def onUSBSelected(self, index):
        if index > 0:  # 確保不是 "選擇 USB 裝置" 選項
            selected_device = self.registered_devices[index - 1]
            self.statusBar.showMessage(f"選擇了 USB 裝置: {self.usbSelector.currentText()}")
            self.load_usb_files(selected_device)
        else:
            self.fileList.clear()  # 清空文件列表
            self.statusBar.showMessage("請選擇 USB 裝置")

    def load_usb_files(self, device):
        self.fileList.clear()  # 清空之前的文件列表
        try:
            # 使用新的函數獲取掛載點
            mountpoint = self.get_mount_point()
            if not mountpoint:
                raise ValueError("無法獲取設備的掛載點")

            for root, dirs, files in os.walk(mountpoint):
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, mountpoint)
                    item = QListWidgetItem(relative_path)
                    item.setData(Qt.UserRole, file_path)  # 存儲完整文件路徑
                    self.fileList.addItem(item)

            self.statusBar.showMessage(f"已加載 {self.fileList.count()} 個文件")
        except Exception as e:
            self.statusBar.showMessage(f"讀取文件列表時出錯: {str(e)}")
            QMessageBox.warning(self, "錯誤", f"無法讀取 USB 設備中的文件：{str(e)}")

    def onFileSelected(self, item):
        # 當選擇檔案時觸發
        # 這裡可以添加讀取選定檔案內容的邏輯
        self.statusBar.showMessage(f"選擇了檔案: {item.text()}")

    def update_usb_selector(self):
        new_devices = self.get_usb_devices()
        
        if not new_devices:
            QMessageBox.information(self, "沒有找到新設備", "沒有檢測到新的 USB 設備。")
            return

        device_list = [f"{dev['manufacturer']} {dev['product']} ({dev['serial_number']})" for dev in new_devices]
        
        device, ok = QInputDialog.getItem(self, "選擇 USB 設備", 
                                          "請選擇要新增的 USB 設備：", 
                                          device_list, 0, False)
        if ok and device:
            selected_device = next(dev for dev in new_devices if f"{dev['manufacturer']} {dev['product']} ({dev['serial_number']})" == device)
            
            if not any(d['serial_number'] == selected_device['serial_number'] for d in self.registered_devices):
                self.registered_devices.append(selected_device)
                self.save_registered_devices()
                self.update_usb_selector_content()
                QMessageBox.information(self, "註冊成功", f"USB 設備 {selected_device['product']} 已成功註冊。")
            else:
                QMessageBox.information(self, "已註冊", f"USB 設備 {selected_device['product']} 已經註冊過了。")

    def get_usb_devices(self):
        all_devices = list(usb.core.find(find_all=True))
        usb_devices = []
        for device in all_devices:
            try:
                manufacturer = usb.util.get_string(device, device.iManufacturer)
                product = usb.util.get_string(device, device.iProduct)
                serial_number = usb.util.get_string(device, device.iSerialNumber)
                
                usb_devices.append({
                    'manufacturer': manufacturer,
                    'product': product,
                    'serial_number': serial_number,
                })
            except:
                # 如果無法獲取某些屬性，我們就跳過這個設備
                pass
        return usb_devices

    def get_mount_point(self):
            """獲取 USB 裝置的掛載點"""
            if sys.platform.startswith('darwin'):  # macOS
                return self.get_mount_point_macos()
            else:
                raise NotImplementedError("目前只支援 macOS 平台")

    def get_mount_point_macos(self):
        try:
            cmd = ['mount']
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            lines = output.splitlines()

            for line in lines:
                if 'Volumes' in line and 'PassWord' in line:
                    parts = line.split(' on ')
                    if len(parts) >= 2:
                        mount_point = parts[1].split(' (')[0]
                        # 檢查掛載點是否包含 .txt 文件
                        if self.has_txt_files(mount_point):
                            return mount_point
            return None
        except Exception as e:
            print(f"獲取掛載點時發生錯誤：{e}")
            return None
            
    def has_txt_files(self, directory):
        try:
            for root, dirs, files in os.walk(directory):
                print(files)
                if any(file.endswith('.txt') for file in files):
                    return True
            return False
        except Exception as e:
            print(f"檢查 .txt 文件時出錯：{e}")
            return False
    
    def _get_mount_point_macos(self):
        try:
            # 使用新的函數獲取掛載點
            cmd = ['mount']
            # mountpoint = subprocess.check_output(['diskutil', 'info', '-plist', '/dev/disk1']).decode('utf-8')
            mountpoint = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            print(mountpoint)
            if not mountpoint:
                raise ValueError("無法獲取設備的掛載點")
            return mountpoint
        except Exception as e:
            print(f"處理設備時出錯: {e}")
            print(f"設備數據: {device}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    viewer = USBFileViewer()
    viewer.show()
    sys.exit(app.exec())
