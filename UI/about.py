# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'about.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(702, 533)
        Form.setStyleSheet("background-color: #e0f7fa")
        self.label = QtWidgets.QLabel(Form)
        self.label.setGeometry(QtCore.QRect(20, 40, 291, 41))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(24)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(Form)
        self.label_2.setGeometry(QtCore.QRect(20, 80, 351, 21))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(16)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(Form)
        self.label_3.setGeometry(QtCore.QRect(130, 170, 141, 21))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(16)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(Form)
        self.label_4.setGeometry(QtCore.QRect(130, 200, 141, 21))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(16)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(Form)
        self.label_5.setGeometry(QtCore.QRect(130, 230, 321, 21))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(16)
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_5")
        self.label_6 = QtWidgets.QLabel(Form)
        self.label_6.setGeometry(QtCore.QRect(130, 260, 201, 21))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(16)
        self.label_6.setFont(font)
        self.label_6.setObjectName("label_6")
        self.label_7 = QtWidgets.QLabel(Form)
        self.label_7.setGeometry(QtCore.QRect(130, 290, 281, 21))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(16)
        self.label_7.setFont(font)
        self.label_7.setObjectName("label_7")
        self.label_8 = QtWidgets.QLabel(Form)
        self.label_8.setGeometry(QtCore.QRect(130, 320, 201, 21))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(16)
        self.label_8.setFont(font)
        self.label_8.setObjectName("label_8")
        self.label_9 = QtWidgets.QLabel(Form)
        self.label_9.setGeometry(QtCore.QRect(130, 350, 201, 21))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(16)
        self.label_9.setFont(font)
        self.label_9.setText("")
        self.label_9.setObjectName("label_9")
        self.label_10 = QtWidgets.QLabel(Form)
        self.label_10.setGeometry(QtCore.QRect(10, 380, 351, 21))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(16)
        self.label_10.setFont(font)
        self.label_10.setObjectName("label_10")
        self.label_11 = QtWidgets.QLabel(Form)
        self.label_11.setGeometry(QtCore.QRect(10, 410, 411, 21))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(16)
        self.label_11.setFont(font)
        self.label_11.setObjectName("label_11")
        self.label_12 = QtWidgets.QLabel(Form)
        self.label_12.setGeometry(QtCore.QRect(10, 440, 611, 21))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(16)
        self.label_12.setFont(font)
        self.label_12.setObjectName("label_12")
        self.label_13 = QtWidgets.QLabel(Form)
        self.label_13.setGeometry(QtCore.QRect(10, 470, 471, 31))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(16)
        self.label_13.setFont(font)
        self.label_13.setObjectName("label_13")

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.label.setText(_translate("Form", "关于河众反病毒软件"))
        self.label_2.setText(_translate("Form", "About Hezhong AntiVirus SoftWare"))
        self.label_3.setText(_translate("Form", "界面设计：tjsh"))
        self.label_4.setText(_translate("Form", "程序核心：tjsh"))
        self.label_5.setText(_translate("Form", "启发引擎：lyz 和 tjsh"))
        self.label_6.setText(_translate("Form", "Yara引擎：VirusTotal"))
        self.label_7.setText(_translate("Form", "Yara规则：ClamAV 和 tjsh"))
        self.label_8.setText(_translate("Form", "MD5库：tjsh"))
        self.label_10.setText(_translate("Form", "软件网站：https://bbs.hezhongkj.top"))
        self.label_11.setText(_translate("Form", "软件开源仓库：https://gitee.com/tjsh/hzav/"))
        self.label_12.setText(_translate("Form", "软件遵守GPLv3协议开源 禁止使用我们的代码商用（例如：出售）"))
        self.label_13.setText(_translate("Form", "河众科技©  版权所有    Hezhong Technology ©"))