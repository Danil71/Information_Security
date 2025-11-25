QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets sql

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

OPENSSL_ROOT = "C:/Program Files/OpenSSL-Win64"
INCLUDEPATH += $$OPENSSL_ROOT/include
LIBS += -L$$OPENSSL_ROOT/lib/VC/ -llibcrypto64MD -llibssl64MD

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    src/crypto.cpp \
    src/main.cpp \
    src/mainwindow.cpp \
    src/usermanager.cpp

HEADERS += \
    headers/crypto.h \
    headers/mainwindow.h \
    headers/usermanager.h \
    mainwindow.h \
    src/usermanager.h

FORMS += \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
