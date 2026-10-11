THEOS_PACKAGE_SCHEME = rootless
export THEOS=/opt/theos

TARGET := iphone:clang:14.5:14.0
ARCHS = arm64 arm64e

INSTALL_TARGET_PROCESSES = CrazyRed

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = v2_侦察授权弹窗

v2_侦察授权弹窗_FILES = Tweak.x
v2_侦察授权弹窗_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
v2_侦察授权弹窗_FRAMEWORKS = UIKit Foundation

include $(THEOS)/makefiles/tweak.mk
