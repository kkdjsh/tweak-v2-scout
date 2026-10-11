THEOS_PACKAGE_SCHEME = rootless
export THEOS=/opt/theos

TARGET := iphone:clang:14.5:14.0
ARCHS = arm64 arm64e

INSTALL_TARGET_PROCESSES = CrazyRed

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = v2scout

v2scout_FILES = Tweak.x
v2scout_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
v2scout_FRAMEWORKS = UIKit Foundation

include $(THEOS)/makefiles/tweak.mk
