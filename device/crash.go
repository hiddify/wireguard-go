package device

import (
	"fmt"
	"runtime/debug"
)

func CrashHandle(f func(), device *Device) {
	defer NoCrash(device)
	f()
}

func NoCrash(device *Device) {
	if r := recover(); r != nil {
		if device != nil && device.log != nil {
			device.log.Errorf("Wireguard error %s, %s!", r, string(debug.Stack()))
		} else {
			fmt.Println("Wireguard error!", r, string(debug.Stack()))
		}
	}

}
