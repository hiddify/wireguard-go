package hiddify

import (
	"fmt"
	"runtime/debug"
)

func CrashHandle(f func()) {
	defer NoCrash()
	f()
}

func NoCrash() {
	if r := recover(); r != nil {
		fmt.Println("Wireguard error!", r, string(debug.Stack()))
	}

}
