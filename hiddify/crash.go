package hiddify

import (
	"fmt"
	"runtime/debug"
)

func CrashHandle(f func()) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Wireguard error!", r, string(debug.Stack()))
		}
	}()
	f()
}

func NoCrash() {
	if r := recover(); r != nil {
		fmt.Println("Wireguard error!", r, string(debug.Stack()))
	}

}
