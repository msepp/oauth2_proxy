// +build !go1.3 plan9 solaris

package main

import "github.com/msepp/oauth2_proxy/v4/pkg/logger"

func WatchForUpdates(filename string, done <-chan bool, action func()) {
	logger.Printf("file watching not implemented on this platform")
	go func() { <-done }()
}
