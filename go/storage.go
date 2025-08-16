package main

import "fmt"

type DataWriter interface {
	write(string)
	read() string
}

func get_entries(url string) []string {
	return []string{url}
}

func main() {
	fmt.Println("Hello World")
	fmt.Println(get_entries("http://google.com"))
}
