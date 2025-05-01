package main

import (
	"fmt"

	"github.com/JesseCoretta/go-dirsyn"
)

/*
This example demonstrates a cursory envelope verification for JPG
encoded data. As mentioned in the comments for the JPEG method,
the actual image data is not read; rather, only the header and footer
bytes are verified.
*/
func main() {
	// Replace with an actual JPG file/path.
	path := `/tmp/reference_jpg_file_here.jpg`

	var r dirsyn.RFC4517

	if err = r.JPEG(path); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s is a valid JPEG\n", path)
}
