package dirsyn

import (
	"testing"
)

var srcs Sources

func TestSrc_codecov(t *testing.T) {
	var r0 X680
	var r1 X690
	var r2 X501
	var r3 X520
	var r4 RFC2307
	var r5 RFC3672
	var r6 RFC4511
	var r7 RFC4512
	var r8 RFC4514
	var r9 RFC4515
	var r10 RFC4516
	var r11 RFC4517
	var r12 RFC4523
	var r13 RFC4530

	srcs.ACIv3()
	srcs.X680()
	srcs.X690()
	srcs.X501()
	srcs.X520()
	srcs.RFC2307()
	srcs.RFC3672()
	srcs.RFC4511()
	srcs.RFC4512()
	srcs.RFC4514()
	srcs.RFC4515()
	srcs.RFC4516()
	srcs.RFC4517()
	srcs.RFC4523()
	srcs.RFC4530()

	r0.Document()
	r1.Document()
	r2.Document()
	r3.Document()
	r4.Document()
	r5.Document()
	r6.Document()
	r7.Document()
	r8.Document()
	r9.Document()
	r10.Document()
	r11.Document()
	r12.Document()
	r13.Document()
}
