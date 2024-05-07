package dirsyn

import "testing"

func TestNetgroupTriple(t *testing.T) {
	var r RFC2307
	for idx, raw := range []string{
		`(console,jc,example.com)`,
		`(-,-,-)`,
		`(,jc,)`,
	} {
		if _, err := r.NetgroupTriple(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}

func TestBootParameter(t *testing.T) {
	var r RFC2307
	for idx, raw := range []string{
		`test=thing:path`,
	} {
		if _, err := r.BootParameter(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}
