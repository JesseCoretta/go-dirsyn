package dirsyn

import "testing"

func TestNISNetgroupTriple(t *testing.T) {
	for idx, raw := range []string{
		`(console,jc,example.com)`,
		`(-,-,-)`,
		`(,jc,)`,
	} {
		if err := NISNetgroupTriple(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}

func TestBootParameter(t *testing.T) {
	for idx, raw := range []string{
		`test=thing:path`,
	} {
		if err := BootParameter(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		}
	}
}
