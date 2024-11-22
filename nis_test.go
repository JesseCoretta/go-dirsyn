package dirsyn

import "testing"

func TestNetgroupTriple(t *testing.T) {
	var r RFC2307
	for idx, raw := range []string{
		`(console,jc,example.com)`,
		`(-,-,-)`,
		`(-,jc,-)`,
	} {
		if trip, err := r.NetgroupTriple(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := trip.String(); got != raw {
			t.Errorf("%s[%d] failed:\nwant: %s\ngot:  %s",
				t.Name(), idx, raw, got)
		}
	}

	r.NetgroupTriple(`(?,?,?,?)`)
	r.NetgroupTriple(`??`)
	r.NetgroupTriple(`(??`)
	r.NetgroupTriple(nil)
	r.NetgroupTriple(`ÃÃ"","","",""`)
	r.NetgroupTriple(`@,\,"","Ã"`)
}

func TestBootParameter(t *testing.T) {
	var r RFC2307
	for idx, raw := range []string{
		`test=thing:path`,
	} {
		if btp, err := r.BootParameter(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := btp.String(); got != raw {
			t.Errorf("%s[%d] failed:\nwant: %s\ngot:  %s",
				t.Name(), idx, raw, got)
		}
	}

	r.BootParameter(`test=`)
	r.BootParameter(`test=;:`)
	r.BootParameter(`test:`)
	r.BootParameter(``)
	r.BootParameter(nil)
}
