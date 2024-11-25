package dirsyn

import "testing"

func TestNetgroupTriple(t *testing.T) {
	var r RFC2307
	for idx, raw := range []string{
		`(console,jc,example.com)`,
		`(-,-,-)`,
		`("","","")`,
		`(-,jc,-)`,
	} {
		if trip, err := r.NetgroupTriple(raw); err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
		} else if got := trip.String(); got != raw {
			t.Errorf("%s[%d] failed:\nwant: %s\ngot:  %s",
				t.Name(), idx, raw, got)
		}
	}

	ngt := NetgroupTriple{}
	_ = ngt.String()
	ngt.setNetgroupTripleFieldByIndex(0, nil)
	ngt.setNetgroupTripleFieldByIndex(0, ``)
	ngt.setNetgroupTripleFieldByIndex(0, `this`)
	ngt.setNetgroupTripleFieldByIndex(1, IA5String(`isOnly`))
	ngt.setNetgroupTripleFieldByIndex(2, IA5String(`aTest`))
	_ = ngt.String()

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

func TestNIS_codecov(t *testing.T) {
	isKeystring(`c--l`)
	isKeystring(`-`)
	isKeystring(``)
	isKeystring(`c界j`)
	isKeystring(`A`)
	isKeystring(`abc`)
}
