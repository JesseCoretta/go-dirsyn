package dirsyn

import (
	"testing"
)

func TestNetscapeACIv3_Instruction(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `( targetfilter = "(&(objectClass=employee)(objectClass=engineering))" )( targetcontrol = "1.2.3.4" || "5.6.7.8" )( targetscope = "onelevel" )(version 3.0; acl "Allow read and write for anyone using greater than or equal 128 SSF - extra nesting"; allow(read,write) ( ( ( userdn = "ldap:///anyone" ) AND ( ssf >= "71" ) ) AND NOT ( dayofweek = "Wed" OR dayofweek = "Fri" ) ); )`,
			Want: `(targetfilter="(&(objectClass=employee)(objectClass=engineering))")(targetcontrol="1.2.3.4"||"5.6.7.8")(targetscope="onelevel")(version 3.0; acl "Allow read and write for anyone using greater than or equal 128 SSF - extra nesting"; allow(read,write) (((userdn="ldap:///anyone") AND (ssf>="71")) AND NOT (dayofweek="Wed" OR dayofweek="Fri"));)`,
		},
		{
			Orig: `( targetfilter = "(&(objectClass=employee)(objectClass=engineering))" )( targetcontrol = "1.2.3.4" || "5.6.7.8" )( targetscope = "onelevel" )(version 3.0; acl "Allow read and write for anyone using greater than or equal 128 SSF - extra nesting"; allow(read,write) ( ( ( userdn = "ldap:///anyone" ) AND ( ssf >= "71" ) ) AND NOT ( dayofweek = "Wed" OR dayofweek = "Fri" ) ); deny(proxy,selfwrite) ( userdn = "ldap:///all" ); )`,
			Want: `(targetfilter="(&(objectClass=employee)(objectClass=engineering))")(targetcontrol="1.2.3.4"||"5.6.7.8")(targetscope="onelevel")(version 3.0; acl "Allow read and write for anyone using greater than or equal 128 SSF - extra nesting"; allow(read,write) (((userdn="ldap:///anyone") AND (ssf>="71")) AND NOT (dayofweek="Wed" OR dayofweek="Fri")); deny(selfwrite,proxy) (userdn="ldap:///all");)`,
		},
		{
			Orig: `( target = "ldap:///uid=*,ou=People,dc=example,dc=com" )(version 3.0; acl "Limit people access to timeframe"; allow(read,search,compare) ( ( timeofday >= "1730" AND timeofday < "2400" ) AND ( userdn = "ldap:///uid=jesse,ou=admin,dc=example,dc=com" OR userdn = "ldap:///uid=courtney,ou=admin,dc=example,dc=com" ) AND NOT ( userattr = "ninja#FALSE" ) ); )`,
			Want: `(target="ldap:///uid=*,ou=People,dc=example,dc=com")(version 3.0; acl "Limit people access to timeframe"; allow(read,search,compare) ((timeofday>="1730" AND timeofday<"2400") AND (userdn="ldap:///uid=jesse,ou=admin,dc=example,dc=com" OR userdn="ldap:///uid=courtney,ou=admin,dc=example,dc=com") AND NOT (userattr="ninja#FALSE"));)`,
		},
	}

	for idx, obj := range tests {
		x, err := r.Instruction(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestNetscapeACIv3_PermissionBindRuleItem(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `allow(read,search,compare) ((ssf >= "(&(objectClass=*)(cn=testing 1 2 3))" OR userdn="thedn") AND NOT (ssf = "256" OR ssf = "255") );`,
			Want: `allow(read,search,compare) ((ssf>="(&(objectClass=*)(cn=testing 1 2 3))" OR userdn="thedn") AND NOT (ssf="256" OR ssf="255"));`,
		},
	}

	for idx, obj := range tests {
		x, err := r.PermissionBindRuleItem(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestNetscapeACIv3_PermissionBindRule(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `allow(read,search,compare) ((ssf >= "(&(objectClass=*)(cn=testing 1 2 3))" OR userdn = "thedn") AND NOT (ssf = "256" OR ssf = "255") ); deny(proxy, add) (timeofday > "1700" AND timeofday <= "1900");`,
			Want: `allow(read,search,compare) ((ssf>="(&(objectClass=*)(cn=testing 1 2 3))" OR userdn="thedn") AND NOT (ssf="256" OR ssf="255")); deny(add,proxy) (timeofday>"1700" AND timeofday<="1900");`,
		},
	}

	for idx, obj := range tests {
		x, err := r.PermissionBindRule(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestNetscapeACIv3_BindRuleItem(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `ssf >= "(&(objectClass=*)(cn=testing 1 2 3))"`,
			Want: `ssf>="(&(objectClass=*)(cn=testing 1 2 3))"`,
		},
		{
			Orig: `( ssf >= "(&(objectClass=*)(cn=testing 1 2 3))" )`,
			Want: `(ssf>="(&(objectClass=*)(cn=testing 1 2 3))")`,
		},
	}

	for idx, obj := range tests {
		x, err := r.BindRuleItem(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestNetscapeACIv3_BindRuleAnd(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig []any
		Want string
	}{
		{
			Orig: []any{
				`ssf >= "128"`,
				`( userdn = "uid=jesse,ou=People,o=example" )`,
			},
			Want: `ssf>="128" AND (userdn="uid=jesse,ou=People,o=example")`,
		},
	}

	for idx, obj := range tests {
		x, err := r.BindRuleAnd(obj.Orig...)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestNetscapeACIv3_BindRuleOr(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig []any
		Want string
	}{
		{
			Orig: []any{
				`userdn = "uid=jesse,ou=People,o=example"`,
				`userdn = "uid=courtney,ou=People,o=example"`,
			},
			Want: `userdn="uid=jesse,ou=People,o=example" OR userdn="uid=courtney,ou=People,o=example"`,
		},
	}

	for idx, obj := range tests {
		x, err := r.BindRuleOr(obj.Orig...)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestNetscapeACIv3_BindRuleNot(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		And  string
		Not  string
		Want string
	}{
		{
			And:  `userdn = "uid=jesse,ou=People,o=example"`,
			Not:  `( userdn = "uid=courtney,ou=People,o=example" )`,
			Want: `userdn="uid=jesse,ou=People,o=example" AND NOT (userdn="uid=courtney,ou=People,o=example")`,
		},
	}

	for idx, obj := range tests {
		x, err := r.BindRuleAnd(obj.And)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else {
			var z ACIv3BindRule
			if z, err = r.BindRuleNot(obj.Not); err != nil {
				t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
				return
			}
			x.Push(z)

			if got := x.String(); got != obj.Want {
				t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
				return
			}
		}
	}
}

func TestNetscapeACIv3_Permission(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig        string
		Want        string
		Disposition bool // true:allow/false:deny
	}{
		{
			Orig:        `allow(read,search,compare)`,
			Want:        `allow(read,search,compare)`,
			Disposition: true,
		},
		{
			Orig:        `deny(write,proxy)`,
			Want:        `deny(write,proxy)`,
			Disposition: false,
		},
	}

	for idx, obj := range tests {
		x, err := r.Permission(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if disp := x.Disposition() == "allow"; disp != obj.Disposition {
			t.Errorf("%s[%d] failed:\n\twant: %t\n\tgot:  %t", t.Name(), idx, obj.Disposition, disp)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestNetscapeACIv3_BindRule(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `((ssf >= "(&(objectClass=*)(cn=testing 1 2 3))" OR userdn="thedn") AND NOT (ssf = "256" OR ssf = "255") )`,
			Want: `((ssf>="(&(objectClass=*)(cn=testing 1 2 3))" OR userdn="thedn") AND NOT (ssf="256" OR ssf="255"))`,
		},
	}

	for idx, obj := range tests {
		x, err := r.BindRule(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Logf("%T\n", x)
			t.Logf("%d :: %T ... %T\n", x.Len(), x.Index(0), x.Index(1))
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestNetscapeACIv3_TargetRule(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `(targetfilter = "(&(objectClass=account)(roleName=User))")(targetattr="cn||sn||givenName")`,
			Want: `(targetfilter="(&(objectClass=account)(roleName=User))")(targetattr="cn||sn||givenName")`,
		},
	}

	for idx, obj := range tests {
		x, err := r.TargetRule(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestNetscapeACIv3_TargetRuleItem(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `( targetattr = "cn || sn || givenName" )`,
			Want: `(targetattr="cn || sn || givenName")`,
		},
		{
			Orig: `(targetfilter = "(&(objectClass=account)(roleName=User))")`,
			Want: `(targetfilter="(&(objectClass=account)(roleName=User))")`,
		},
	}

	for idx, obj := range tests {
		x, err := r.TargetRuleItem(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestNetscapeACIv3_AttributeFilterOperation(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `add=homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta)) && gecos:(|(objectClass=contractor)(objectClass=intern)),delete=uidNumber:(&(objectClass=accounting)(terminated=FALSE)) && gidNumber:(objectClass=account)`,
			Want: `add=homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta)) && gecos:(|(objectClass=contractor)(objectClass=intern)),delete=uidNumber:(&(objectClass=accounting)(terminated=FALSE)) && gidNumber:(objectClass=account)`,
		},
	}

	for idx, obj := range tests {
		x, err := r.AttributeFilterOperation(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestNetscapeACIv3_AttributeFilterOperationItem(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `add=homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta)) && gecos:(|(objectClass=contractor)(objectClass=intern))`,
			Want: `add=homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta)) && gecos:(|(objectClass=contractor)(objectClass=intern))`,
		},
	}

	for idx, obj := range tests {
		x, err := r.AttributeFilterOperationItem(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}

func TestNetscapeACIv3_AttributeFilter(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta))`,
			Want: `homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta))`,
		},
	}

	for idx, obj := range tests {
		x, err := r.AttributeFilter(obj.Orig)
		if err != nil {
			t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
			return
		} else if got := x.String(); got != obj.Want {
			t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
			return
		}
	}
}
