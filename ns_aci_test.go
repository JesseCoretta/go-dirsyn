package dirsyn

import (
	"fmt"
	"testing"
	"time"
)

func ExampleNetscapeACIv3_SearchScope() {
	var r NetscapeACIv3
	scope, err := r.SearchScope("one")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(scope)
	// Output: onelevel
}

func TestNetscapeACIv3_Instruction(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `( targetfilter = "(&(objectClass=employee)(objectClass=engineering))" )( targetcontrol = "1.2.3.4" || "1.2.3.5" )( targetscope = "onelevel" )(version 3.0; acl "Allow read and write for anyone using greater than or equal 128 SSF - extra nesting"; allow(read,write) ( ( ( userdn = "ldap:///anyone" ) AND ( ssf >= "71" ) ) AND NOT ( dayofweek = "Wed" OR dayofweek = "Fri" ) ); )`,
			Want: `(targetfilter="(&(objectClass=employee)(objectClass=engineering))")(targetcontrol="1.2.3.4||1.2.3.5")(targetscope="onelevel")(version 3.0; acl "Allow read and write for anyone using greater than or equal 128 SSF - extra nesting"; allow(read,write) (((userdn="ldap:///anyone") AND (ssf>="71")) AND NOT (dayofweek="Wed" OR dayofweek="Fri"));)`,
		},
		{
			Orig: `( targetfilter = "(&(objectClass=employee)(objectClass=engineering))" )( targetcontrol = "1.2.3.4" || "1.2.3.5" )( targetscope = "onelevel" )(version 3.0; acl "Allow read and write for anyone using greater than or equal 128 SSF - extra nesting"; allow(read,write) ( ( ( userdn = "ldap:///anyone" ) AND ( ssf >= "71" ) ) AND NOT ( dayofweek = "Wed" OR dayofweek = "Fri" ) ); deny(proxy,selfwrite) ( userdn = "ldap:///all" ); )`,
			Want: `(targetfilter="(&(objectClass=employee)(objectClass=engineering))")(targetcontrol="1.2.3.4||1.2.3.5")(targetscope="onelevel")(version 3.0; acl "Allow read and write for anyone using greater than or equal 128 SSF - extra nesting"; allow(read,write) (((userdn="ldap:///anyone") AND (ssf>="71")) AND NOT (dayofweek="Wed" OR dayofweek="Fri")); deny(selfwrite,proxy) (userdn="ldap:///all");)`,
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

	// coverage
	pbr, _ := r.PermissionBindRule("allow(none) ssf>=128")
	_, _ = r.Instruction("")
	_, _ = r.Instruction("(version 3.0;")
	_, _ = r.Instruction("(version 3.0; acl \"Hello\"")
	_, _ = r.Instruction("(version 3.0; acl \"Hello\";;)")
	_, _ = r.Instruction("(version 3.0; acl 'Hello'; allow(none)")
	_, _ = r.Instruction("(version 3.0; acl \"Hello\"; allow(none) ssf>=128)")
	_, _ = r.Instruction("(version 3.0; acl \"Hello\"; allow(none) ssf>=128]")
	_, _ = r.Instruction(ACIv3TargetRule{&aCITargetRule{slice: []ACIv3TargetRuleItem{}}})
	_, _ = r.Instruction(ACIv3TargetRule{&aCITargetRule{slice: []ACIv3TargetRuleItem{}}}, "acl", ACIv3PermissionBindRule{})
	_, _ = r.Instruction(ACIv3TargetRule{&aCITargetRule{slice: []ACIv3TargetRuleItem{}}}, "acl", pbr)
	_, _ = r.Instruction(ACIv3PermissionBindRule{})
	_, _ = r.Instruction("acl", ACIv3PermissionBindRule{})
	_, _ = r.Instruction(rune(22), ACIv3PermissionBindRule{})
	_, _ = r.Instruction("my acl", "allow(none) ssf>=128")
	_, _ = r.Instruction("my acl", pbr)
	_, _ = r.Instruction("my acl", rune(22))
	_, _ = r.Instruction(struct{}{}, struct{}{}, struct{}{}, struct{}{})
	_, _ = r.Instruction("(targetattr=\"*\")", "my acl", rune(22))
	_, _ = r.Instruction("(targetattr=\"*\")", rune(22), pbr)
	_, _ = r.Instruction("(targetattr=\"*\")", "my acl", pbr)
	_, _ = r.Instruction(rune(22), "my acl", pbr)
	_, _ = r.Instruction("(targetattr=\"*\")", "my acl", "allow(none) ssf>=128")
	var ins ACIv3Instruction
	_ = ins.OID()
}

func TestNetscapeACIv3_PermissionBindRuleItem(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `allow(read,search,compare) ((ssf >= "56" OR userdn="ldap:///all") AND NOT (ssf = "256" OR ssf = "255") );`,
			Want: `allow(read,search,compare) ((ssf>="56" OR userdn="ldap:///all") AND NOT (ssf="256" OR ssf="255"));`,
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
		_ = x.Permission()
		_ = x.BindRule()
		_ = x.Kind()
		_ = x.Valid()
	}
}

func TestNetscapeACIv3_PermissionBindRule(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `allow(read,search,compare) ((ssf >= "57" OR userdn = "ldap:///all") AND NOT (ssf = "256" OR ssf = "255") ); deny(proxy, add) (timeofday > "1700" AND timeofday <= "1900");`,
			Want: `allow(read,search,compare) ((ssf>="57" OR userdn="ldap:///all") AND NOT (ssf="256" OR ssf="255")); deny(add,proxy) (timeofday>"1700" AND timeofday<="1900");`,
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
		_ = x.Index(0)
		_ = x.Kind()
		_ = x.Valid()
	}
}

func TestNetscapeACIv3_BindRuleItem(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `userdn != "ldap:///anyone"`,
			Want: `userdn!="ldap:///anyone"`,
		},
		{
			Orig: `( ssf >= "57" )`,
			Want: `(ssf>="57")`,
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
				`( userdn = "ldap:///uid=jesse,ou=People,o=example" )`,
			},
			Want: `ssf>="128" AND (userdn="ldap:///uid=jesse,ou=People,o=example")`,
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
			Want: `userdn="ldap:///uid=jesse,ou=People,o=example" OR userdn="ldap:///uid=courtney,ou=People,o=example"`,
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
			Want: `userdn="ldap:///uid=jesse,ou=People,o=example" AND NOT (userdn="ldap:///uid=courtney,ou=People,o=example")`,
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

func TestNetscapeACIv3_BindRuleInterface(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig  string
		Want  string
		Valid bool
	}{
		{
			Orig:  `((ssf >= "102" OR userdn="ldap:///anyone") AND NOT (ssf = "256" OR ssf = "255") )`,
			Want:  `((ssf>="102" OR userdn="ldap:///anyone") AND NOT (ssf="256" OR ssf="255"))`,
			Valid: true,
		},
		{
			Orig:  `( groupdn = "ldap:///cn=Human Resources,dc=example,dc=com" )`,
			Want:  `(groupdn="ldap:///cn=Human Resources,dc=example,dc=com")`,
			Valid: true,
		},
		{
			Orig:  `( uerattr = "aciurl#LDAPURL" )`,
			Valid: false,
		},
		{
			Orig:  `( userdn = "ldap:///all" )`,
			Want:  `(userdn="ldap:///all")`,
			Valid: true,
		},
		{
			Orig:  `( userdn |? "flap:///parent" || "ldap:///self" `,
			Valid: false,
		},
		{
			Orig:  `( userdn = "ldap:///anyone" ) AND ( ip != "192.0.2." )`,
			Want:  `(userdn="ldap:///anyone") AND (ip!="192.0.2.")`,
			Valid: true,
		},
		{
			Orig:  `( udn = "ldap:anyone" )`,
			Valid: false,
		},
		{
			Orig:  `( userdn = "ldap:///self" )`,
			Want:  `(userdn="ldap:///self")`,
			Valid: true,
		},
		{
			Orig:  `( userDN = "ldap:///self" ) UND ( ssf >= "128" )`,
			Valid: false,
		},
		{
			Orig:  `( userdn = "ldap:///uid=user,ou=People,dc=example,dc=com" )`,
			Want:  `(userdn="ldap:///uid=user,ou=People,dc=example,dc=com")`,
			Valid: true,
		},
		{
			Orig:  `( userdn "ldap:///uid=user,ou=People,dc=example,dc=com" ) AND ( dayofweek "Son,Sat" )`,
			Valid: false,
		},
		{
			Orig:  `( userdn = "ldap:///uid=user,ou=People,dc=example,dc=com" ) AND ( timeofday >= "1800" AND timeofday < "2400" )`,
			Want:  `(userdn="ldap:///uid=user,ou=People,dc=example,dc=com") AND (timeofday>="1800" AND timeofday<"2400")`,
			Valid: true,
		},
		{
			Orig:  `groupdn =`,
			Valid: false,
		},
		{
			Orig:  `groupdn = "ldap:///cn=DomainAdmins,ou=Groups,[$dn],dc=example,dc=com"`,
			Want:  `groupdn="ldap:///cn=DomainAdmins,ou=Groups,[$dn],dc=example,dc=com"`,
			Valid: true,
		},
		{
			Orig:  `gropedn "ldap:///cn=DomainAdmins,ou=Groups,dc=subdomain1,dc=hostedCompany1,dc=example,dc=com"`,
			Valid: false,
		},
		{
			Orig:  `groupdn = "ldap:///cn=example,ou=groups,dc=example,dc=com"`,
			Want:  `groupdn="ldap:///cn=example,ou=groups,dc=example,dc=com"`,
			Valid: true,
		},
		{
			Orig:  `"manager#USERDN"`,
			Valid: false,
		},
		{
			Orig:  `userattr = "owner#USERDN"`,
			Want:  `userattr="owner#USERDN"`,
			Valid: true,
		},
		{
			Orig:  `((userattr = "parent[0].owner#USERDN"`,
			Valid: false,
		},
		{
			Orig:  `userattr = "parent[1].manager#USERDN"`,
			Want:  `userattr="parent[1].manager#USERDN"`,
			Valid: true,
		},
		{
			Orig:  `target_to = "http:///anyone" SAND stfu < "128"`,
			Valid: false,
		},
		{
			Orig:  `userdn = "ldap:///anyone" || "ldap:///self" || "ldap:///cn=Admin"`,
			Want:  `userdn="ldap:///anyone || ldap:///self || ldap:///cn=Admin"`,
			Valid: true,
		},
		{
			Orig:  `userdn = "" AND ssf >= "128"`,
			Valid: false,
		},
		{
			Orig:  `( ( ( userdn = "ldap:///anyone" ) AND ( ssf >= "71" ) ) AND NOT ( dayofweek = "Wed" ) )`,
			Want:  `(((userdn="ldap:///anyone") AND (ssf>="71")) AND NOT (dayofweek="Wed"))`,
			Valid: true,
		},
		{
			Orig:  `( ( userdn = "ldap:///anyone" AND ssf >= "128" ) I DID NOT HIT HER dayofweek = "Fri" )`,
			Valid: false,
		},
		{
			Orig:  `( authmethod = "NONE" OR authmethod = "SIMPLE" )`,
			Want:  `(authmethod="NONE" OR authmethod="SIMPLE")`,
			Valid: true,
		},
		{
			Orig:  `userdn = "ldap:///alguien" ) Y ( direcciónIP != "2001:db8::" )`,
			Valid: false,
		},
		{
			Orig:  `groupdn = "ldap:///cn=Administrators,ou=Groups,dc=example,com" AND groupdn = "ldap:///cn=Operators,ou=Groups,dc=example,com"`,
			Want:  `groupdn="ldap:///cn=Administrators,ou=Groups,dc=example,com" AND groupdn="ldap:///cn=Operators,ou=Groups,dc=example,com"`,
			Valid: true,
		},
		{
			Orig:  `extop = "ldap:///cn=Human Resources,ou=People,dc=example,dc=com"`,
			Valid: false,
		},
		{
			Orig:  `userattr = "manager#USERDN"`,
			Want:  `userattr="manager#USERDN"`,
			Valid: true,
		},
		{
			Orig:  `userdn = "ldap:///anyone" AND ssf >= "128" AND NOT [ dayofweek = "Fri" OR dayofweek = "Sun" ]`,
			Valid: false,
		},
		{
			Orig:  `userdn = "ldap:///anyone" AND ssf >= "128" AND NOT dayofweek = "Fri"`,
			Want:  `userdn="ldap:///anyone" AND ssf>="128" AND NOT dayofweek="Fri"`,
			Valid: true,
		},
		{
			Orig:  `usedn = "ldap:///bueller"`,
			Valid: false,
		},
		{
			Orig:  `userdn = "ldap:///cn=Courtney Tolana,dc=example,dc=com"`,
			Want:  `userdn="ldap:///cn=Courtney Tolana,dc=example,dc=com"`,
			Valid: true,
		},
		{
			Orig:  `rolepn # "ldap:///dc=example,dc=com??sub?(manager=example)`,
			Valid: false,
		},
		{
			Orig:  `userdn = "ldap:///ou=People,dc=example,dc=com??sub?(department=Human Resources)"`,
			Want:  `userdn="ldap:///ou=People,dc=example,dc=com??sub?(department=Human Resources)"`,
			Valid: true,
		},
		{
			Orig:  `( userdn = "ldap:///n'importequi" ) ET ( SystèmeDeNomsDeDomaines != "client.example.com" )`,
			Valid: false,
		},
		{
			Orig:  `( userdn = "ldap:///anyone" ) AND ( dns != "client.example.com" )`,
			Want:  `(userdn="ldap:///anyone") AND (dns!="client.example.com")`,
			Valid: true,
		},
		{
			Orig:  `userdn = ''`,
			Valid: false,
		},
		{
			Orig:  `( userdn = "ldap:///anyone" ) AND NOT ( dns != "client.example.com" )`,
			Want:  `(userdn="ldap:///anyone") AND NOT (dns!="client.example.com")`,
			Valid: true,
		},
		{
			Orig:  `useratr = "ldap:///ou=Profiles,ou=Configuration,dc=example,dc=com?hardwareType#physical"`,
			Valid: false,
		},
	}

	for idx, obj := range tests {
		x, err := r.BindRule(obj.Orig)
		if obj.Valid {
			if err != nil {
				t.Errorf("%s[%d] failed: %v", t.Name(), idx, err)
				return
			} else if got := x.String(); got != obj.Want {
				t.Errorf("%s[%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, obj.Want, got)
				return
			}
		} else if x != nil {
			t.Errorf("%s[%d] failed: expected error, got nil", t.Name(), idx)
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
			Want: `(targetattr="cn||sn||givenName")`,
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
		x.Kind()
		x.TRM()
		x.Keyword()
		x.SetDelimiter()
		x.SetDelimiter(0)
		x.SetDelimiter(1)
	}
}

func TestNetscapeACIv3_AttributeFilterOperationItem(t *testing.T) {
	var r NetscapeACIv3

	tests := []struct {
		Orig string
		Want string
	}{
		{
			Orig: `add=homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta))`,
			Want: `add=homeDirectory:(&(objectClass=employee)(cn=Jesse Coretta))`,
		},
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
		x.Index(0)
		x.Kind()
		x.TRM()
		x.Keyword()
		x.Push(x.Index(0).String())
		x.Contains("")
		x.Contains(rune(88))
		x.Contains(x.Index(0))
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
		x.Attribute()
		x.Filter()
	}
}

func ExampleACIv3Operator_stringers() {
	for _, cop := range []ACIv3Operator{
		ACIv3Eq, ACIv3Ne, ACIv3Lt, ACIv3Gt, ACIv3Le, ACIv3Ge,
	} {
		fmt.Printf("[%d] %s (%s)[%s]\n",
			int(cop),
			cop.Description(),
			cop.Context(),
			cop)
	}

	// Output:
	// [1] Equal To (Eq)[=]
	// [2] Not Equal To (Ne)[!=]
	// [3] Less Than (Lt)[<]
	// [4] Greater Than (Gt)[>]
	// [5] Less Than Or Equal (Le)[<=]
	// [6] Greater Than Or Equal (Ge)[>=]
}

func ExampleACIv3Operator_Valid() {
	var unknown ACIv3Operator = ACIv3Operator(12)
	fmt.Printf("Is a known %T: %t", unknown, unknown.Valid() == nil)
	// Output: Is a known dirsyn.ACIv3Operator: false
}

/*
This example demonstrates the string representation for all
known ACIv3Operator constants.
*/
func ExampleACIv3Operator_String() {
	for _, cop := range []ACIv3Operator{
		ACIv3Eq, ACIv3Ne, ACIv3Lt, ACIv3Gt, ACIv3Le, ACIv3Ge,
	} {
		fmt.Printf("%s\n", cop)
	}
	// Output:
	// =
	// !=
	// <
	// >
	// <=
	// >=
}

/*
This example demonstrates the use of the Context method to show
all the context name for all ACIv3Operator constants.
*/
func ExampleACIv3Operator_Context() {
	for _, cop := range []ACIv3Operator{
		ACIv3Eq, ACIv3Ne, ACIv3Lt, ACIv3Gt, ACIv3Le, ACIv3Ge,
	} {
		fmt.Printf("%s\n", cop.Context())
	}
	// Output:
	// Eq
	// Ne
	// Lt
	// Gt
	// Le
	// Ge
}

/*
This example demonstrates the use of the Description method to
show all descriptive text for all ACIv3Operator constants.
*/
func ExampleACIv3Operator_Description() {
	for _, cop := range []ACIv3Operator{
		ACIv3Eq, ACIv3Ne, ACIv3Lt, ACIv3Gt, ACIv3Le, ACIv3Ge,
	} {
		fmt.Printf("%s\n", cop.Description())
	}
	// Output:
	// Equal To
	// Not Equal To
	// Less Than
	// Greater Than
	// Less Than Or Equal
	// Greater Than Or Equal
}

func TestNetscapeACIv3_codecov(t *testing.T) {
	var r NetscapeACIv3
	bi, err := r.BindRuleItem(`userdn!="ldap:///anyone"`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
	bi.(ACIv3BindRuleItem).SetQuotationStyle(0)
	bi.(ACIv3BindRuleItem).SetQuotationStyle(1)
	bi.(ACIv3BindRuleItem).SetPaddingStyle(0)
	bi.(ACIv3BindRuleItem).SetPaddingStyle(1)
	bi.(ACIv3BindRuleItem).Push("garbage")
	bi.(ACIv3BindRuleItem).isBindRule()
	bi.(ACIv3BindRuleItem).Len()
	bi.(ACIv3BindRuleItem).Index(0)

	_, _ = r.BindRuleItem(ACIv3BindUDN, ACIv3Eq, "ldap:///anyone")
	_, _ = r.BindRuleItem(ACIv3BindUDN, 0x00, "ldap:///anyone")
	_, _ = r.BindRuleItem(rune(88))

	var pbri ACIv3PermissionBindRuleItem
	pbri.Valid()
	pbri.parse("")
	pbri.parse("bogus")
	pbri.parse("allow(read) stuff")

	var attr ACIv3Attribute
	attr.Kind()
	attr.Keyword()
	attr, _ = r.Attribute("cn", "sn", "givenName")
	_ = attr.string(true, false)
	_ = attr.string(false, true)
	_ = attr.string(true, true)
	_ = attr.string(false, false)
	attr, _ = r.Attribute("*")
	attr.Ne()
	attr.Push("drink")
	attr.Push("_")
	attr.Push([]string{"drink", "objectClass"})
	attr.Push(ACIv3Attribute{})
	attr.aCIAttribute.all = true
	attr.string(true, true)
	_ = attr.String()
	attr.Ne()
	attr.aCIAttribute.all = false
	attr.aCIAttribute.slice = []string{"cn", "sn"}
	attr.push(&AttributeType{})
	attr.Push([]string{"cn", "sn"})
	attr.Push("cn", "sn")
	attr.Push(attr)
	attr.Ne()
	attr.Push(&AttributeType{NumericOID: "2.5.4.3", Name: []string{"cn"}, SuperType: "name"})

	var pbr ACIv3PermissionBindRule
	pbr.Valid()
	pbr.parse("")
	pbr.parse("bogus")

	var bi2 ACIv3BindRuleItem
	bi2.SetKeyword("userdn")
	bi2.SetOperator("=")
	bi2.SetExpression()
	_ = bi2.String()
	bi2.Valid()
	bi2.aCIBindRuleItem = &aCIBindRuleItem{}
	_ = bi2.String()
	bi2.Valid()
	bi2.SetKeyword("userdn")
	bi2.SetOperator("=")
	bi2.IsParen()
	bi2.Valid()
	_ = bi2.String()

	var bnt ACIv3BindRuleNot
	bnt.Valid()
	bnt.Push(nil)
	bnt.aCIBindRuleNot = &aCIBindRuleNot{
		ACIv3BindRule: newACIv3BindRuleItem(`userdn`, `=`, `ldap:///`),
	}
	bnt.Push(bi)
	bnt.Push(`( userdn!="ldap:///all" OR groupdn!="ldap:///parent" )`)
	bnt.SetParen(true)
	bnt.SetQuotationStyle(0)
	bnt.SetQuotationStyle(1)
	bnt.SetPaddingStyle(0)
	bnt.SetPaddingStyle(1)
	bnt.Kind()
	bnt.Len()
	bnt.isBindRule()
	bnt.Index(0)
	bnt.Valid()
	bnt.IsParen()

	var bands ACIv3BindRuleAnd
	bands.Valid()
	bands.Push(nil)
	bands.aCIBindRuleSlice.aCIBindRuleSliceString(``)
	bands.Push(bi)
	bands.aCIBindRuleSlice = &aCIBindRuleSlice{slice: []ACIv3BindRule{bi}, pad: true}
	bands.SetParen(true)
	bands.SetPaddingStyle(0)
	bands.SetPaddingStyle(1)
	bands.aCIBindRuleSlice.aCIBindRuleSliceString(``)
	bands.SetQuotationStyle(0)
	bands.Kind()
	bands.isBindRule()
	bands.Len()
	bands.Index(0)
	bands.Valid()
	bands.IsParen()
	bands.aCIBindRuleSlice.slice = append(bands.aCIBindRuleSlice.slice, ACIv3BindRuleItem{})
	bands.aCIBindRuleSlice.Valid()

	getAndOrBool([]aCIBindRuleTokenType{brValue})

	var bors ACIv3BindRuleOr
	bors.Valid()
	bors.Push(nil)
	bors.aCIBindRuleSlice.aCIBindRuleSliceString(``)
	bors.Push(bi)
	bors.aCIBindRuleSlice = &aCIBindRuleSlice{}
	bors.aCIBindRuleSlice.Valid()
	bors.aCIBindRuleSlice = &aCIBindRuleSlice{slice: []ACIv3BindRule{bi}, pad: true}
	bors.SetParen(true)
	bors.Push(bi)
	bors.SetPaddingStyle(0)
	bors.SetPaddingStyle(1)
	bors.SetQuotationStyle(0)
	bors.Kind()
	bors.isBindRule()
	bors.Len()
	bors.Index(0)
	bors.Valid()
	bors.IsParen()

	var pos int
	processACIv3BindRule([]aCIBindRuleToken{}, &pos)
	parseACIv3BindRuleTokens([]aCIBindRuleToken{
		{Type: brParenClose, Value: ")"},
		{},
	})

	var kw ACIv3Keyword
	kw = ACIv3BindUDN
	kw.isACIv3Keyword()
	kw = ACIv3Target
	kw.isACIv3Keyword()

	assertATBTVBindKeyword(ACIv3BindGAT)
	matchTKW(nil)
	matchTKW(ACIv3Target)
	matchBKW(nil)
	matchBKW(ACIv3BindGAT)
	matchBT(``)

	var lousyCop ACIv3Operator = ACIv3Operator(7)
	_ = lousyCop.String()
	_ = lousyCop.Context()
	_ = lousyCop.Description()
	_ = lousyCop.Valid()
	lousyCop.Compare(0)
	lousyCop.Compare(``)
	lousyCop.Compare(rune(3))
	lousyCop.Compare(ACIv3Eq)

	var brm ACIv3BindRuleMethods
	brm.Valid()
	brm.Index(0)
	brm.Index(2)
	brm.Index(ACIv3Eq)
	brm.Len()

	var trm ACIv3TargetRuleMethods
	trm.Valid()
	trm.Len()
	trm.Index(0)
	trm.Index(2)
	trm.Index(ACIv3Eq)

	r.WeekdaysBindRule(ACIv3Eq)
	r.WeekendBindRule(ACIv3Eq)

	var prm ACIv3Permission
	prm.aCIPermission = &aCIPermission{}
	prm.Valid()
	prm.Shift(1023)
	_ = prm.String()
	marshalACIv3Permission()
	marshalACIv3Permission(rune(22), true)
	parseACIv3Permission("")
	parseACIv3Permission("allow(read")
	parseACIv3Permission("allow(read]")
	parseACIv3Permission("allow(toys)")
	parseACIv3Permission("allow((((((()))))")
	parseACIv3Permission("allowallow()")
	prm, _ = marshalACIv3Permission("allow(read)")
	prm.aCIPermission.shift([]int{16, 32})
	prm.aCIPermission.unshift([]string{"read", "write"})
	prm.aCIPermission.unshift([]int{16, 32})
	prm.cast().Shift(1023)
	_ = prm.String()
	prm, _ = marshalACIv3Permission("allow(none)")
	_ = prm.String()
	prm.aCIPermission.bool = nil
	prm.Valid()
	var allow bool = true
	prm.aCIPermission.bool = &allow

	_, _ = r.PermissionBindRuleItem()
	_, _ = r.PermissionBindRuleItem(rune(22))
	_, _ = r.PermissionBindRuleItem(prm, ACIv3BindRuleItem{&aCIBindRuleItem{}})
	_, _ = r.PermissionBindRuleItem(prm, struct{}{})
	_, _ = r.PermissionBindRuleItem(prm, bi)

	var ssf ACIv3SecurityStrengthFactor
	ssf.Set(256)
	ssf.Set(257)
	ssf.Set(nil)
	ssf.Eq()
	ssf.Ne()
	ssf.Lt()
	ssf.Le()
	ssf.Gt()
	ssf.Ge()
	marshalACIv3SecurityStrengthFactor()

	var am ACIv3AuthenticationMethod
	am = ACIv3AuthenticationMethod(77)
	am.Valid()
	_ = am.String()
	am = ACIv3Anonymous
	am.Valid()
	_ = am.String()
	r.AuthenticationMethod()
	r.AuthenticationMethod(1)

	var dow ACIv3DayOfWeek
	dow.Shift(ACIv3Sunday)
	dow.Unshift(ACIv3Sunday)
	dow.Valid()
	dow = newDoW()
	dow.Valid()
	dow.Shift(ACIv3Sunday)
	dow.Unshift(ACIv3Saturday)
	dow.Unshift(7)
	dow.Len()
	dow.Valid()
	dow.BRM().Valid()
	dow.parse("sunday")
	dow.parse("humpday")
	dow.Len()
	dow.Eq()
	dow.Ne()
	dow.Keyword()
	_ = matchDoW("sunday")
	_ = matchDoW(1)
	_ = matchDoW(ACIv3Sunday)
	_, _ = r.DayOfWeek("sunday,monday")
	_, _ = marshalACIv3DayOfWeek()
	_, _ = marshalACIv3DayOfWeek("mon", "tues", "sun")
	_, _ = marshalACIv3DayOfWeek(ACIv3Sunday)

	parseACIv3BindRuleExpression([]aCIBindRuleToken{{Type: 7, Value: "?"}})
	parseACIv3BindRuleExpression([]aCIBindRuleToken{
		{Type: brValue, Value: "("},
		{Type: 88, Value: ""},
		{Type: brValue, Value: ")"},
	})
	parseACIv3BindRuleGroup([]aCIBindRuleToken{{Type: 7, Value: "?"}}, &pos)
	parseACIv3BindRuleGroup([]aCIBindRuleToken{
		{Type: brValue, Value: "userdn"},
		{Type: brValue, Value: "="},
		{Type: brParenClose, Value: ")"},
		{Type: brValue, Value: "userdn"},
		{Type: brParenOpen, Value: "("},
		{Type: brParenClose, Value: ")"},
	}, &pos)

	for i := 1; i < 8; i++ {
		matchStrDoW(matchIntDoW(i).String())
	}

	var asc ACIv3Scope
	asc.Keyword()
	asc = ACIv3Scope(0)
	_ = asc.String()
	asc = ACIv3Scope(1)
	_ = asc.String()
	asc = ACIv3Scope(2)
	_ = asc.String()
	asc = ACIv3Scope(3)
	_ = asc.String()
	asc = ACIv3Scope(4)
	_ = asc.String()
	asc.Eq()
	asc.Ne()
	asc.TRM()
	_, _ = marshalACIv3SearchScope()
	_, _ = marshalACIv3SearchScope(2)
	_, _ = marshalACIv3SearchScope(rune(2))
	_ = aCIIntToScope(3)
	_ = aCIIntToScope(4)
	_ = aCIStrToScope("base")
	_ = aCIStrToScope("one")
	_ = aCIStrToScope("subtree")
	_ = aCIStrToScope("subordinate")

	var af ACIv3AttributeFilter
	af.Valid()
	af.aCIAttributeFilter = &aCIAttributeFilter{ACIv3Attribute: attr}
	af.Valid()
	af.parse("gecos(objectClass=*)")
	af.parse("gecos:(objectClass=*)")
	af.parse("_:(objectClass=*)")
	af.parse(":(objectClass=*)")

	var fqdn ACIv3FQDN
	fqdn.aCIFQDNLabels.set()
	fqdn.aCIFQDNLabels.set("__bogus__")
	fqdn.aCIFQDNLabels.set("www.?bogus?.com")
	processLabel("www.???.com")

	var ip ACIv3IPAddress
	ip.Valid()
	ip.Set("192.168/16")
	ip.aCIIPAddresses.set()
	ip.aCIIPAddresses.set("__bogus__")
	ip.Valid()
	isV4("")
	isV6("")
	isV6("dead::beef")

	af.aCIAttributeFilter.ACIv3Attribute = ACIv3Attribute{}
	af.Valid()
	af.aCIAttributeFilter.ACIv3Attribute = ACIv3Attribute{&aCIAttribute{slice: []string{"gecos"}}}
	af.Valid()
	af.aCIAttributeFilter.Filter, _ = marshalFilter("(objectClass=*")
	af.Valid()
	af.parse("gecos:(&(objectClass=top)(employeeStatus=active))")
	af.Keyword()
	af.Kind()
	af.IsZero()
	af.Valid()
	_ = af.String()
	af.aCIAttributeFilter.set("gecos")
	af.aCIAttributeFilter.set("(objectClass=top)")
	_, _ = r.AttributeFilter()
	_, _ = r.AttributeFilter(rune(87))
	_, _ = r.AttributeFilter(rune(87), rune(87))
	_, _ = r.AttributeFilter(rune(87), rune(87), rune(87))
	_, _ = r.AttributeFilter("", rune(87))
	_, _ = r.AttributeFilter("", af.Filter)
	_, _ = r.AttributeFilter(attr, af.aCIAttributeFilter.Filter)
	_, _ = r.AttributeFilter(attr, nil)
	_, _ = r.AttributeFilter("gecos", af.aCIAttributeFilter.Filter)
	_, _ = r.AttributeFilter("gecos", nil)
	_, _ = r.AttributeFilter("gecos:(objectClass=top)")
	_, _ = r.AttributeFilter("gecos", "(objectClass=top)")
	_, _ = r.AttributeFilter(attr, "(objectClass=top)")
	_, _ = marshalACIv3AttributeFilterOperationItem(ACIv3AddOp, nil)

	_, _ = r.AttributeFilterOperation()

	var afoi ACIv3AttributeFilterOperationItem
	afoi.Contains("this")
	afoi, _ = r.AttributeFilterOperationItem("add=gecos:(objectClass=*)")
	afoi.Eq()
	afoi.Ne()

	var afo ACIv3AttributeFilterOperation
	afo.Valid()
	afo, _ = r.AttributeFilterOperation("add=gecos:(objectClass=*);delete=homeDirectory:(employeeStatus=terminated)")
	afo.Eq()
	afo.Ne()
	afo.Valid()
	afo.aCIAttributeFilterOperation.semi = true
	_ = afo.String()
	add := afo.aCIAttributeFilterOperation.add
	del := afo.aCIAttributeFilterOperation.del
	afo, _ = r.AttributeFilterOperation(ACIv3DelOp, del)
	afo.Len()
	afo, _ = r.AttributeFilterOperation(ACIv3AddOp, add)
	afo.Len()
	afo.Eq()
	afo.Ne()
	afo.Valid()
	afo.Len()
	_ = afo.String()
	afo.aCIAttributeFilterOperation.add.Eq()
	afo.aCIAttributeFilterOperation.add.Ne()
	afo.aCIAttributeFilterOperation.add.aCIAttributeFilterOperationItem.slice = nil
	afo.aCIAttributeFilterOperation.add.Valid()

	checkACIv3AFOSubstr("add=", "del=")
	checkACIv3AFOSubstr("add=...add=", "add=...,add=")
	checkACIv3AFOSubstr("add=", "add=")
	checkACIv3AFOSubstr("=", "=")
	checkACIv3AFOSubstr("add=", "")

	splitACIv3AttributeFilterOperation("")
	splitACIv3AttributeFilterOperation(";")
	splitACIv3AttributeFilterOperation("..;..")
	splitACIv3AttributeFilterOperation("..,..")
	_, _ = r.AttributeFilterOperation(rune(3))
	_, _ = r.AttributeFilterOperation(rune(3), af)
	_, _ = r.AttributeFilterOperation(ACIv3AddOp, af)
	_, _ = r.AttributeFilterOperation(ACIv3AddOp, af, nil)

	marshalACIv3AttributeFilterOperation(ACIv3DelOp, del)

	marshalACIv3AttributeFilterOperationItem()
	marshalACIv3AttributeFilterOperationItem(nil)
	marshalACIv3AttributeFilterOperationItem(ACIv3AddOp, af)
	marshalACIv3AttributeFilterOperationItem(ACIv3DelOp, af)
	marshalACIv3AttributeFilterOperationItem(rune(3), af)
	marshalACIv3AttributeFilterOperationItem(rune(3), rune(3), rune(3))
	marshalACIv3AttributeFilterOperationItem(rune(3), af, rune(3))

	var tod ACIv3TimeOfDay
	tod.Valid()
	tod.Set("0530")
	tod.BRM()
	tod.Valid()
	tod.Keyword()
	longForm := "Jan 2, 2006 at 3:04pm (MST)"
	thyme, _ := time.Parse(longForm, "Feb 3, 2013 at 7:54pm (PST)")
	assertToD(tod.aCITimeOfDay, thyme)
	r.TimeframeBindRule(tod, tod)
	tod, _ = r.TimeOfDay("0530")
	tod.Eq()
	tod.Ne()
	tod.Gt()
	tod.Ge()
	tod.Lt()
	tod.Le()

	var oidc, oide ACIv3ObjectIdentifier
	oidc.Contains("1.2.3.4")
	oide.Contains("1.2.3.4")
	oidc, _ = r.LDAPControlOIDs("1.2.3.4")
	oide, _ = r.LDAPExtendedOperationOIDs("1.2.3.4")
	oidc.Contains("1.2.3.4")
	oide.Contains("1.2.3.4")
	oidc.Push("1.2.3.4")
	oide.Push("1.2.3.4")
	oidc.Eq().SetQuotationStyle(0)
	oidc.Ne().SetQuotationStyle(1)
	oide.Eq().SetQuotationStyle(0)
	oide.Ne().SetQuotationStyle(1)
	oide.aCIObjectIdentifier.string(true, true)
	oide.aCIObjectIdentifier.string(false, false)
	oide.aCIObjectIdentifier.string(false, true)
	oide.aCIObjectIdentifier.string(true, false)

	processACIv3TargetRuleItem([]aCITargetRuleToken{
		{},
	})
	processACIv3TargetRuleItem([]aCITargetRuleToken{
		{Type: 0x1},
		{},
		{},
		{},
		{},
	})
	processACIv3TargetRuleItem([]aCITargetRuleToken{
		{Type: trParenOpen},
		{Type: trKeyword},
		{},
		{},
		{},
	})
	processACIv3TargetRuleItem([]aCITargetRuleToken{
		{Type: trParenOpen, Value: "("},
		{Type: trKeyword, Value: "-"},
		{Type: trOperator, Value: "?"},
		{Type: trValue, Value: "..."},
		{Type: trParenClose, Value: ")"},
	})
	processACIv3TargetRuleItem([]aCITargetRuleToken{
		{Type: trParenOpen, Value: "("},
		{Type: trKeyword, Value: "target"},
		{Type: trOperator, Value: "?"},
		{Type: trValue, Value: "..."},
		{Type: trParenClose, Value: ")"},
	})

	var tr ACIv3TargetRule
	_ = tr.Valid()
	_ = tr.parse(``)
	_ = tr.parse(`(target=`)
	_ = tr.Valid()
	_ = tr.parse(`(target="ldap:///cn=user||ldap:///cn=otheruser")`)
	_ = tr.Index(0).Kind()
	tr.SetQuotationStyle(0)
	tr.SetQuotationStyle(1)
	tr.Valid()
	tr.Len()
	_ = tr.String()

	var atb ACIv3AttributeBindTypeOrValue
	atb.Valid()
	atb.Set()
	atb.atbtv = new(atbtv)
	_ = atb.atbtv.String()
	atb.atbtv[0] = attr
	atb.atbtv[1] = ACIv3BindUAT
	_ = atb.atbtv.String()
	var blarg string = "blarg"
	atb.atbtv[1] = AttributeValue{&blarg}
	_ = atb.atbtv.String()
	atb.parse("owner#USERDN", ACIv3BindGAT)
	_ = atb.atbtv.String()
	atb.Eq()
	atb.Ne()
	atb.BRM()
	atb.ACIv3BindKeyword = ACIv3BindGAT
	atb.Keyword()
	atb.ACIv3BindKeyword = ACIv3BindUAT
	atb.Keyword()
	marshalACIv3AttributeBindTypeOrValue("owner#USERDN")
	marshalACIv3AttributeBindTypeOrValue("owner", "USERDN")
	marshalACIv3AttributeBindTypeOrValue("owner", "USERDN")
	marshalACIv3AttributeBindTypeOrValue("groupattr", atb)
	marshalACIv3AttributeBindTypeOrValue(atb)
	atb.Keyword()
	atb.Set()
	_ = atb.atbtv.String()
	_, _ = parseATBTV("_#GROUPBLARG", ACIv3BindGDN)

	var tri ACIv3TargetRuleItem
	_ = tri.String()
	tri.SetKeyword("nothing")
	tri.SetOperator(".")
	tri.SetExpression("nothing")
	tri.Valid()
	tri.IsZero()
	tri.Kind()
	tri.SetQuotationStyle(0)
	tri.SetQuotationStyle(1)
	tr.Push(tri)
	tr.aCITargetRule = &aCITargetRule{}
	tr.aCITargetRule.slice = append(tr.aCITargetRule.slice, ACIv3TargetRuleItem{&aCITargetRuleItem{}})
	tr.Valid()
	tr.SetQuotationStyle(0)
	tr.SetQuotationStyle(1)
	newACIv3TargetRuleMethods(nil)
	r.TargetRuleItem(ACIv3TargetScope, rune(22))
	r.TargetRuleItem(ACIv3TargetKeyword(0x0), rune(22))
	r.TargetRuleItem(ACIv3TargetKeyword(0x1), rune(22), rune(22))

	tri, _ = r.TargetRuleItem(rune(0), rune(0), nil)
	tri, _ = r.TargetRuleItem(ACIv3Target, ACIv3Eq, "bogus")
	_ = tri.String()
	tri, _ = r.TargetRuleItem(ACIv3Target, ACIv3Eq, "ldap:///cn=Manager")
	_ = tri.String()
	tri.aCITargetRuleItem.pad = true
	_ = tri.String()

	var bdn ACIv3BindDistinguishedName = ACIv3BindDistinguishedName{ACIv3BindUDN, &aCIDistinguishedName{slice: []string{"ldap:///all"}}}
	bdn.Len()
	bdn.Contains("nothing")
	bdn.Eq()
	bdn.Ne()
	bdn.Push("nothing")
	bdn.Index(0)

	bdn.aCIDistinguishedName.string(true, false)
	bdn.aCIDistinguishedName.string(false, true)
	bdn.aCIDistinguishedName.string(false, false)
	bdn.aCIDistinguishedName.string(true, true)
	udn, _ := marshalDistinguishedName("cn=admin")
	bdn.aCIDistinguishedName.contains(udn)

	var tdn ACIv3TargetDistinguishedName = ACIv3TargetDistinguishedName{ACIv3Target, &aCIDistinguishedName{slice: []string{"ldap:///all"}}}
	tdn.Len()
	tdn.Contains("nothing")
	tdn.Eq()
	tdn.Ne()
	tdn.Push("nothing")
	tdn.Index(0)

	trm = attr.TRM()
	trm.Valid()
	trm.Len()
	trm.Index("=")
	trm.Index(1)
	trm.Index(1111)
	trm.Index(ACIv3Eq)

	_, _ = tokenizeACIv3TargetRule(`=!?`)
	_, _ = tokenizeACIv3TargetRule(`!?`)
	_, _ = tokenizeACIv3TargetRule(`!=`)
	_, _, _ = tokenizeACIv3TargetRuleMultival(-1, -1, ``, []aCITargetRuleToken{})
	_, _, _ = tokenizeACIv3TargetRuleKeyword(0x0, -1, -1, ``, []aCITargetRuleToken{})
	_, _, _ = tokenizeTargetRuleQuotedValue(1, 1, `"things"`, []aCITargetRuleToken{})
	_, _, _ = tokenizeTargetRuleQuotedValue(1, 1, `"thi\"ngs\" are cool"`, []aCITargetRuleToken{})
	_, _ = assertTargetValueByKeyword(ACIv3Target)
	_, _ = assertTargetValueByKeyword(ACIv3TargetKeyword(99), "")
	_, _ = assertTargetValueByKeyword(ACIv3TargetAttr, "owner#USERDN")
	_, _ = assertTargetValueByKeyword(ACIv3TargetAttr, ACIv3Attribute{&aCIAttribute{all: true}})
	_, _ = assertTargetValueByKeyword(ACIv3TargetAttr, ACIv3AttributeBindTypeOrValue{ACIv3BindUDN, &atbtv{}})
	_, _ = assertTargetValueByKeyword(ACIv3TargetAttrFilters, "blarg")

	marshalACIv3BindDistinguishedName(ACIv3Target)
	marshalACIv3TargetDistinguishedName(ACIv3BindUDN)

	keywordAllowsACIv3Operator(`userdn`, ">=")
	keywordAllowsACIv3Operator(`target`, ">=")
	keywordAllowsACIv3Operator(ACIv3BindUAT, ">=")
	keywordAllowsACIv3Operator(ACIv3BindUAT, rune(33))
	keywordAllowsACIv3Operator(rune(33), "")

	// test permutations of keywords and cops

	permutations := map[string]map[ACIv3Keyword][]any{
		`valid`: {
			// target keywords
			ACIv3Target:            {`eq`, `ne`, ACIv3Eq, ACIv3Ne, 1, 2},
			ACIv3TargetTo:          {`eq`, `ne`},
			ACIv3TargetFrom:        {`eq`, `ne`},
			ACIv3TargetCtrl:        {`eq`, `ne`},
			ACIv3TargetAttr:        {`eq`, `ne`},
			ACIv3TargetFilter:      {`eq`, `ne`, ACIv3Ne, 2},
			ACIv3TargetExtOp:       {`eq`, `ne`},
			ACIv3TargetScope:       {`eq`},
			ACIv3TargetAttrFilters: {`eq`, 1, ACIv3Eq},

			// bind keywords
			ACIv3BindUDN: {`eq`, `ne`, ACIv3Eq, "equal to", `EQ`},
			ACIv3BindGDN: {`eq`, ACIv3Ne, `not equal to`, `NE`, `ne`},
			ACIv3BindRDN: {`eq`, `ne`},
			ACIv3BindDNS: {`eq`, `ne`},
			ACIv3BindUAT: {`eq`, `ne`},
			ACIv3BindGAT: {`eq`, `ne`},
			ACIv3BindDoW: {`eq`, `ne`},
			ACIv3BindIP:  {`eq`, `ne`},
			ACIv3BindAM:  {`eq`, `ne`},
			ACIv3BindToD: {`eq`, 4, `ne`, ACIv3Le, `LE`, 6, `le`, ACIv3Lt, `LT`, `lt`, 3, ACIv3Ge, `GE`, `ge`, ACIv3Gt, `GT`, `gt`},
			ACIv3BindSSF: {`eq`, 1, `ne`, ACIv3Le, `LE`, 5, `le`, ACIv3Lt, `LT`, 2, `lt`, ACIv3Ge, `GE`, `ge`, ACIv3Gt, `GT`, `gt`},
		},
	}

	for typ, kwmap := range permutations {
		for kw, values := range kwmap {
			for i := 0; i < len(values); i++ {
				op := values[i]
				if !keywordAllowsACIv3Operator(kw, op) {
					t.Errorf("%s [%s] failed: %s %T [%v] denied or not resolved",
						t.Name(), kw, typ, invalidCop, op)
					return
				}
			}
		}
	}
}

var bogusKeywords []string = []string{
	`bagels`,
	`63`,
	`a^574384`,
	``,
	`userdnssf`,
}

func TestACIv3Keyword_bogusMatches(t *testing.T) {
	for _, bogus := range bogusKeywords {
		if bt := matchBT(bogus); bt != ACIv3BindType(0x0) {
			t.Errorf("%s failed: '%s' matched bogus %T",
				t.Name(), bogus, bt)
			return
		}

		if tk := matchTKW(bogus); tk != ACIv3TargetKeyword(0x0) {
			t.Errorf("%s failed: '%s' matched bogus %T",
				t.Name(), bogus, tk)
			return
		}

		if bk := matchBKW(bogus); bk != ACIv3BindKeyword(0x0) {
			t.Errorf("%s failed: '%s' matched bogus %T",
				t.Name(), bogus, bk)
			return
		}
	}
}

// Let's print out each BindType constant
// defined in this package.
func ExampleACIv3BindType() {
	for idx, bt := range []ACIv3BindType{
		ACIv3BindTypeUSERDN,
		ACIv3BindTypeGROUPDN,
		ACIv3BindTypeROLEDN,
		ACIv3BindTypeSELFDN,
		ACIv3BindTypeLDAPURL,
	} {
		fmt.Printf("%T %d/%d: %s\n",
			bt, idx+1, 5, bt)
	}
	// Output:
	// dirsyn.ACIv3BindType 1/5: USERDN
	// dirsyn.ACIv3BindType 2/5: GROUPDN
	// dirsyn.ACIv3BindType 3/5: ROLEDN
	// dirsyn.ACIv3BindType 4/5: SELFDN
	// dirsyn.ACIv3BindType 5/5: LDAPURL
}

/*
This example demonstrates the interrogation of BindKeyword const
definitions. This type qualifies for the Keyword interface type.

There are a total of eleven (11) such BindKeyword definitions.
*/
func ExampleACIv3BindKeyword() {
	for idx, bk := range []ACIv3BindKeyword{
		ACIv3BindUDN,
		ACIv3BindRDN,
		ACIv3BindGDN,
		ACIv3BindUAT,
		ACIv3BindGAT,
		ACIv3BindIP,
		ACIv3BindDNS,
		ACIv3BindDoW,
		ACIv3BindToD,
		ACIv3BindAM,
		ACIv3BindSSF,
	} {
		fmt.Printf("[%s] %02d/%d: %s\n",
			bk.Kind(), idx+1, 11, bk)
	}
	// Output:
	// [bindRule] 01/11: userdn
	// [bindRule] 02/11: roledn
	// [bindRule] 03/11: groupdn
	// [bindRule] 04/11: userattr
	// [bindRule] 05/11: groupattr
	// [bindRule] 06/11: ip
	// [bindRule] 07/11: dns
	// [bindRule] 08/11: dayofweek
	// [bindRule] 09/11: timeofday
	// [bindRule] 10/11: authmethod
	// [bindRule] 11/11: ssf
}

/*
This example demonstrates the interrogation of TargetKeyword const
definitions. This type qualifies for the Keyword interface type.

There are a total of nine (9) such TargetKeyword definitions.
*/
func ExampleACIv3TargetKeyword() {
	for idx, tk := range []ACIv3TargetKeyword{
		ACIv3Target,
		ACIv3TargetTo,
		ACIv3TargetAttr,
		ACIv3TargetCtrl,
		ACIv3TargetFrom,
		ACIv3TargetScope,
		ACIv3TargetFilter,
		ACIv3TargetAttrFilters,
		ACIv3TargetExtOp,
	} {
		fmt.Printf("[%s] %d/%d: %s\n",
			tk.Kind(), idx+1, 9, tk)
	}
	// Output:
	// [targetRule] 1/9: target
	// [targetRule] 2/9: target_to
	// [targetRule] 3/9: targetattr
	// [targetRule] 4/9: targetcontrol
	// [targetRule] 5/9: target_from
	// [targetRule] 6/9: targetscope
	// [targetRule] 7/9: targetfilter
	// [targetRule] 8/9: targattrfilters
	// [targetRule] 9/9: extop
}

/*
This example demonstrates the interrogation of qualifiers of
the Keyword interface type (BindKeyword and TargetKeyword
const definitions).

There are a total of twenty (20) qualifying instances (spanning
two (2) distinct types) of this interface.
*/
func ExampleACIv3Keyword() {
	for idx, k := range []ACIv3Keyword{
		ACIv3BindUDN,
		ACIv3BindRDN,
		ACIv3BindGDN,
		ACIv3BindUAT,
		ACIv3BindGAT,
		ACIv3BindIP,
		ACIv3BindDNS,
		ACIv3BindDoW,
		ACIv3BindToD,
		ACIv3BindAM,
		ACIv3BindSSF,
		ACIv3Target,
		ACIv3TargetTo,
		ACIv3TargetAttr,
		ACIv3TargetCtrl,
		ACIv3TargetFrom,
		ACIv3TargetScope,
		ACIv3TargetFilter,
		ACIv3TargetAttrFilters,
		ACIv3TargetExtOp,
	} {
		fmt.Printf("[%s] %02d/%d: %s\n",
			k.Kind(), idx+1, 20, k)
	}
	// Output:
	// [bindRule] 01/20: userdn
	// [bindRule] 02/20: roledn
	// [bindRule] 03/20: groupdn
	// [bindRule] 04/20: userattr
	// [bindRule] 05/20: groupattr
	// [bindRule] 06/20: ip
	// [bindRule] 07/20: dns
	// [bindRule] 08/20: dayofweek
	// [bindRule] 09/20: timeofday
	// [bindRule] 10/20: authmethod
	// [bindRule] 11/20: ssf
	// [targetRule] 12/20: target
	// [targetRule] 13/20: target_to
	// [targetRule] 14/20: targetattr
	// [targetRule] 15/20: targetcontrol
	// [targetRule] 16/20: target_from
	// [targetRule] 17/20: targetscope
	// [targetRule] 18/20: targetfilter
	// [targetRule] 19/20: targattrfilters
	// [targetRule] 20/20: extop
}

func ExampleACIv3BindKeyword_String() {
	fmt.Printf("%s", ACIv3BindUDN)
	// Output: userdn
}

func ExampleACIv3BindKeyword_Kind() {
	fmt.Printf("%s", ACIv3BindUDN.Kind())
	// Output: bindRule
}

func ExampleACIv3TargetKeyword_String() {
	fmt.Printf("%s", ACIv3TargetScope)
	// Output: targetscope
}

func ExampleACIv3TargetKeyword_Kind() {
	fmt.Printf("%s", ACIv3TargetAttrFilters.Kind())
	// Output: targetRule
}

func ExampleACIv3InheritanceLevel_String() {
	fmt.Printf("%s", ACIv3Level8)
	// Output: 8
}

func ExampleACIv3Inheritance_BRM() {
	var r NetscapeACIv3

	attr, err := r.Attribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	abtv, err := r.AttributeBindTypeOrValue("userattr", attr, "uid=frank,ou=People,dc=example,dc=com")
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh ACIv3Inheritance
	inh, err = r.Inheritance(abtv, 1, 3)
	if err != nil {
		fmt.Println(err)
		return
	}

	brm := inh.BRM()
	fmt.Printf("%d available comparison operator methods", brm.Len())
	// Output: 2 available comparison operator methods
}

func ExampleACIv3Inheritance_String() {
	var r NetscapeACIv3

	attr, err := r.Attribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uat ACIv3AttributeBindTypeOrValue
	uat, err = r.AttributeBindTypeOrValue("userattr", attr, `uid=frank,ou=People,dc=example,dc=com`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh ACIv3Inheritance
	if inh, err = r.Inheritance(uat, ACIv3Level6, ACIv3Level7); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", inh)
	// Output: parent[6,7].manager#uid=frank,ou=People,dc=example,dc=com
}

func ExampleACIv3Inheritance_Valid() {
	var inh ACIv3Inheritance
	fmt.Printf("%T.Valid: %t", inh, inh.Valid() == nil)
	// Output: dirsyn.ACIv3Inheritance.Valid: false
}

func ExampleACIv3Inheritance_Eq() {
	var r NetscapeACIv3

	attr, err := r.Attribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uat ACIv3AttributeBindTypeOrValue
	uat, err = r.AttributeBindTypeOrValue("userattr", attr, `uid=frank,ou=People,dc=example,dc=com`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh ACIv3Inheritance
	if inh, err = r.Inheritance(uat, ACIv3Level6, ACIv3Level7); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", inh.Eq())
	// Output: userattr="parent[6,7].manager#uid=frank,ou=People,dc=example,dc=com"
}

func ExampleACIv3Inheritance_Ne() {
	var r NetscapeACIv3

	attr, err := r.Attribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uat ACIv3AttributeBindTypeOrValue
	uat, err = r.AttributeBindTypeOrValue(ACIv3BindUAT, attr, `uid=frank,ou=People,dc=example,dc=com`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh ACIv3Inheritance
	if inh, err = r.Inheritance(uat, ACIv3Level1, ACIv3Level3); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", inh.Ne())
	// Output: userattr!="parent[1,3].manager#uid=frank,ou=People,dc=example,dc=com"
}

func ExampleACIv3Inheritance_IsZero() {
	var inh ACIv3Inheritance
	fmt.Printf("%t", inh.IsZero())
	// Output: true
}

func ExampleACIv3Inheritance_Len() {
	var r NetscapeACIv3

	attr, err := r.Attribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uat ACIv3AttributeBindTypeOrValue
	uat, err = r.AttributeBindTypeOrValue("userattr", attr, ACIv3BindTypeUSERDN)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh ACIv3Inheritance
	if inh, err = r.Inheritance(uat, ACIv3Level6, ACIv3Level7); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Number of levels: %d", inh.Len())
	// Output: Number of levels: 2
}

func ExampleACIv3Inheritance_Positive() {
	var r NetscapeACIv3

	attr, err := r.Attribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uat ACIv3AttributeBindTypeOrValue
	uat, err = r.AttributeBindTypeOrValue(ACIv3BindUAT, attr, ACIv3BindTypeUSERDN)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh ACIv3Inheritance
	if inh, err = r.Inheritance(uat, ACIv3Level6, ACIv3Level7); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Level 5 positive? %t", inh.Positive(5))
	// Output: Level 5 positive? false
}

func ExampleACIv3Inheritance_Shift() {
	var r NetscapeACIv3

	attr, err := r.Attribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	value := `uid=frank,ou=People,dc=example,dc=com`

	var abtv ACIv3AttributeBindTypeOrValue
	abtv, err = r.AttributeBindTypeOrValue("groupattr", attr, value)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh ACIv3Inheritance
	if inh, err = r.Inheritance(abtv, 1, 3); err != nil {
		fmt.Println(err)
		return
	}

	inh.Unshift(1)           // we changed our mind; remove level "1"
	inh.Unshift(`1`)         // (or, alternatively ...)
	inh.Unshift(ACIv3Level1) // (or, alternatively ...)
	inh.Shift(8)             // add the one we forgot

	fmt.Printf("Number of levels: %d", inh.Len())
	// Output: Number of levels: 2
}

func ExampleACIv3Inheritance_Unshift() {
	var r NetscapeACIv3

	attr, err := r.Attribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	value := `uid=frank,ou=People,dc=example,dc=com`

	var abtv ACIv3AttributeBindTypeOrValue
	abtv, err = r.AttributeBindTypeOrValue("groupattr", attr, value)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh ACIv3Inheritance
	if inh, err = r.Inheritance(abtv, 1, 3, 8); err != nil {
		fmt.Println(err)
		return
	}

	inh.Unshift(1)           // we changed our mind; remove level "1"
	inh.Unshift(`1`)         // (or, alternatively ...)
	inh.Unshift(ACIv3Level1) // (or, alternatively ...)

	fmt.Printf("Number of levels: %d", inh.Len())
	// Output: Number of levels: 2
}

func ExampleACIv3Inheritance_Keyword() {
	var r NetscapeACIv3

	attr, err := r.Attribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uat ACIv3AttributeBindTypeOrValue
	uat, err = r.AttributeBindTypeOrValue("userattr", attr, ACIv3BindTypeUSERDN)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh ACIv3Inheritance
	if inh, err = r.Inheritance(uat, ACIv3Level6, ACIv3Level7); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Keyword: %s", inh.Keyword())
	// Output: Keyword: userattr
}

func ExampleACIv3Inheritance_Positive_byString() {
	var r NetscapeACIv3

	attr, err := r.Attribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var gat ACIv3AttributeBindTypeOrValue
	gat, err = r.AttributeBindTypeOrValue("userattr", attr, ACIv3BindTypeGROUPDN)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh ACIv3Inheritance
	if inh, err = r.Inheritance(gat, ACIv3Level6, ACIv3Level7); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Level 6 positive? %t", inh.Positive(`6`))
	// Output: Level 6 positive? true
}

func TestACIv3Inheritance(t *testing.T) {
	var r NetscapeACIv3

	attr, err := r.Attribute(`manager`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	var uat ACIv3AttributeBindTypeOrValue
	uat, err = r.AttributeBindTypeOrValue(ACIv3BindUAT, attr, "USERDN")
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	var inh ACIv3Inheritance
	if inh, err = r.Inheritance(uat, ACIv3Level0, ACIv3Level1, ACIv3Level2, ACIv3Level8); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	got := inh.Eq()
	want := `userattr="parent[0,1,2,8].manager#USERDN"`
	if want != got.String() {
		t.Errorf("%s failed: want '%s', got '%s'", t.Name(), want, got)
	}
}

func ExampleACIv3Inheritance_uSERDN() {
	var r NetscapeACIv3

	attr, err := r.Attribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uat ACIv3AttributeBindTypeOrValue
	uat, err = r.AttributeBindTypeOrValue(ACIv3BindUAT, attr, ACIv3BindTypeUSERDN)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh ACIv3Inheritance
	if inh, err = r.Inheritance(uat, 0, 1, 2, 8); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", inh.Eq())
	// Output: userattr="parent[0,1,2,8].manager#USERDN"
}

func ExampleACIv3Inheritance_uAT() {
	var r NetscapeACIv3

	attr, err := r.Attribute(`manager`)
	if err != nil {
		fmt.Println(err)
		return
	}

	value := `uid=frank,ou=People,dc=example,dc=com`

	var uat ACIv3AttributeBindTypeOrValue
	uat, err = r.AttributeBindTypeOrValue("userattr", attr, value)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh ACIv3Inheritance
	if inh, err = r.Inheritance(uat, 3, 4); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", inh.Eq())
	// Output: userattr="parent[3,4].manager#uid=frank,ou=People,dc=example,dc=com"
}

func ExampleACIv3Inheritance_groupAttr() {
	var r NetscapeACIv3

	attr, err := r.Attribute(`owner`)
	if err != nil {
		fmt.Println(err)
		return
	}

	var gat ACIv3AttributeBindTypeOrValue
	gat, err = r.AttributeBindTypeOrValue("groupattr", attr, ACIv3BindTypeUSERDN)
	if err != nil {
		fmt.Println(err)
		return
	}

	var inh ACIv3Inheritance
	if inh, err = r.Inheritance(gat, 3, 4); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", inh.Eq())
	// Output: groupattr="parent[3,4].owner#USERDN"
}

func TestLevels_bogus(t *testing.T) {
	var inh ACIv3Inheritance
	if err := inh.Valid(); err == nil {
		t.Errorf("%s failed: invalid %T returned no validity error",
			t.Name(), inh)
		return
	}

	if inh.String() != badACIv3InhStr {
		t.Errorf("%s failed: invalid %T returned no bogus inheritance warning",
			t.Name(), inh)
		return
	}

	if inh.Eq() != badACIv3BindRule {
		t.Errorf("%s failed: invalid %T returned unexpected %T instance during equality bindrule creation",
			t.Name(), inh, badACIv3BindRule)
		return
	}

	if inh.Ne() != badACIv3BindRule {
		t.Errorf("%s failed: invalid %T returned unexpected %T instance during negated equality bindrule creation",
			t.Name(), inh, badACIv3BindRule)
		return
	}

	if !inh.IsZero() {
		t.Errorf("%s failed: bogus %T is non-zero",
			t.Name(), inh)
		return
	}

	for idx, rawng := range []string{
		`100.manager#USERDN`,
		`parent[100].manager#USERDN`,
		`parent[].manager#SELFDN`,
		`parent[4]#ROLEDN`,
		`parent[-1,20,3,476,5,666,7,666,9]?manager#LDAPURI`,
		`parent[0]].owner#GROUPDN`,
		`Parent[1,3,5,7)owner]#LDAPURI`,
		`parent[1,3,5,7)owner#LDAPURI`,
		`parent[1,2,3,4].squatcobbler`,
		``,
	} {
		var inh ACIv3Inheritance
		err := inh.parse(rawng)
		if err == nil {
			t.Errorf("%s failed [idx:%d]: parsing of bogus %T definition returned no error (%s)",
				t.Name(), idx, inh, rawng)
			return

		}

		if inh.String() != badACIv3InhStr {
			t.Errorf("%s failed [idx:%d]: %T parsing attempt failed; want '%s', got '%s'",
				t.Name(), idx, inh, badACIv3Inheritance, inh)
			return
		}
	}
}

func TestACIv3Inheritance_parse(t *testing.T) {
	for idx, raw := range []string{
		`parent[0,5,9].manager#USERDN`,
		`parent[1].manager#SELFDN`,
		`parent[4].terminated#ROLEDN`,
		`parent[0,1,2,3,4,5,6,7,8,9].manager#LDAPURI`,
		`parent[0].owner#GROUPDN`,
	} {
		var inh ACIv3Inheritance
		err := inh.parse(raw)
		if err != nil {
			t.Errorf("%s[%d] failed: %T parsing attempt failed; %v",
				t.Name(), idx, inh, err)
			return

		}

		if raw != inh.String() {
			t.Errorf("%s[%d] failed: %T parsing attempt failed; want '%s', got '%s'",
				t.Name(), idx, inh, raw, inh)
			return
		}

		want := fmt.Sprintf("(userattr=%q)", raw)
		equality := inh.Eq().SetParen(true)

		if got := equality.String(); want != got {
			t.Errorf("%s[%d] failed: %T equality creation error; want '%s', got '%s'",
				t.Name(), idx, inh, want, got)
			return
		}

		negation := inh.Ne().SetParen(true)
		want = fmt.Sprintf("(userattr!=%q)", raw)
		if got := negation.String(); want != got {
			t.Errorf("%s[%d] failed: %T negated equality creation error; want '%s', got '%s'",
				t.Name(), idx, inh, want, got)
			return
		}
	}
}

func TestACIv3Inheritance_codecov(t *testing.T) {
	var inh ACIv3Inheritance
	_ = inh.Positive(`4`)
	_ = inh.Keyword()
	_ = inh.String()
	_ = inh.Shift(1370)
	_ = inh.Shift(`farts`)
	_ = inh.Shift(-100)
	_ = inh.Shift(3.14159)
	_ = inh.Unshift(1370)
	_ = inh.Unshift(`farts`)
	_ = inh.Unshift(-100)
	_ = inh.Unshift(3.14159)
	_ = inh.Positive(`fart`)
	_ = inh.Positive(100000)
	_ = inh.Positive(-1)
	_ = inh.Positive(4)
	_ = inh.Positive("something awful")
	_ = inh.Positive(ACIv3InheritanceLevel(^uint16(0)))
	_ = inh.Positive(3.14159)
	_, _ = marshalACIv3Inheritance()
	_, _ = marshalACIv3Inheritance(rune(22))
	_, _ = marshalACIv3Inheritance(rune(22))
	_, _ = marshalACIv3Inheritance(ACIv3Inheritance{})
	inh, _ = marshalACIv3Inheritance("parent[0,8].owner#USERDN")
	_, _ = marshalACIv3Inheritance(inh)
	_, _ = marshalACIv3Inheritance("owner#USERDN", 1, 2, 3)
	_, _ = marshalACIv3Inheritance(rune(22), 1, 2, 3)
	inh.Shift(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
	inh.cast().Shift(13782)
	inh.Valid()
}

func TestACIv3FQDN(t *testing.T) {
	var r NetscapeACIv3
	f, err := r.FQDN()
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	_ = f.Len()
	_ = f.Keyword()
	_ = f.Eq()
	_ = f.Ne()
	_ = f.Valid()
	var typ string = f.Keyword().String()

	if f.len() != 0 {
		t.Errorf("%s failed: unexpected %T length: want '%d', got '%d'",
			t.Name(), f, 0, f.len())
		return
	}

	if err := f.Valid(); err == nil {
		t.Errorf("%s failed: empty %T deemed valid", t.Name(), f)
		return
	}

	f.Set()
	f.Set(``)
	f.Set(`-www-`, `-example`, `com-`)
	f.Set(`www`, `example`, `com`)

	want := `www.example.com`
	got := f.String()

	if want != got {
		t.Errorf("%s failed; want '%s', got '%s'", t.Name(), want, got)
		return
	}

	absurd := `eeeeeeeeeeeeeeeeeeeeeeeee#eee^eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeexample`

	if validLabel(absurd) {
		t.Errorf("%s failed: bogus %T label accepted as valid (%s)",
			t.Name(), absurd, absurd)
		return
	}

	var F ACIv3FQDN
	if F.String() != badACIv3FQDNStr {
		t.Errorf("%s failed: unexpected string result; want '%s', got '%s'",
			t.Name(), badACIv3FQDN, F)
		return
	}

	F.Set(`www`).Set(`$&^#*(`).Set(absurd).Set(`example`).Set(``).Set(`com`)
	if llen := F.Len(); llen != 3 {
		t.Errorf("%s failed; want '%d', got '%d'", t.Name(), 3, llen)
		return
	}

	// try every comparison operator supported in
	// this context ...
	brm := F.BRM()
	for i := 0; i < brm.Len(); i++ {
		cop, meth := brm.Index(i + 1)
		wcop := fmt.Sprintf("(%s%s\"www.example.com\")", f.Keyword(), cop)
		if T := meth(); T.SetParen(true).String() != wcop {
			t.Errorf("%s [%s] multival failed [%s rule]; %s, %s",
				t.Name(), F.Keyword(), cop.Context(), cop.Description(), typ)
			return
		}
	}
}

func TestDNS_alternativeACIv3FQDN(t *testing.T) {
	var r NetscapeACIv3

	want := `www.example.com`
	f, _ := r.FQDN(want)
	if got := f.String(); got != want {
		t.Errorf("%s failed; want '%s', got '%s'", t.Name(), want, got)
		return
	}
}

func TestACIv3IPAddress_BRM(t *testing.T) {
	var i ACIv3IPAddress
	_ = i.Len()
	_ = i.Eq()
	_ = i.Ne()
	_ = i.Valid()
	_ = i.Keyword()

	if !i.IsZero() {
		t.Errorf("%s failed: non-zero %T instance", t.Name(), i)
		return
	}

	if got := i.String(); got != badACIv3IPAddrStr {
		t.Errorf("%s failed: unexpected string result; want '%s', got '%s'",
			t.Name(), badACIv3IPAddrStr, got)
		return
	}

	var typ string = i.Keyword().String()

	if !i.unique(`192.168.0`) {
		t.Errorf("%s failed; uniqueness check returned bogus result",
			t.Name())
		return
	}
	i.Set(`192.168.0`)
	i.Set(`12.3.45.*`)
	i.Set(`12.3.45.*`) // duplicate
	i.Set(`10.0.0.0/8`)
	i.Valid()
	i.unique(`10.0.0.0/8`)

	if lens := i.Len(); lens != 3 {
		t.Errorf("%s failed: bad %T length; want '%d', got '%d'", t.Name(), i, 3, lens)
		return
	}

	if cond := i.Ne(); cond.IsZero() {
		t.Errorf("%s failed: nil %T instance!", t.Name(), cond)
		return
	}

	// try every comparison operator supported in
	// this context ...
	brm := i.BRM()
	for j := 0; j < brm.Len(); j++ {
		cop, meth := brm.Index(j + 1)
		if meth == nil {
			t.Errorf("%s [%s] multival failed: expected %s method (%T), got nil",
				t.Name(), i.Keyword(), cop.Context(), meth)
			return
		}

		wcop := fmt.Sprintf("(%s%s%q)", i.Keyword(), cop, i)
		if T := meth(); T.SetParen(true).String() != wcop {
			t.Errorf("%s [%s] multival failed [%s rule]",
				t.Name(), i.Keyword(), typ)
			return
		}
	}
}

func ExampleACIv3FQDN_Eq() {
	var r NetscapeACIv3

	f, _ := r.FQDN() // no need to check error w/o arguments.

	// Let's set the host labels incrementally ...
	f.Set(`www`)
	f.Set(`example`)
	f.Set(`com`)

	fmt.Printf("%s", f.Eq())
	// Output: dns="www.example.com"
}

func ExampleACIv3FQDN_Ne() {
	var r NetscapeACIv3

	f, err := r.FQDN(`www.example.com`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", f.Ne().SetPaddingStyle(1))
	// Output: dns != "www.example.com"
}

func ExampleACIv3IPAddress_Set() {
	var r NetscapeACIv3

	i, _ := r.IPAddress() // no need to check error w/o arguments.

	i.Set(`192.168.0`).Set(`12.3.45.*`).Set(`10.0.0.0/8`)
	neg := i.Ne().SetParen(true).SetPaddingStyle(1)
	fmt.Printf("%s", neg)
	// Output: ( ip != "192.168.0,12.3.45.*,10.0.0.0/8" )
}

func ExampleACIv3IPAddress_Eq_oneShot() {
	var r NetscapeACIv3

	i, _ := r.IPAddress()
	fmt.Printf("%s", i.Set(`192.168.0`, `12.3.45.*`, `10.0.0.0/8`).Eq())
	// Output: ip="192.168.0,12.3.45.*,10.0.0.0/8"
}

/*
This example demonstrates the creation of an instance of ACIv3IPAddress, which
is used in a variety of contexts.

In this example, a string name is fed to the package level IP function to form
a complete ACIv3IPAddress instance, which is then shown in string representation.
*/
func ExampleNetscapeACIv3_IPAddress() {
	var r NetscapeACIv3
	ip, err := r.IPAddress(`10.0.0.1`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", ip)
	// Output: 10.0.0.1
}

/*
This example demonstrates the string representation of the receiver instance.
*/
func ExampleACIv3IPAddress_String() {
	var r NetscapeACIv3
	ip, err := r.IPAddress(`192.168.56.7`)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s", ip)
	// Output: 192.168.56.7
}

func ExampleACIv3IPAddress_Keyword() {
	var ip ACIv3IPAddress
	fmt.Printf("%v", ip.Keyword())
	// Output: ip
}

func ExampleACIv3IPAddress_Kind() {
	var ip ACIv3IPAddress
	fmt.Printf("%v", ip.Kind())
	// Output: ip
}

func ExampleACIv3IPAddress_Len() {
	var r NetscapeACIv3
	ip, err := r.IPAddress(`10.8.`)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%d", ip.Len())
	// Output: 1
}

/*
This example demonstrates a check of the receiver for "nilness".
*/
func ExampleACIv3IPAddress_IsZero() {
	var r NetscapeACIv3
	ip, err := r.IPAddress(`10.8.`, `192.`)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%t", ip.IsZero())
	// Output: false
}

/*
This example demonstrates a check of the receiver for an aberrant state.
*/
func ExampleACIv3IPAddress_Valid() {
	var ip ACIv3IPAddress
	fmt.Printf("Valid: %t", ip.Valid() == nil)
	// Output: Valid: false
}

func ExampleACIv3IPAddress_Eq() {
	var r NetscapeACIv3

	i, err := r.IPAddress("192.8.", "10.7.0")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", i.Eq())
	// Output: ip="192.8.,10.7.0"
}

func ExampleACIv3IPAddress_Ne() {
	var r NetscapeACIv3

	i, err := r.IPAddress("10.8.")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", i.Ne())
	// Output: ip!="10.8."
}

func ExampleACIv3FQDN_Set() {
	var r NetscapeACIv3
	f, err := r.FQDN("*.example.com")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", f)
	// Output: *.example.com
}

func ExampleACIv3FQDN_Eq_oneShot() {
	var r NetscapeACIv3
	f, err := r.FQDN("www.example.com")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s", f.Eq())
	// Output: dns="www.example.com"
}

/*
This example demonstrates the string representation of the receiver instance.
*/
func ExampleACIv3FQDN_String() {
	var r NetscapeACIv3
	f, err := r.FQDN("example.com")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", f)
	// Output: example.com
}

func ExampleACIv3FQDN_Keyword() {
	var f ACIv3FQDN
	fmt.Printf("%v", f.Keyword())
	// Output: dns
}

/*
This example demonstrates a check of the receiver for "nilness".
*/
func ExampleACIv3FQDN_IsZero() {
	var r NetscapeACIv3
	f, err := r.FQDN("www.example.com")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%t", f.IsZero())
	// Output: false
}

/*
This example demonstrates a check of the receiver for an aberrant state.
*/
func ExampleACIv3FQDN_Valid() {
	var f ACIv3FQDN
	fmt.Printf("Valid: %t", f.Valid() == nil)
	// Output: Valid: false
}

func ExampleACIv3FQDN_BRM() {
	var r NetscapeACIv3
	f, err := r.FQDN("www.example.com")
	if err != nil {
		fmt.Println(err)
		return
	}
	cops := f.BRM()
	fmt.Printf("%T allows Eq: %t", f, cops.Contains(`=`))
	// Output: dirsyn.ACIv3FQDN allows Eq: true
}

func ExampleACIv3FQDN_Len() {
	var r NetscapeACIv3
	f, err := r.FQDN("www.example.com")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%T contains %d DNS labels", f, f.Len())
	// Output: dirsyn.ACIv3FQDN contains 3 DNS labels
}

func ExampleACIv3IPAddress_BRM() {
	var r NetscapeACIv3
	ip, err := r.IPAddress("www.example.com")
	if err != nil {
		fmt.Println(err)
		return
	}
	cops := ip.BRM()
	fmt.Printf("%T allows Eq: %t", ip, cops.Contains(`=`))
	// Output: dirsyn.ACIv3IPAddress allows Eq: true
}

func TestACIv3SecurityStrengthFactor(t *testing.T) {
	var (
		r      NetscapeACIv3
		factor ACIv3SecurityStrengthFactor
		typ    string = ACIv3BindSSF.String()
	)

	for i := 0; i < 257; i++ {
		want := itoa(i) // what we expect (string representation)

		var err error
		factor, err = r.SecurityStrengthFactor(i)
		if err != nil {
			t.Errorf("%s failed [%s int]: %v",
				t.Name(), typ, err)
			return
		}
		if want != factor.String() {
			t.Errorf("%s failed [%s int]; want %s, got %s",
				t.Name(), typ, want, factor.String())
			return
		}

		// reset using string representation of iterated integer
		if got := factor.Set(want); want != got.String() {
			t.Errorf("%s failed [%s str]",
				t.Name(), typ)
			return
		}

		brm := factor.BRM()
		for c := 0; c < brm.Len(); c++ {
			cop, meth := brm.Index(c + 1)
			wcop := fmt.Sprintf("%s%s%q", factor.Keyword(), cop, factor.String())

			// create bindrule B using comparison
			// operator (cop).
			if B := meth(); B.String() != wcop {
				t.Errorf("%s failed [%s rule]", t.Name(), typ)
				return
			}
		}
		factor.clear() // codecov

	}

	// try to set our factor using special keywords
	// this package understands ...
	for word, value := range map[string]string{
		`mAx`:  `256`,
		`full`: `256`,
		`nOnE`: `0`,
		`OFF`:  `0`,
		`fart`: `0`,
	} {
		factor, _ = r.SecurityStrengthFactor(value)
		if got := factor.Set(word); got.String() != value {
			t.Errorf("%s failed [factor word '%s']", t.Name(), word)
			return
		}
	}
}

func TestACIv3AuthenticationMethod(t *testing.T) {
	// codecov
	_ = noAuth.Eq()
	_ = noAuth.Ne()

	ACIv3AuthenticationMethodLowerCase = true

	for idx, auth := range authMap {
		if _, err := marshalACIv3AuthenticationMethod(auth); err != nil {
			t.Errorf("%s[%d] failed: unable to match auth method '%s'",
				t.Name(), idx, auth)
			return
		} else if _, err = marshalACIv3AuthenticationMethod(auth.String()); err != nil {
			t.Errorf("%s[%d] failed: unable to match auth method by string (%s)",
				t.Name(), idx, auth.String())
			return
		}
	}

	ACIv3AuthenticationMethodLowerCase = false
}

func ExampleACIv3SecurityStrengthFactor_Eq() {
	var r NetscapeACIv3
	ssf, err := r.SecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", ssf.Set(128).Ne().SetParen(true))
	// Output: (ssf!="128")
}

func ExampleACIv3SecurityStrengthFactor_Ne() {
	var r NetscapeACIv3
	ssf, err := r.SecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", ssf.Set(128).Ne().SetParen(true))
	// Output: (ssf!="128")
}

func ExampleACIv3SecurityStrengthFactor_Lt() {
	var r NetscapeACIv3
	ssf, err := r.SecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", ssf.Set(128).Lt())
	// Output: ssf<"128"
}

func ExampleACIv3SecurityStrengthFactor_Le() {
	var r NetscapeACIv3
	ssf, err := r.SecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", ssf.Set(128).Le().SetParen(true))
	// Output: (ssf<="128")
}

func ExampleACIv3SecurityStrengthFactor_Gt() {
	var r NetscapeACIv3
	ssf, err := r.SecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", ssf.Set(128).Gt().SetParen(true))
	// Output: (ssf>"128")
}

func ExampleACIv3SecurityStrengthFactor_Ge() {
	var r NetscapeACIv3
	ssf, err := r.SecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", ssf.Set(128).Ge().SetParen(true))
	// Output: (ssf>="128")
}

func ExampleACIv3SecurityStrengthFactor_String() {
	var r NetscapeACIv3
	ssf, err := r.SecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s", ssf)
	// Output: 128
}

func ExampleACIv3SecurityStrengthFactor_Valid() {
	var s ACIv3SecurityStrengthFactor
	fmt.Printf("Valid: %t", s.Valid() == nil) // zero IS valid, technically speaking!
	// Output: Valid: true
}

func ExampleACIv3SecurityStrengthFactor_IsZero() {
	var s ACIv3SecurityStrengthFactor
	fmt.Printf("Zero: %t", s.IsZero())
	// Output: Zero: true
}

func ExampleACIv3SecurityStrengthFactor_Keyword() {
	var s ACIv3SecurityStrengthFactor
	fmt.Printf("Keyword: %s", s.Keyword())
	// Output: Keyword: ssf
}

func ExampleNetscapeACIv3_SecurityStrengthFactor() {
	// convenient alternative to "var X ACIv3SecurityStrengthFactor, X.Set(...) ..."
	var r NetscapeACIv3
	ssf, err := r.SecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s", ssf)
	// Output: 128
}

func ExampleACIv3AuthenticationMethod_BRM() {
	meths := ACIv3Anonymous.BRM()
	fmt.Printf("%d available aci.BindRuleMethod instances", meths.Len())
	// Output: 2 available aci.BindRuleMethod instances
}

func ExampleACIv3AuthenticationMethod_Ne() {
	fmt.Printf("%s", ACIv3Anonymous.Ne())
	// Output: authmethod!="NONE"
}

func ExampleACIv3AuthenticationMethod_Eq() {
	fmt.Printf("%s", ACIv3SASL.Eq())
	// Output: authmethod="SASL"
}

func ExampleACIv3SecurityStrengthFactor_BRM() {
	var r NetscapeACIv3

	ssf, err := r.SecurityStrengthFactor(128)
	if err != nil {
		fmt.Println(err)
		return
	}
	meths := ssf.BRM()

	fmt.Printf("%d available aci.BindRuleMethod instances", meths.Len())
	// Output: 6 available aci.BindRuleMethod instances
}

func ExampleACIv3AuthenticationMethod_String() {
	fmt.Printf("%s", ACIv3EXTERNAL)
	// Output: SASL EXTERNAL
}

func ExampleACIv3ObjectIdentifier_IsZero() {
	var oid ACIv3ObjectIdentifier
	fmt.Printf("%T is zero: %t\n", oid, oid.IsZero())
	// Output: dirsyn.ACIv3ObjectIdentifier is zero: true
}

/*
This example demonstrates the use of the Index method to obtain a single slice OID.
*/
func ExampleACIv3ObjectIdentifier_Index() {
	var r NetscapeACIv3

	oid, err := r.LDAPControlOIDs(
		`1.3.6.1.4.1.56521.999.5`,
		`1.3.6.1.4.1.56521.999.6`,
		`1.3.6.1.4.1.56521.999.7`,
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Slice keyword: %s", oid.Index(1))
	// Output: Slice keyword: 1.3.6.1.4.1.56521.999.6
}

func ExampleACIv3ObjectIdentifier_Eq() {
	var r NetscapeACIv3

	oid, err := r.LDAPControlOIDs(
		`1.3.6.1.4.1.56521.999.5`,
		`1.3.6.1.4.1.56521.999.6`,
		`1.3.6.1.4.1.56521.999.7`,
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Target rule: %s", oid.Eq())
	// Output: Target rule: (targetcontrol="1.3.6.1.4.1.56521.999.5||1.3.6.1.4.1.56521.999.6||1.3.6.1.4.1.56521.999.7")
}

func ExampleACIv3ObjectIdentifier_Ne() {
	var r NetscapeACIv3

	oid, err := r.LDAPExtendedOperationOIDs(
		`1.3.6.1.4.1.56521.999.5`,
		`1.3.6.1.4.1.56521.999.6`,
		`1.3.6.1.4.1.56521.999.7`,
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Target rule: %s", oid.Ne())
	// Output: Target rule: (extop!="1.3.6.1.4.1.56521.999.5||1.3.6.1.4.1.56521.999.6||1.3.6.1.4.1.56521.999.7")
}

func ExampleACIv3ObjectIdentifier_Push() {
	var r NetscapeACIv3

	oid, err := r.LDAPExtendedOperationOIDs(
		`1.3.6.1.4.1.56521.999.5`,
		`1.3.6.1.4.1.56521.999.6`,
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	// Add a third OID we forgot:
	oid.Push(`1.3.6.1.4.1.56521.999.7`)

	fmt.Printf("%d", oid.Len())
	// Output: 3
}

/*
This example demonstrates use of the [ACIv3ObjectIdentifier.Len] method to return the number of slices present within the receiver as an integer.
*/
func ExampleACIv3ObjectIdentifier_Len() {
	var r NetscapeACIv3

	oid, err := r.LDAPExtendedOperationOIDs(
		`1.3.6.1.4.1.56521.999.5`,
		`1.3.6.1.4.1.56521.999.6`,
		`1.3.6.1.4.1.56521.999.7`,
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%d", oid.Len())
	// Output: 3
}

/*
This example demonstrates use of the [ACIv3ObjectIdentifier.Keyword] method to obtain the current [ACIv3TargetKeyword] context from the receiver.
*/
func ExampleACIv3ObjectIdentifier_Keyword() {
	var r NetscapeACIv3

	oid, err := r.LDAPExtendedOperationOIDs(
		`1.3.6.1.4.1.56521.999.5`,
		`1.3.6.1.4.1.56521.999.6`,
		`1.3.6.1.4.1.56521.999.7`,
	)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", oid.Keyword())
	// Output: extop
}

/*
This example demonstrates the use of the [ACIv3ObjectIdentifier.TRM] method to obtain a list of available [ACIv3Operator] identifiers and methods.
*/
func ExampleACIv3ObjectIdentifier_TRM() {
	var oid ACIv3ObjectIdentifier
	fmt.Printf("Allows greater-than: %t", oid.TRM().Contains(ACIv3Gt))
	// Output: Allows greater-than: false
}

/*
This example demonstrates the use of the [ACIv3ObjectIdentifier.Valid] method upon a nil receiver.
*/
func ExampleACIv3ObjectIdentifier_Valid() {
	var oid ACIv3ObjectIdentifier
	fmt.Printf("Valid: %t", oid.Valid() == nil)
	// Output: Valid: false
}

func TestAllow_all(t *testing.T) {
	var r NetscapeACIv3

	G, err := r.Permission(true,
		ACIv3ReadAccess,
		ACIv3CompareAccess,
		ACIv3SearchAccess,
		ACIv3ImportAccess,
		ACIv3ExportAccess,
		ACIv3SelfWriteAccess,
		ACIv3DeleteAccess,
		ACIv3AddAccess,
		ACIv3WriteAccess)

	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	want := `allow(all)`
	got := G.String()
	if want != got {
		t.Errorf("%s failed: want '%s', got '%s'", t.Name(), want, got)
		return
	}
}

func ExampleACIv3Right_String() {
	// iterate all of the known Right definitions
	// defined as constants in this package.
	for idx, privilege := range []ACIv3Right{
		ACIv3NoAccess,
		ACIv3ReadAccess,
		ACIv3WriteAccess,
		ACIv3AddAccess,
		ACIv3DeleteAccess,
		ACIv3SearchAccess,
		ACIv3CompareAccess,
		ACIv3SelfWriteAccess,
		ACIv3ProxyAccess,
		ACIv3ImportAccess,
		ACIv3ExportAccess,
		ACIv3AllAccess, // does NOT include proxy access !
	} {
		fmt.Printf("Privilege %02d/%d: %s (bit:%d)\n", idx+1, 12, privilege, int(privilege))
	}
	// Output:
	// Privilege 01/12: none (bit:0)
	// Privilege 02/12: read (bit:1)
	// Privilege 03/12: write (bit:2)
	// Privilege 04/12: add (bit:4)
	// Privilege 05/12: delete (bit:8)
	// Privilege 06/12: search (bit:16)
	// Privilege 07/12: compare (bit:32)
	// Privilege 08/12: selfwrite (bit:64)
	// Privilege 09/12: proxy (bit:128)
	// Privilege 10/12: import (bit:256)
	// Privilege 11/12: export (bit:512)
	// Privilege 12/12: all (bit:895)
}

/*
This example demonstrates the withholding (denial) of all privileges except proxy.
*/
func ExampleACIv3Permission_granting() {
	var r NetscapeACIv3

	// grant read/write
	p, err := r.Permission(true, ACIv3ReadAccess, ACIv3WriteAccess)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", p)
	// Output: allow(read,write)
}

/*
This example demonstrates the withholding (denial) of all privileges except proxy.
*/
func ExampleACIv3Permission_witholding() {
	var r NetscapeACIv3

	// deny everything (this does not include proxy privilege)
	p, err := r.Permission(false, ACIv3AllAccess)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", p)
	// Output: deny(all)
}

func ExampleACIv3Permission_IsZero() {
	var p ACIv3Permission
	fmt.Printf("Privileges are undefined: %t", p.IsZero())
	// Output: Privileges are undefined: true
}

func ExampleACIv3Permission_Valid() {
	var p ACIv3Permission
	fmt.Printf("%T is ready for use: %t", p, p.Valid() == nil)
	// Output: dirsyn.ACIv3Permission is ready for use: false
}

func ExampleACIv3Permission_Disposition() {
	var r NetscapeACIv3
	p, err := r.Permission(true, "read", "write", "compare", "selfwrite")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", p.Disposition())
	// Output: allow
}

func ExampleACIv3Permission_String() {
	var r NetscapeACIv3
	p, err := r.Permission(true, "read", "write", "compare", "selfwrite")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s", p)
	// Output: allow(read,write,compare,selfwrite)
}

func ExampleACIv3Permission_Len() {
	var r NetscapeACIv3
	p, err := r.Permission(false, "read", "write", "compare", "search", "proxy")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Number of privileges denied: %d", p.Len())
	// Output: Number of privileges denied: 5
}

func ExampleACIv3Permission_shifting() {
	var r NetscapeACIv3
	// Shift or Unshift values may be ACIv3Right constants, or their
	// string or uint16 equivalents:
	p, err := r.Permission(false, ACIv3ReadAccess, "write", 32, ACIv3SearchAccess, "PROXY")
	if err != nil {
		fmt.Println(err)
		return
	}

	p.Unshift("compare") // remove the negated compare (bit 32) privilege
	fmt.Printf("Forbids compare: %t", p.Positive(`compare`))
	// Output: Forbids compare: false
}

func TestACIv3Rights_bogus(t *testing.T) {
	var p ACIv3Permission
	err := p.Valid()
	if err == nil {
		t.Errorf("%s failed: invalid %T returned no validity error",
			t.Name(), p)
		return
	}

	var r NetscapeACIv3
	p, _ = r.Permission(true)
	if p.String() != badACIv3PermStr {
		t.Errorf("%s failed: invalid %T returned no bogus string warning",
			t.Name(), p)
		return
	}

	p.Unshift(`all`)
	p.Shift(-1985)       //underflow
	p.Shift(45378297659) //overflow
	if !p.IsZero() {
		t.Errorf("%s failed: overflow or underflow shift value accepted for %T",
			t.Name(), p)
		return
	}

	p.Unshift(-5)     //underflow
	p.Unshift(134559) //overflow
	if !p.IsZero() {
		t.Errorf("%s failed: overflow or underflow unshift value accepted for %T",
			t.Name(), p)
		return
	}

}

func TestRights_lrShift(t *testing.T) {
	var r NetscapeACIv3
	p, err := r.Permission(true, "none")
	if err != nil {
		fmt.Println(err)
		return
	} else if !p.Positive(0) || !p.Positive(`none`) || !p.positive(ACIv3NoAccess) {
		t.Errorf("%s failed: cannot identify 'none' permission", t.Name())
		return
	}

	// three iterations, one per supported
	// ACIv3Right type
	for i := 0; i < 3; i++ {

		// iterate each of the rights in the
		// rights/names map
		for k, v := range aCIRightsMap {

			if k == 0 {
				continue
			}

			term, typ := testGetRightsTermType(i, k, v)

			shifters := map[int]func(...any) ACIv3Permission{
				0: p.Shift,
				1: p.Unshift,
			}

			for j := 0; j < len(shifters); j++ {
				mode, phase := testGetRightsPhase(j)
				if shifters[j](term); p.Positive(term) != phase {
					t.Errorf("%s failed: %T %s %s failed [key:%d; term:%v] (value:%v)",
						t.Name(), p, typ, mode, k, term, p)
					return
				}
			}
		}
	}
}

func testGetRightsPhase(j int) (mode string, phase bool) {
	mode = `shift`
	if phase = (0 == j); !phase {
		mode = `un` + mode
	}

	return
}

func testGetRightsTermType(i int, k ACIv3Right, v string) (term any, typ string) {
	term = k // default
	switch i {
	case 1:
		term = v // string name (e.g.: read)
	case 2:
		term = ACIv3Right(k) // Right
	}
	typ = fmt.Sprintf("%T", term) // label for err

	return
}

func TestACIv3Permission_codecov(t *testing.T) {
	var r NetscapeACIv3
	var p, d ACIv3Permission
	_ = p.Valid()
	_ = p.Len()
	_ = p.Valid()
	_ = p.Disposition()
	_ = p.Shift()
	_ = p.Shift(nil)
	_ = p.Positive(nil)
	_ = p.Shift(4)
	_ = p.Shift(4547887935)
	_ = p.Shift(-45478879)
	_ = p.Unshift()
	_ = p.Unshift(nil)
	_ = p.Unshift(4)
	_ = p.Unshift(4547887935)
	_ = p.Unshift(-45478879)
	_, err := marshalACIv3Permission(`alow(red,rite)`)
	if err == nil {
		t.Errorf("%s failed: expected error, got nothing", t.Name())
		return
	}
	_ = p.Disposition()
	_ = p.Positive("PROXY")

	p, err = r.Permission(true, "read", "write")
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	d, err = r.Permission(false, "read", "write")
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	_ = p.Unshift()
	_ = p.Unshift(nil)
	_ = p.Unshift(4)
	_ = p.Shift(4547887935)
	_ = p.Positive(4547887935)
	_ = p.Shift(-45478879)
	_ = p.Unshift(4547887935)
	_ = p.Unshift(-45478879)
	_ = d.Unshift()
	_ = d.Unshift(nil)
	_ = d.Unshift(4)
	_ = d.Shift(4547887935)
	_ = d.Positive(4547887935)
	_ = d.Shift(-45478879)
	_ = d.Unshift(4547887935)
}

func TestACIv3DistinguishedName(t *testing.T) {
	var r NetscapeACIv3

	mydn, _ := marshalDistinguishedName("cn=Jesse Coretta,ou=Contractors,ou=Accounts,dc=example,dc=com")

	// Create a mix of proper DistinguishedName instances,
	// or their string equivalents.
	dNs := []any{
		mydn,
		"cn=Frank Rizzo,ou=Customers,ou=Accounts,dc=example,dc=com",
	}

	var strRes []string
	for _, dn := range dNs {
		switch tv := dn.(type) {
		case string:
			if !hasPfx(tv, "ldap:///") {
				tv = "ldap:///" + tv
			}
			strRes = append(strRes, tv)
		case DistinguishedName:
			strRes = append(strRes, "ldap:///"+tv.String())
		}
	}

	// Resulting string value we expect
	expect := join(strRes, `||`)

	for idx, kw := range []ACIv3BindKeyword{
		ACIv3BindUDN,
		ACIv3BindGDN,
		ACIv3BindRDN,
	} {
		for idx2, typ := range []any{
			kw,
			kw.String(),
		} {
			dn, err := r.BindDistinguishedName(append([]any{typ}, dNs...)...)
			if err != nil {
				t.Errorf("%s[%d][%d] failed: %v", t.Name(), idx, idx2, err)
				return
			} else if dn.Len() != len(dNs) {
				t.Errorf("%s[%d][%d] failed: expected %d, got %d", t.Name(), idx, idx2, len(dNs), dn.Len())
				return
			}

			rule := dn.Eq()
			want := kw.String() + "=\"" + expect + `"`
			if got := rule.String(); got != want {
				t.Errorf("%s[%d][%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, idx2, want, got)
				return
			}
		}
	}

	for idx, kw := range []ACIv3TargetKeyword{
		ACIv3Target,
		ACIv3TargetTo,
		ACIv3TargetFrom,
	} {
		for idx2, typ := range []any{
			kw,
			kw.String(),
		} {
			dn, err := r.TargetDistinguishedName(append([]any{typ}, dNs...)...)
			if err != nil {
				t.Errorf("%s[%d][%d] failed: %v", t.Name(), idx, idx2, err)
				return
			} else if dn.Len() != len(dNs) {
				t.Errorf("%s[%d][%d] failed: expected %d, got %d", t.Name(), idx, idx2, len(dNs), dn.Len())
				return
			}

			rule := dn.Eq()
			want := `(` + kw.String() + "=\"" + expect + `")`
			if got := rule.String(); got != want {
				t.Errorf("%s[%d][%d] failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), idx, idx2, want, got)
				return
			}
		}
	}

}
