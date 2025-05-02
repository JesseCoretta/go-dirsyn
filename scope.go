package dirsyn

/*
scope.go contains basic RFC4511 Search Scope types and methods. Note that the
ACIScope equivalent is defined within aci.go.
*/

/*
SearchScope is a type definition used to represent one of the four (4) possible LDAP Search Scope types
that are eligible for use within the ACIv3 syntax specification honored by this package.

SearchScope constants are generally used for crafting TargetRule instances that bear the [TargetScope]
[TargetKeyword], as well as for crafting fully-qualified LDAP Search URIs.

See the SearchScope constants defined in this package for specific scopes available.
*/
type SearchScope uint8

/*
Scope initializes, sets and returns an instance of SearchScope in one shot. Valid input types are as follows:

  - Standard scope names as string values (e.g.: `base`, `one`, `subtree`)
  - Integer representations of scopes (see the predefined [SearchScope] constants for details)

This function may only be needed in certain situations where a scope needs to be parsed from values with
different representations. Usually the predefined [SearchScope] constants are sufficient.
*/
func (r RFC4511) SearchScope(x any) (s SearchScope, err error) {
	switch tv := x.(type) {
	case string:
		s = strToScope(tv)
	case int:
		s = intToScope(tv)
	}

	if s == noScope {
		err = errorBadType("search scope")
	}

	return
}

/*
SearchScope constants define four (4) known LDAP Search Scopes permitted for use per
the ACIv3 syntax specification honored by this package.
*/
const (
	noScope          SearchScope = iota // 0x0 <unspecified_scope>
	ScopeBaseObject                     // 0x1, `base`
	ScopeSingleLevel                    // 0x2, `one` or `onelevel`
	ScopeSubtree                        // 0x3, `sub` or `subtree`
	// see aci.go for Subordinate (0x4)
)

/*
invalid value constants used as stringer method returns when something goes wrong :/
*/
const (
	badSearchScope = `<invalid_search_scope>`
)

/*
standard returns the more common naming variations for a given search scope.
Generally, these are used in fully-qualified LDAP Search URL statements.
*/
func (r SearchScope) String() (s string) {
	s = badSearchScope
	switch r {
	case ScopeBaseObject:
		s = `base`
	case ScopeSingleLevel:
		s = `one`
	case ScopeSubtree:
		s = `sub`
	}

	return
}

/*
strToScope returns a SearchScope constant based on the string input.
*/
func strToScope(x string) (s SearchScope) {
	s = noScope
	switch lc(x) {
	case `base`, `baseobject`:
		s = ScopeBaseObject
	case `one`, `onelevel`:
		s = ScopeSingleLevel
	case `sub`, `subtree`:
		s = ScopeSubtree
	}

	return
}

/*
intToScope returns a SearchScope constant based on the integer input.
*/
func intToScope(x int) (s SearchScope) {
	s = noScope
	x++
	switch x {
	case 1:
		s = ScopeBaseObject
	case 2:
		s = ScopeSingleLevel
	case 3:
		s = ScopeSubtree
	}

	return
}
