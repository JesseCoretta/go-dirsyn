package dirsyn

import "os"

func errorBadLength(name string, length int) error {
	return mkerr(`Invalid length '` + fmtInt(int64(length), 10) + `' for ` + name)
}

func errorBadType(name string) error {
	return mkerr(`Incompatible input type for ` + name)
}

func errorTxt(txt string) error {
	return mkerr(txt)
}

var (
	nilBEREncodeErr   error = mkerr("Cannot BER encode nil instance")
	unknownBERPacket  error = mkerr("Unidentified BER packet; cannot process")
	endOfFilterErr    error = mkerr("Unexpected end of filter")
	invalidFilterErr  error = mkerr("Invalid or malformed filter")
	emptyFilterSetErr error = mkerr("Zero or invalid filter SET")
	invalidMR         error = mkerr("Invalid or incompatible matching rule")
	nilInstanceErr    error = mkerr("Nil instance error")
	errNotExist       error = os.ErrNotExist
)

// ACI-specific errror
var (
	badACIv3InheritanceLevelErr         error = mkerr("Invalid ACI inheritance level")
	badACIv3AttributeBindTypeOrValueErr error = mkerr("Invalid ACI AttributeBindTypeOrValue")
	badACIv3ValAssignmentErr            error = mkerr("Unsupported ACI value assignment per keyword")
	badACIv3AttributeErr                error = mkerr("Invalid ACI attribute")
	badACIv3InstructionErr              error = mkerr("Invalid ACI Instruction")
	badACIv3AFErr                       error = mkerr("Invalid ACI Attribute Filter")
	badACIv3AFOpErr                     error = mkerr("Invalid ACI Attribute Filter Operation")
	badACIv3AFOpItemErr                 error = mkerr("Invalid ACI Attribute Filter Operation Item")
	badACIv3KWErr                       error = mkerr("Invalid ACI keyword")
	badACIv3CopErr                      error = mkerr("Invalid ACI comparison operator")
	badACIv3InhErr                      error = mkerr("Invalid ACI inheritance statement")
	badACIv3DoWErr                      error = mkerr("Invalid ACI day of week value")
	badACIv3ToDErr                      error = mkerr("Invalid ACI time of day value")
	badACIv3FQDNErr                     error = mkerr("Invalid ACI FQDN")
	badACIv3PermErr                     error = mkerr("Invalid ACI permission statement")
	badACIv3TRErr                       error = mkerr("Invalid ACI target rule statement")
	badACIv3BRErr                       error = mkerr("Invalid ACI bind rule statement")
	badACIv3PBRErr                      error = mkerr("Invalid ACI permission+bind rule statement")
	missingACIv3LvlsErr                 error = mkerr("Missing or invlaid ACI inheritance level(s)")
)
