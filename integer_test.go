package dirsyn

import (
	"testing"
)

func TestInteger(t *testing.T) {
	var r RFC4517

	for _, strint := range []string{
		`1`,
		`0`,
		`-38458953`,
		`4839058392687026702779083590780972360798625907867923470670934207967924076924`,
		`-4839058392687026702779083590780972360798625907867923470670934207967924076924`,
	} {
		if err := r.Integer(strint); err != nil {
			t.Errorf("%s failed: %v", t.Name(), err)
		}
	}
}
