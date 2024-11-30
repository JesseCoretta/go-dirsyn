package dirsyn

import (
	"testing"
)

func TestWordMatch(t *testing.T) {
	result, err := wordMatch(`word up`, `werd up`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result.False() {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s", t.Name(), `FALSE`, result)
	}

	_, _ = wordMatch(nil, `words are cool`)
	_, _ = wordMatch(`words are cool`, struct{}{})
	_, _ = wordMatch(`a`, `words are cool`)
}

func TestKeywordMatch(t *testing.T) {
	result, err := keywordMatch(`word up`, `word_up:cool`)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
	} else if !result.False() {
		t.Errorf("%s failed:\nwant: %s\ngot:  %s", t.Name(), `FALSE`, result)
	}

	_, _ = keywordMatch(`a`, struct{}{})
	_, _ = keywordMatch(struct{}{}, nil)
	_, _ = keywordMatch(`a a :: a`, `a`)
}
