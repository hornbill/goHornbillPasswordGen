package hornbillPasswordGen

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"math/rand"
	"unicode/utf8"
)

type cryptoSource struct{}

//PasswordProfileStruct is the struct that contains the profile details used when generating a new Password
type PasswordProfileStruct struct {
	Length       int
	UseLower     bool
	ForceLower   int
	UseUpper     bool
	ForceUpper   int
	UseNumeric   bool
	ForceNumeric int
	UseSpecial   bool
	ForceSpecial int
}

const (
	version = "1.0.0"
	//Define character sets
	lcs = "abcdefghijklmnopqrstuvwxyz"
	ucs = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	num = "0123456789"
	spc = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
)

var (
	//Profile - defines the password Profile
	Profile PasswordProfileStruct
)

//NewPasswordInstance - creates a new password generator instance
func NewPasswordInstance() *PasswordProfileStruct {
	npwd := new(PasswordProfileStruct)
	return npwd
}

//GenPassword - generates a password against the previously set Profile
func (pwdProfile *PasswordProfileStruct) GenPassword() (string, error) {
	var passwordChars []string
	var password string
	var allChars string

	if (pwdProfile.ForceLower + pwdProfile.ForceUpper + pwdProfile.ForceNumeric + pwdProfile.ForceSpecial) > pwdProfile.Length {
		return "", errors.New("Sum of forced Profile values is greater than total password Length requested")
	}

	//process lower chars
	if pwdProfile.UseLower {
		allChars += lcs
	}
	for i := 0; i < pwdProfile.ForceLower; i++ {
		character := getRune(lcs)
		passwordChars = append(passwordChars, character)
	}

	//process upper chars
	if pwdProfile.UseUpper {
		allChars += ucs
	}
	for i := 0; i < pwdProfile.ForceUpper; i++ {
		character := getRune(ucs)
		passwordChars = append(passwordChars, character)
	}

	//process number chars
	if pwdProfile.UseNumeric {
		allChars += num
	}
	for i := 0; i < pwdProfile.ForceNumeric; i++ {
		character := getRune(num)
		passwordChars = append(passwordChars, character)
	}

	//process special chars
	if pwdProfile.UseSpecial {
		allChars += spc
	}
	for i := 0; i < pwdProfile.ForceSpecial; i++ {
		character := getRune(spc)
		passwordChars = append(passwordChars, character)
	}

	//Generate rest of password
	if len(passwordChars) < pwdProfile.Length {
		if allChars == "" {
			allChars = lcs + ucs + num + spc
		}
		moreCharsLen := pwdProfile.Length - len(passwordChars)
		for i := 0; i < moreCharsLen; i++ {
			character := getRune(allChars)
			passwordChars = append(passwordChars, character)
		}
	}

	//Shuffle slice, build password string
	var src cryptoSource
	rnd := rand.New(src)
	for _, i := range rnd.Perm(len(passwordChars)) {
		password += passwordChars[i]
	}

	return password, nil
}

//crypto seed generation
func (s cryptoSource) Seed(seed int64) {}

func (s cryptoSource) Int63() int64 {
	return int64(s.Uint64() & ^uint64(1<<63))
}

func (s cryptoSource) Uint64() (v uint64) {
	err := binary.Read(crand.Reader, binary.BigEndian, &v)
	if err != nil {
		panic(err)
	}
	return v
}

//getRune - selects random rune from given source string
func getRune(sourceChars string) string {
	var src cryptoSource
	rnd := rand.New(src)
	charPosition := rnd.Intn(utf8.RuneCountInString(sourceChars))
	runesArray := []rune(sourceChars)
	return string(runesArray[charPosition])
}
