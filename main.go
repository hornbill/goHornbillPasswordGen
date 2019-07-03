package hornbillpasswordgen

//version "1.2.0"

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"math/rand"
	"strconv"
	"strings"
	"unicode/utf8"
)

type cryptoSource struct{}

//PasswordProfileStruct is the struct that contains the profile details used when generating a new Password
type PasswordProfileStruct struct {
	Length         int
	UseLower       bool
	ForceLower     int
	UseUpper       bool
	ForceUpper     int
	UseNumeric     bool
	ForceNumeric   int
	UseSpecial     bool
	ForceSpecial   int
	Blacklist      []string
	MustNotContain []string
}

const (
	//Define character sets
	lcs = "abcdefghijklmnopqrstuvwxyz"
	ucs = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	num = "0123456789"
	spc = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
)

var (
	//Profile - defines the password Profile
	Profile   PasswordProfileStruct
	debugMode bool
	debugging []string
)

//NewPasswordInstance - creates a new password generator instance
func NewPasswordInstance() *PasswordProfileStruct {
	npwd := new(PasswordProfileStruct)
	return npwd
}

//SetDebug - switches on debug mode, returning debugging information as an array of strings when calling GenPassword
func (pwdProfile *PasswordProfileStruct) SetDebug() {
	debugMode = true
	debugging = append(debugging, "Debugging Switched ON")
}

//GenPassword - generates and returns a password
func (pwdProfile *PasswordProfileStruct) GenPassword() (string, []string, error) {
	debug("GenPassword function call")
	newPass, err := newPassword(*pwdProfile)
	return newPass, debugging, err
}

//debug - append debugging array if debugMode switched on
func debug(outputString string) {
	if debugMode {
		debugging = append(debugging, outputString)
	}
}

//newPassword - generates a password against the previously set Profile
func newPassword(pwdProfile PasswordProfileStruct) (string, error) {
	debug("newPassword function call")
	var passwordChars []string
	var password string
	var allChars string

	if (pwdProfile.ForceLower + pwdProfile.ForceUpper + pwdProfile.ForceNumeric + pwdProfile.ForceSpecial) > pwdProfile.Length {
		return "", errors.New("sum of forced profile values is greater than total password length requested")
	}

	//process lower chars
	if pwdProfile.UseLower {
		debug("UseLower TRUE")
		allChars += lcs
	}
	for i := 0; i < pwdProfile.ForceLower; i++ {
		character := getRune(lcs)
		passwordChars = append(passwordChars, character)
	}

	//process upper chars
	if pwdProfile.UseUpper {
		debug("UseUpper TRUE")
		allChars += ucs
	}
	for i := 0; i < pwdProfile.ForceUpper; i++ {
		character := getRune(ucs)
		passwordChars = append(passwordChars, character)
	}

	//process number chars
	if pwdProfile.UseNumeric {
		debug("UseNumeric TRUE")
		allChars += num
	}
	for i := 0; i < pwdProfile.ForceNumeric; i++ {
		character := getRune(num)
		passwordChars = append(passwordChars, character)
	}

	//process special chars
	if pwdProfile.UseSpecial {
		debug("UseSpecial TRUE")
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

	debug("allChars: " + allChars)
	debug("passwordChars: " + strings.Join(passwordChars, ""))
	debug("password: " + password)

	//Check generated password isn't in blacklist
	if len(pwdProfile.Blacklist) > 0 {
		debug("Blacklist Length: " + strconv.Itoa(len(pwdProfile.Blacklist)))
		if isBlk := checkBlacklist(pwdProfile.Blacklist, password); isBlk {
			debug("[BLACKLIST] Generated password in blacklist: " + password)
			password, err := newPassword(pwdProfile)
			debug("[BLACKLIST] New Password: " + password)
			debug("[BLACKLIST] Error: " + err.Error())
			return password, err
		}
		debug("Password not found in Blacklist")
	}

	//Check generated password doesn't contain any of the strings provided in the MustNotContain array
	if len(pwdProfile.MustNotContain) > 0 {
		debug("MustNotContain Length: " + strconv.Itoa(len(pwdProfile.MustNotContain)))
		if containsStr := checkContain(pwdProfile.MustNotContain, password); containsStr {
			debug("[MUSTNOTCONTAIN] Generated password contains restricted string: " + password)
			password, err := newPassword(pwdProfile)
			debug("[MUSTNOTCONTAIN] New Password: " + password)
			debug("[MUSTNOTCONTAIN] Error: " + err.Error())
			return password, err
		}
		debug("Password does not contain restricted strings")
	}
	debug("Returning Password: " + password)
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

//checkBlacklist - checks string against set blacklist array
func checkBlacklist(blacklist []string, password string) bool {
	pwBlacklisted := false
	for _, v := range blacklist {
		if strings.EqualFold(password, v) {
			pwBlacklisted = true
			break
		}
	}
	return pwBlacklisted
}

//checkMustNotContain - checks string against restricted use strings - useful for checking personal information
func checkContain(blacklist []string, password string) bool {
	pwContainsRestricted := false
	for _, v := range blacklist {
		if len(v) > 2 && strings.Contains(strings.ToLower(password), strings.ToLower(v)) {
			pwContainsRestricted = true
			break
		}
	}
	return pwContainsRestricted
}
