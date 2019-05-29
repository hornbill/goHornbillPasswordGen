# Hornbill Password Generator

A Go module to generate cryptographically-secure strings.

Uses crypto/rand to generate a source seed for the (much more user friendly) math.rand, so passwords are secure and can't be time-hacked.

## NewPasswordInstance()

Creates a new Password Profile instance. The following optional variables can be set once the instance has been created:

* Length			int
* UseLower			bool
* ForceLower		int
* UseUpper			bool
* ForceUpper		int
* UseNumeric		bool
* ForceNumeric		int
* UseSpecial		bool
* ForceSpecial		int
* Blacklist			[]string
* MustNotContain	[]string

## GenPassword()

Generates password as per Profile.

## Usage Example

```
package main

import (
	"fmt"

	"github.com/hornbill/goHornbillPasswordGen"
)

func main() {
	//Create new Password Generator instance
	pwdinst := hornbillPasswordGen.NewPasswordInstance()

	//Define the password profile
	pwdinst.Length = 10                                             //Password Length
	pwdinst.UseLower = true                                         //Use lower case a-z characters in the password
	pwdinst.ForceLower = 2                                          //Minimum number of lower case characters to use in the password
	pwdinst.UseNumeric = true                                       //Use numeric 0-9 characters in the password
	pwdinst.ForceNumeric = 2                                        //Minumum number of numeric characters to use in the password
	pwdinst.UseUpper = true                                         //Use upper case A-Z characters in the password
	pwdinst.ForceUpper = 2                                          //Minimum number of upper case characters to use in the password
	pwdinst.UseSpecial = false                                      //Use special characters in the password: !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~
	pwdinst.ForceSpecial = 0                                        //Minimum number of special characters to use in the password
	pwdinst.Blacklist = append(pwdinst.Blacklist, "password")       //Disallowed passwords - case insensitive
	pwdinst.Blacklist = append(pwdinst.Blacklist, "12345678")       //Disallowed passwords - case insensitive
	pwdinst.MustNotContain = append(pwdinst.MustNotContain, "your") //Strings that the new password must not contain - case insensitive - mandatory string length >= 3 characters
	pwdinst.MustNotContain = append(pwdinst.MustNotContain, "name") //Strings that the new password must not contain - case insensitive - mandatory string length >= 3 characters

	//Generate a new password
	newPassword, err := pwdinst.GenPassword()
	if err != nil {
		fmt.Println(fmt.Sprintf("%v", err))
		return
	}
	fmt.Println("New Password:", newPassword)
}
```

## Notes

* If no UseXXX bools are set, all character sets (lower case, upper case, numeric and special) will be used. ForceXXX values will still be enforced.
* If sum of ForceXXX values are greater than Length value, an error will be returned.
* If sum of ForceXXX values are less than Length Value, the additional characters are randomly generated from all character sets specified in the UseXXX bools.
* If no ForceXXX values are > 0, then all characters are randomly generated from all character sets specified in the UseXXX bools.
* If UseXXX bool is set to true, and corresponding ForceXXX value is > 0, then ONLY the ForceXXX number of characters from the relevant set will be used - no more of that type of character will be used to build the rest of the string (if applicable)  