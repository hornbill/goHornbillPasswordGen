package main

import (
	"fmt"

	hornbillpasswordgen "github.com/hornbill/goHornbillPasswordGen"
)

func main() {
	//Create new Password Generator instance
	pwdinst := hornbillpasswordgen.NewPasswordInstance()

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
