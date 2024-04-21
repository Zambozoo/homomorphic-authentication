package main

func main() {
	username := "Username"
	password := "Password"
	client := NewClient(8, 8080)
	_ = NewServer(8, 8080)

	if ok, err := client.SignUp(username, password); err != nil {
		panic(err)
	} else if !ok {
		panic("failed to sign up")
	}

	if ok, err := client.LogIn(username, password); err != nil {
		panic(err)
	} else if !ok {
		panic("failed to login")
	}
}
