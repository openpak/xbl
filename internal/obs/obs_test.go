package obs

import (
	"strings"
	"testing"
)

func TestRedactForm(t *testing.T) {
	out := Redact([]byte("client_id=000000004426B87D&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=abcdefghijklmnopqrstuvwxyz0123456789ABCD"))
	if strings.Contains(out, "abcdefghij") || !strings.Contains(out, "client_id=000000004426B87D") {
		t.Fatal(out)
	}
	out = Redact([]byte("code=GJ45S8Z2&email=a%40b.c&password=hunter2"))
	if strings.Contains(out, "hunter2") || strings.Contains(out, "GJ45S8Z2") {
		t.Fatal(out)
	}
	out = Redact([]byte(`{"access_token":"x","user_id":"0009abcd"}`))
	if strings.Contains(out, `"x"`) {
		t.Fatal(out)
	}
}
