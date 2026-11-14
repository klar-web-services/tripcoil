package redact

import (
	"slices"
	"strings"
	"testing"
)

func TestCmdline(t *testing.T) {
	cases := []struct{ in, want []string }{
		{[]string{"app", "--password=hunter2"}, []string{"app", "--password=<redacted>"}},
		{[]string{"app", "--password", "hunter2", "--port", "80"}, []string{"app", "--password", "<redacted>", "--port", "80"}},
		{[]string{"app", "--API-KEY=abc"}, []string{"app", "--API-KEY=<redacted>"}},
		{[]string{"app", "--key", "/etc/ssl/k.pem"}, []string{"app", "--key", "<redacted>"}},
		{[]string{"app", "--keyfile", "/etc/ssl/k.pem"}, []string{"app", "--keyfile", "/etc/ssl/k.pem"}},
		{[]string{"app", "--db-password=s3cret"}, []string{"app", "--db-password=<redacted>"}},
		{[]string{"env", "PGPASSWORD=s3cret", "AWS_SECRET_ACCESS_KEY=x", "api_key=y"}, []string{"env", "PGPASSWORD=<redacted>", "AWS_SECRET_ACCESS_KEY=<redacted>", "api_key=<redacted>"}},
		{[]string{"app", "postgres://shop:s3cret@db:5432/shop"}, []string{"app", "postgres://shop:<redacted>@db:5432/shop"}},
		{[]string{"app", "--url=https://x.example/hook?token=abc&x=1"}, []string{"app", "--url=https://x.example/hook?token=<redacted>"}},
		{[]string{"postgres: shop password=s3cret idle"}, []string{"postgres: shop password=<redacted> idle"}},
		{[]string{"nginx: master process /usr/sbin/nginx"}, []string{"nginx: master process /usr/sbin/nginx"}},
		{nil, []string{}},
	}
	for _, tc := range cases {
		got := Cmdline(tc.in)
		if !slices.Equal(got, tc.want) {
			t.Errorf("Cmdline(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCmdlineDoesNotChangeInput(t *testing.T) {
	in := []string{"app", "--password=hunter2"}
	_ = Cmdline(in)
	if in[1] != "--password=hunter2" {
		t.Fatal("input modified")
	}
	if strings.Contains(strings.Join(Cmdline([]string{"x", "--token", "hunter2"}), " "), "hunter2") {
		t.Fatal("secret leaked")
	}
}
