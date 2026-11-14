package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func tree(t *testing.T, files ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, f := range files {
		p := filepath.Join(root, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestIsInterpreter(t *testing.T) {
	for _, exe := range []string{"/usr/bin/node", "/usr/bin/python3.12", "/usr/lib/jvm/java-21/bin/java", "/usr/sbin/php-fpm8.2", "/usr/bin/ruby3.2", "/usr/local/bin/bun", "/usr/bin/deno"} {
		if !isInterpreter(exe) {
			t.Errorf("%s is an interpreter", exe)
		}
	}
	for _, exe := range []string{"/usr/sbin/nginx", "/usr/bin/nodemon", "/opt/api/api"} {
		if isInterpreter(exe) {
			t.Errorf("%s is not an interpreter", exe)
		}
	}
}

func TestFindAppDir(t *testing.T) {
	root := tree(t,
		"srv/shop/package.json", "srv/shop/server.js", "srv/shop/node_modules/next/package.json", "srv/shop/node_modules/next/dist/bin/next",
		"srv/api/.venv/pyvenv.cfg", "srv/api/.venv/bin/gunicorn", "srv/api/.venv/bin/python3", "srv/api/requirements.txt",
		"srv/app.jar",
		"usr/lib/node_modules/pm2/package.json", "usr/lib/node_modules/pm2/lib/ProcessContainerFork.js",
		"usr/lib/node_modules/node-red/package.json", "usr/lib/node_modules/node-red/red.js",
		"usr/share/nodejs/yarn/package.json", "usr/share/nodejs/yarn/bin/yarn.js",
		"srv/plain/main.py",
		"home/n8n/.nvm/package.json", "home/n8n/.nvm/versions/node/v20.11.0/bin/node",
		"home/n8n/.nvm/versions/node/v20.11.0/lib/node_modules/n8n/package.json", "home/n8n/.nvm/versions/node/v20.11.0/lib/node_modules/n8n/bin/n8n",
		"home/n8n/bot/index.js",
		"home/deploy/package.json", "home/deploy/.npm-global/lib/node_modules/node-red/package.json", "home/deploy/.npm-global/lib/node_modules/node-red/red.js",
		"home/deploy/.local/bin/gunicorn", "root/package.json", "root/.local/bin/celery", "srv/app/requirements.txt",
		"home/app/package.json", "home/app/src/server.js",
		"srv/mono/package.json",
	)
	const nvm = "/home/n8n/.nvm/versions/node/v20.11.0"
	for link, target := range map[string]string{
		"usr/bin/node-red":                     "../lib/node_modules/node-red/red.js",
		nvm[1:] + "/bin/n8n":                   "../lib/node_modules/n8n/bin/n8n",
		"home/deploy/.npm-global/bin/node-red": "../lib/node_modules/node-red/red.js",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, link)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	owned := func(_ context.Context, path string) bool { return path == "/usr/share/nodejs/yarn/package.json" }
	f := appDirFinder{root: root, owned: owned}
	cases := []struct {
		name    string
		cmdline []string
		cwd     string
		want    appDir
		found   bool
	}{
		{"script", []string{"node", "server.js"}, "/srv/shop", appDir{Path: "/srv/shop"}, true},
		{"flags before script", []string{"node", "--max-old-space-size=512", "-r", "dotenv/config", "/srv/shop/server.js"}, "/", appDir{Path: "/srv/shop"}, true},
		{"script inside node_modules", []string{"node", "/srv/shop/node_modules/next/dist/bin/next", "start"}, "/", appDir{Path: "/srv/shop"}, true},
		{"venv", []string{"/srv/api/.venv/bin/python3", "/srv/api/.venv/bin/gunicorn", "app:app"}, "/", appDir{Path: "/srv/api/.venv"}, true},
		{"venv python", []string{"/srv/api/.venv/bin/python3", "-m", "uvicorn", "main:app"}, "/", appDir{Path: "/srv/api/.venv"}, true},
		{"jar", []string{"java", "-Xmx1g", "-jar", "/srv/app.jar"}, "/", appDir{Path: "/srv/app.jar", Jar: true}, true},
		{"pm2 falls back to cwd", []string{"node", "/usr/lib/node_modules/pm2/lib/ProcessContainerFork.js"}, "/srv/shop", appDir{Path: "/srv/shop"}, true},
		{"global npm package through a symlink", []string{"node", "/usr/bin/node-red"}, "/", appDir{Path: "/usr/lib/node_modules/node-red"}, true},
		{"global package under nvm", []string{nvm + "/bin/node", nvm + "/bin/n8n"}, "/home/n8n", appDir{Path: nvm + "/lib/node_modules/n8n"}, true},
		{"global package in a home npm prefix", []string{"node", "/home/deploy/.npm-global/bin/node-red"}, "/home/deploy", appDir{Path: "/home/deploy/.npm-global/lib/node_modules/node-red"}, true},
		{"runtime's bin is not a start point", []string{nvm + "/bin/node", "/home/n8n/bot/index.js"}, "/home/n8n/bot", appDir{}, false},
		{"pip --user script does not reach the home directory", []string{"/usr/bin/python3", "/home/deploy/.local/bin/gunicorn", "app:app"}, "/srv/app", appDir{Path: "/srv/app"}, true},
		{"pip --user script does not reach /root", []string{"python3", "/root/.local/bin/celery", "-A", "proj", "worker"}, "/srv/app", appDir{Path: "/srv/app"}, true},
		{"app rooted in a home directory", []string{"node", "/home/app/src/server.js"}, "/", appDir{Path: "/home/app"}, true},
		{"distribution-packaged module is not an app", []string{"node", "/usr/share/nodejs/yarn/bin/yarn.js"}, "/srv/shop", appDir{Path: "/srv/shop"}, true},
		{"deleted cwd is not a start point", []string{"node", "server.js"}, "/srv/mono/apps/old (deleted)", appDir{}, false},
		{"python -m uses cwd", []string{"python3", "-m", "http.server"}, "/srv/shop", appDir{Path: "/srv/shop"}, true},
		{"no marker", []string{"python3", "main.py"}, "/srv/plain", appDir{}, false},
		{"root cwd", []string{"php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)"}, "/", appDir{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := f.find(context.Background(), tc.cmdline, tc.cwd)
			if got != tc.want || found != tc.found {
				t.Fatalf("got %+v %v, want %+v %v", got, found, tc.want, tc.found)
			}
		})
	}
}
