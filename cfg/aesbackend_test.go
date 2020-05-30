/*
 * knoxite
 *     Copyright (c) 2020, Nicolas Martin <penguwin@penguwin.eu>
 *
 *   For license see LICENSE
 */
package cfg

import (
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

const testPassword = "test"

func TestAESBackendLoad(t *testing.T) {
	cwd, _ := os.Getwd()

	// try to load the config from an absolute path using a URI
	u, _ := url.Parse("crypto://" + testPassword + "@" + filepath.Join(cwd, "testdata", "knoxite-crypto.conf"))
	backend, _ := NewAESBackend(u)
	conf, err := backend.Load(u)
	if err != nil {
		t.Errorf("Error loading config file fixture from absolute path %s. %v", u, err)
	}

	repo, ok := conf.Repositories["knoxitetest"]
	if !ok {
		t.Errorf("There should exist an repoconfig aliased with 'knoxitetest'")
	}
	if repo.Url != "/tmp/knoxitetest" {
		t.Errorf("Expected '/tmp/koxitetest as repo url, got: %s", repo.Url)
	}
	if repo.Compression != "gzip" {
		t.Errorf("Expected gzip as compression type, got: %s", repo.Compression)
	}
	if repo.Encryption != "aes" {
		t.Errorf("Expected aes as encryption type, got: %s", repo.Encryption)
	}
	if repo.Tolerance != 0 {
		t.Errorf("Expected repoTolerance of 0, got: %v", repo.Tolerance)
	}

	// try to load the config with a wrong password
	u, _ = url.Parse("crypto://wrongpasswd@" + filepath.Join(cwd, "testdata", "knoxite-crypto.conf"))
	backend, _ = NewAESBackend(u)
	_, err = backend.Load(u)
	if err == nil || err.Error() != "cipher: message authentication failed" {
		t.Errorf("loading the config file with an invalid password should fail. %v", err)
	}
}

func TestAESBackendSave(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "knoxitetest")
	if err != nil {
		t.Error("Could not create temp directory")
	}

	cwd, _ := os.Getwd()
	u, err := url.Parse(filepath.Join("crypto://"+testPassword+"@", cwd, "testdata", "knoxite-crypto.conf"))
	backend, _ := NewAESBackend(u)
	c, err := backend.Load(u)
	if err != nil {
		t.Errorf("Failed to load config fixture from relative path %s: %v", u, err)
	}

	// Save the config file to a new absolute path using a URL
	p := filepath.Join(tmpdir, "knoxite-crypto.conf")
	u, err = url.Parse("crypto://" + testPassword + "@" + p)
	c.SetURL(u.String())
	backend, _ = NewAESBackend(u)
	err = backend.Save(c)
	if err != nil {
		t.Errorf("failed to save the config to %s", u)
	}
	if !exist(p) {
		t.Errorf("configuration file wasn't saved to %s", p)
	}

	ok, err := IsEncrypted(u)
	if !ok {
		t.Errorf("encrypted config header not added. %v", err)
	}
}
