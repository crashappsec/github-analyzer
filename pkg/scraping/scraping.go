// Copyright 2022 Crash Override
// Copyright 2013 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// package scraping is a modified version over go-github's scrape package
// using rsc.io/2fa instead of gotp
package scraping

import (
	"fmt"

	"bytes"
	"encoding/gob"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"github.com/crashappsec/github-security-auditor/pkg/issue"
	"github.com/crashappsec/github-security-auditor/pkg/log"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/publicsuffix"
)

var defaultBaseURL = "https://github.com/"

// Client is a GitHub scraping client.
type Client struct {
	*http.Client

	// base URL for github.com pages.  Exposed primarily for testing.  Also
	// used for saving and restoring cookies on the Client.
	baseURL *url.URL
}

func NewClient(transport http.RoundTripper) *Client {
	jar, err := cookiejar.New(
		&cookiejar.Options{PublicSuffixList: publicsuffix.List},
	)
	if err != nil {
		log.Logger.Fatalf("error creating cookiejar: %v", err)
	}
	baseURL, _ := url.Parse(defaultBaseURL)

	return &Client{
		Client: &http.Client{
			Transport: transport,
			Jar:       jar,
		},
		baseURL: baseURL,
	}
}

func (c *Client) SaveCookies() ([]byte, error) {
	cookies := c.Client.Jar.Cookies(c.baseURL)

	var b bytes.Buffer
	err := gob.NewEncoder(&b).Encode(cookies)
	return b.Bytes(), err
}

// LoadCookies loads the provided cookies for github.com.
func (c *Client) LoadCookies(v []byte) error {
	var cookies []*http.Cookie
	r := bytes.NewReader(v)
	err := gob.NewDecoder(r).Decode(&cookies)
	if err != nil {
		return err
	}

	c.Client.Jar.SetCookies(c.baseURL, cookies)
	return nil
}

// get fetches a urlStr (a GitHub URL relative to the client's baseURL), and
// returns the parsed response document.
func (c *Client) get(
	urlStr string,
	a ...interface{},
) (*goquery.Document, error) {
	u, err := c.baseURL.Parse(fmt.Sprintf(urlStr, a...))
	if err != nil {
		return nil, fmt.Errorf("error parsing URL: %q: %v", urlStr, err)
	}
	resp, err := c.Client.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("error fetching url %q: %v", u, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf(
			"received %v response fetching URL %q",
			resp.StatusCode,
			u,
		)
	}

	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %v", err)
	}

	return doc, nil
}

func (c *Client) Authenticate(username, password, otpcode string) error {
	setPassword := func(values url.Values) {
		values.Set("login", username)
		values.Set("password", password)
	}
	resp, err := fetchAndSubmitForm(
		c.Client,
		"https://github.com/login",
		setPassword,
	)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"received %v response submitting login form",
			resp.StatusCode,
		)
	}

	if otpcode == "" {
		return nil
	}

	setOTP := func(values url.Values) {
		values.Set("otp", otpcode)
	}
	resp, err = fetchAndSubmitForm(
		c.Client,
		"https://github.com/sessions/two-factor",
		setOTP,
	)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"received %v response submitting otp form",
			resp.StatusCode,
		)
	}

	return nil
}

func AuditScraping(
	username, password, otpseed, org string,
) ([]issue.Issue, error) {
	var issues []issue.Issue

	client := NewClient(nil)
	if err := client.Authenticate(username, password, otpseed); err != nil {
		log.Logger.Error(err)
		return issues, nil
	}

	restrictedAccess, err := client.AppRestrictionsEnabled(org)
	if err != nil {
		log.Logger.Error(err)
	}
	if !restrictedAccess && err == nil {
		issues = append(issues, issue.ApplicationRestrictionsDisabled(org))
	}

	apps, err := client.ListOAuthApps(org)
	if err != nil {
		log.Logger.Error(err)
	}
	appinfo := make([]string, len(apps))
	for _, app := range apps {
		appinfo = append(appinfo, fmt.Sprintf("%+v", app))
	}
	issues = append(issues, issue.OAuthStats(org, appinfo))
	return issues, nil
}
