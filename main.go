package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

type lywtf struct {
	ForbiddenUserAgents  []string
	ForbiddenResponse    string
	ForbiddenNetworks    []netip.Prefix
	ForbiddenHeaders     map[string]string
	RedirectURL          string
	RedirectHTTPResponse int
}

func (l *lywtf) isBlockedRequest(c *gin.Context) bool {
	for _, fUA := range l.ForbiddenUserAgents {
		if strings.Contains(c.Request.UserAgent(), fUA) {
			return true
		}
	}

	if l.ForbiddenNetworks != nil {
		clientIP, err := netip.ParseAddr(c.ClientIP())
		if err != nil {
			log.Printf("can't parse %s as IP: %v", c.ClientIP(), err)
		} else {
			for _, fNe := range l.ForbiddenNetworks {
				if fNe.Contains(clientIP) {
					return true
				}
			}
		}
	}

	return false
}

func (l *lywtf) getRoot(c *gin.Context) {
	if l.isBlockedRequest(c) {
		for header := range l.ForbiddenHeaders {
			c.Header(header, l.ForbiddenHeaders[header])
		}
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, l.ForbiddenResponse)
		return
	}

	c.Redirect(l.RedirectHTTPResponse, l.RedirectURL)
}

func main() {
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatal("lyftw requires a non-empty config.json")
	}

	config := lywtf{}
	err = json.Unmarshal(configFile, &config)
	if err != nil {
		log.Fatalf("can't parse config file: %v", err)
	}

	log.Printf("Parsed config: %+v", config)

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.SetTrustedProxies([]string{"127.0.0.1", "::1"})
	r.GET("/", config.getRoot)
	r.Run()
}
