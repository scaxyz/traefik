package tailscale

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

const apiEndPoint = "https://api.tailscale.com/api/v2/tailnet"

var _ Authorizer = (*authorizer)(nil)

type authorizer struct {
	tailnet string
	token   string
	cache   *TimedAuthCache
	ttl     time.Duration
}

type Authorizer interface {
	IsAuthorized(src string, dst string, dstPort string) (bool, error)
}

func NewAuthorizer(tailnet string, token string, ttl time.Duration) *authorizer {
	return &authorizer{
		tailnet: tailnet,
		token:   token,
		cache:   NewTimedAuthCache(),
		ttl:     ttl,
	}
}

func createKey(src string, dst string, dstPort string) string {
	return fmt.Sprint(src, "->", dst, ":", dstPort)
}

func (am *authorizer) IsAuthorized(src string, dst string, dstPort string) (bool, error) {

	if !isInTailscaleNet(src) {
		return false, nil
	}

	if !isInTailscaleNet(dst) {
		return true, nil
	}

	access, fresh, _ := am.cache.Get(createKey(src, dst, dstPort))

	if fresh {
		return access, nil
	}

	authorized, err := isAuthorized(am.tailnet, am.token, src, dst, dstPort)

	if err != nil {
		return false, err
	}

	am.cache.Set(createKey(src, dst, dstPort), authorized, am.ttl)
	return authorized, nil
}

var tailscaleNet = net.IPNet{
	IP:   net.IPv4(10, 0, 0, 0),
	Mask: net.IPv4Mask(255, 0, 0, 0),
}

func isInTailscaleNet(ipstr string) bool {

	ip := net.ParseIP(ipstr)
	if ip == nil {
		return false
	}

	return tailscaleNet.Contains(ip)

}

func isAuthorized(tailnet string, token string, src string, dst string, dstPort string) (bool, error) {

	if tailnet == "" {
		tailnet = "-"
	}

	url := fmt.Sprintf("%s/%s/acl/validate", apiEndPoint, tailnet)
	body := bytes.NewBufferString(fmt.Sprintf(`[{"src": "%s", "accept": ["%s:%s"], "deny": []}]`, src, dst, dstPort))

	request, err := http.NewRequest("POST", url, body)
	if err != nil {
		return false, err
	}

	bearerToken := base64.StdEncoding.EncodeToString([]byte(token + ":"))

	request.Header.Set("Authorization", fmt.Sprintf("Basic %s", bearerToken))
	request.Header.Set("accept", "application/json")
	request.Header.Set("content-type", "application/json")
	request.Header.Set("content-length", strconv.Itoa(body.Len()))

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return false, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("tailscale returned unexpected status code: %d", resp.StatusCode)
	}

	// respBody, err := ioutil.ReadAll(resp.Body)

	return resp.ContentLength == 0, nil
}
