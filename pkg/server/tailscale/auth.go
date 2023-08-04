package tailscale

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
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
	log.Debug().Str("src", src).Str("dst", dst).Msg("Checking if authorized")
	if !isInTailscaleNet(src) {
		log.Debug().Str("src", src).Str("dst", dst).Msg("Src not in tailscale net")
		return false, nil
	}

	if !isInTailscaleNet(dst) {
		log.Debug().Str("src", src).Str("dst", dst).Msg("Dst not in tailscale net")
		return true, nil
	}

	access, fresh, _ := am.cache.Get(createKey(src, dst, dstPort))
	log.Debug().Str("fresh", strconv.FormatBool(fresh)).Msg("Cache retrieved")
	if fresh {
		return access, nil
	}

	authorized, err := isAuthorized(am.tailnet, am.token, src, dst, dstPort)
	log.Debug().Str("authorized", strconv.FormatBool(authorized)).Msg("Checking if authorized using api")
	if err != nil {
		log.Error().Err(err).Msg("Could not check if authorized")
		return false, err
	}

	am.cache.Set(createKey(src, dst, dstPort), authorized, am.ttl)
	log.Debug().Str("authorized", strconv.FormatBool(authorized)).Msg("Cache set")
	return authorized, nil
}

var tailscaleNet = net.IPNet{
	IP:   net.IPv4(10, 0, 0, 0),
	Mask: net.IPv4Mask(255, 0, 0, 0),
}

func isInTailscaleNet(ipstr string) bool {

	ip := net.ParseIP(ipstr)
	if ip == nil {
		log.Warn().Str("ip", ipstr).Msg("Could not parse ip")
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
