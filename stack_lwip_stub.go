//go:build !with_lwip

package tun

import E "github.com/sagernet/sing/common/exceptions"

const WithLWIP = false

func NewLWIP(options StackOptions) (Stack, error) {
	return nil, E.New("lwIP is not included in this build, rebuild with -tags with_lwip")
}
