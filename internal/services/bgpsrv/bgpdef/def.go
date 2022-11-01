package bgpdef

import (
	"fmt"

	bgpapi "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/proto"
	apb "google.golang.org/protobuf/types/known/anypb"
)

var V4Family = &bgpapi.Family{
	Afi:  bgpapi.Family_AFI_IP,
	Safi: bgpapi.Family_SAFI_UNICAST,
}

var V6Family = &bgpapi.Family{
	Afi:  bgpapi.Family_AFI_IP6,
	Safi: bgpapi.Family_SAFI_UNICAST,
}

var CommunitiesAttribute = apbMustNew(&bgpapi.CommunitiesAttribute{
	Communities: []uint32{100, 200},
})

var OriginAttribute = apbMustNew(&bgpapi.OriginAttribute{
	Origin: 1, // eBGP
})

func apbMustNew(msg proto.Message) *apb.Any {
	out, err := apb.New(msg)
	if err != nil {
		panic(fmt.Sprintf("unable to create any msg: %s", err.Error()))
	}
	return out
}
