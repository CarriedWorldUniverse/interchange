// Package edge provides utilities for interchange's gRPC edge routing:
// identity metadata injection into outgoing gRPC contexts, client metadata
// stripping (anti-spoof), product entitlement checks, and mTLS dialing.
package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// Identity is the verified caller (mirrors gateway.Identity incl. Products).
type Identity struct {
	Subject, Kind, Org, ResponsibleHuman string
	Scopes, Products                     []string
}

var cwbMetaKeys = []string{
	"cwb-org",
	"cwb-subject",
	"cwb-kind",
	"cwb-scopes",
	"cwb-products",
	"cwb-responsible-human",
}

// StripClientMetadata removes any client-supplied cwb-* keys from md (anti-spoof).
func StripClientMetadata(md metadata.MD) {
	for _, k := range cwbMetaKeys {
		md.Delete(k)
	}
}

// OutgoingContext returns ctx carrying the verified identity as cwb-* outgoing metadata.
func OutgoingContext(ctx context.Context, id Identity) context.Context {
	md := metadata.MD{}
	md.Set("cwb-org", id.Org)
	md.Set("cwb-subject", id.Subject)
	md.Set("cwb-kind", id.Kind)
	md.Set("cwb-scopes", strings.Join(id.Scopes, " "))
	md.Set("cwb-products", strings.Join(id.Products, " "))
	if id.ResponsibleHuman != "" {
		md.Set("cwb-responsible-human", id.ResponsibleHuman)
	}
	return metadata.NewOutgoingContext(ctx, md)
}

// HasProduct reports whether id has product entitlement for the named product (NEX-427).
func HasProduct(id Identity, product string) bool {
	for _, p := range id.Products {
		if p == product {
			return true
		}
	}
	return false
}

// DialPillar dials a pillar over mTLS using interchange's client cert + CA.
func DialPillar(addr, certFile, keyFile, caFile string) (*grpc.ClientConn, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	})
	return grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
}
