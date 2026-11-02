// Package httpx carries verified transport metadata across the HTTP/server and
// service boundaries without coupling either layer to the other.
package httpx

import "context"

type Info struct {
	RequestID string
	IP        string
	UserAgent string
	CSRF      string
	Origin    string
}

type key struct{}

func With(ctx context.Context, info Info) context.Context {
	return context.WithValue(ctx, key{}, info)
}

func From(ctx context.Context) Info {
	v, _ := ctx.Value(key{}).(Info)
	return v
}
