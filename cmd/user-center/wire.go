//go:build wireinject

package main

import (
	"github.com/google/wire"

	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/internal/wiring"
)

func wireApp(b *conf.Bootstrap) (*wiring.App, func(), error) {
	panic(wire.Build(wiring.ProviderSet))
}
