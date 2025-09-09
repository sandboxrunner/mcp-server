package runtime

import (
	"context"

	"github.com/beam-cloud/go-runc"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// RuncInterface defines the interface for runc operations we need
type RuncInterface interface {
	State(ctx context.Context, id string) (*runc.Container, error)
	Exec(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error
	Create(ctx context.Context, id, bundle string, opts *runc.CreateOpts) error
	Start(ctx context.Context, id string) error
	Kill(ctx context.Context, id string, sig int, opts *runc.KillOpts) error
	Delete(ctx context.Context, id string, opts *runc.DeleteOpts) error
	List(ctx context.Context) ([]*runc.Container, error)
}