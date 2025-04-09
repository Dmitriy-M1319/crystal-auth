package opentelemetry

import (
	"context"

	"go.opentelemetry.io/otel/metric"
)

type ApiMetricsProvider struct {
	registerCounter  metric.Int64Counter
	loginCounter     metric.Int64Counter
	authorizeCounter metric.Int64Counter
	logoutCounter    metric.Int64Counter
}

func NewApiMetricsProvider(meter metric.Meter) (*ApiMetricsProvider, error) {
	rCounter, err := meter.Int64Counter("registerCounter", metric.WithDescription("A count of Register Queries"))
	if err != nil {
		return nil, err
	}
	loginCounter, err := meter.Int64Counter("loginCounter", metric.WithDescription("A count of Login Queries"))
	if err != nil {
		return nil, err
	}
	aCounter, err := meter.Int64Counter("authorizeCounter", metric.WithDescription("A count of Authorize Queries"))
	if err != nil {
		return nil, err
	}
	logoutCounter, err := meter.Int64Counter("logoutCounter", metric.WithDescription("A count of Logout Queries"))
	if err != nil {
		return nil, err
	}
	return &ApiMetricsProvider{
		registerCounter:  rCounter,
		loginCounter:     loginCounter,
		authorizeCounter: aCounter,
		logoutCounter:    logoutCounter,
	}, nil
}

func (prov *ApiMetricsProvider) AddRegister(ctx context.Context, count int64) {
	prov.registerCounter.Add(ctx, count)
}
func (prov *ApiMetricsProvider) AddLogin(ctx context.Context, count int64) {
	prov.loginCounter.Add(ctx, count)
}
func (prov *ApiMetricsProvider) AddAuthorize(ctx context.Context, count int64) {
	prov.authorizeCounter.Add(ctx, count)
}
func (prov *ApiMetricsProvider) AddLogout(ctx context.Context, count int64) {
	prov.logoutCounter.Add(ctx, count)
}
