// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azcosmos

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteAttemptTimeoutPublicClientTLS(t *testing.T) {
	var requests, transportCalls atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/" {
			fmt.Fprintf(w, `{"writableLocations":[{"name":"East US","databaseAccountEndpoint":%q}],"readableLocations":[{"name":"East US","databaseAccountEndpoint":%q}]}`, server.URL+"/", server.URL+"/")
			return
		}
		requests.Add(1)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"item"}`)
	}))
	defer server.Close()
	transport := timeoutTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && transportCalls.Add(1) == 1 {
			<-r.Context().Done()
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: r.Context().Err()}
		}
		return server.Client().Do(r)
	})
	key, err := NewKeyCredential("dGVzdA==")
	require.NoError(t, err)
	client, err := NewClientWithKey(server.URL, key, &ClientOptions{ClientOptions: azcore.ClientOptions{
		Transport: transport,
		Retry: policy.RetryOptions{MaxRetries: 3, TryTimeout: 100 * time.Millisecond,
			RetryDelay: 1500 * time.Millisecond, MaxRetryDelay: 1500 * time.Millisecond},
	}})
	require.NoError(t, err)
	defer client.Close()
	c, err := client.NewContainer("db", "coll")
	require.NoError(t, err)
	require.NoError(t, timeoutTestCall(context.Background(), c, "create"))
	assert.Equal(t, int32(2), transportCalls.Load())
	assert.Equal(t, int32(1), requests.Load(), "only the recovery attempt reaches the server")
}

func TestWriteAttemptTimeoutRetainedEvidence(t *testing.T) {
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"dial-deadline", dial},
		{"dial-connect-timeout", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ETIMEDOUT}},
		{"dns-timeout", &net.DNSError{Err: "synthetic timeout", IsTimeout: true}},
		{"connection-refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}},
		{"wrapped-dial", &url.Error{Op: "POST", URL: "https://timeout.invalid", Err: fmt.Errorf("transport: %w", dial)}},
	} {
		for _, op := range []string{"create", "upsert", "patch"} {
			t.Run(tc.name+"/"+op, func(t *testing.T) {
				t.Parallel()
				sends := 0
				var first, second time.Time
				transport := timeoutTestTransport(func(r *http.Request) (*http.Response, error) {
					sends++
					if sends == 1 {
						first = time.Now()
						<-r.Context().Done()
						return nil, tc.err
					}
					second = time.Now()
					body, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					require.NotEmpty(t, body, "the outer retry must rewind the write body")
					return timeoutTestResponse(r, http.StatusOK), nil
				})
				c, attempts := timeoutTestContainer(t, transport, policy.RetryOptions{
					MaxRetries: 3, TryTimeout: 100 * time.Millisecond,
					RetryDelay: 1500 * time.Millisecond, MaxRetryDelay: 1500 * time.Millisecond,
				}, true)
				err := timeoutTestCall(context.Background(), c, op)
				require.NoError(t, err)
				assert.Equal(t, 2, sends)
				assert.Equal(t, 2, attempts.attempts)
				assert.GreaterOrEqual(t, second.Sub(first), time.Second)
			})
		}
	}
}

func TestWriteAttemptTimeoutMissingOrConflictingEvidence(t *testing.T) {
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
	veto := &timeoutTestVeto{context.DeadlineExceeded}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"bare-deadline", context.DeadlineExceeded},
		{"erased-dial", &url.Error{Op: "POST", URL: "https://timeout.invalid", Err: context.DeadlineExceeded}},
		{"read-deadline", &net.OpError{Op: "read", Err: context.DeadlineExceeded}},
		{"write-deadline", &net.OpError{Op: "write", Err: context.DeadlineExceeded}},
		{"read-socket-timeout", &net.OpError{Op: "read", Err: syscall.ETIMEDOUT}},
		{"write-socket-timeout", &net.OpError{Op: "write", Err: syscall.ETIMEDOUT}},
		{"unqualified-socket-timeout", syscall.ETIMEDOUT},
		{"eof", io.EOF},
		{"unexpected-eof", io.ErrUnexpectedEOF},
		{"reset", syscall.ECONNRESET},
		{"broken-pipe", syscall.EPIPE},
		{"unknown", errors.New("transport phase unavailable")},
		{"joined-dial-and-deadline", errors.Join(dial, context.DeadlineExceeded)},
		{"joined-dial-and-read", errors.Join(dial, &net.OpError{Op: "read", Err: context.DeadlineExceeded})},
		{"joined-dial-and-eof", errors.Join(dial, io.EOF)},
		{"joined-dns-and-reset", errors.Join(&net.DNSError{}, syscall.ECONNRESET)},
		{"nested-veto", &url.Error{Op: "POST", URL: "https://timeout.invalid", Err: errors.Join(dial, veto)}},
		{"dial-wrapped-veto", &net.OpError{Op: "dial", Err: veto}},
		{"dial-wrapped-read", &net.OpError{Op: "dial", Err: &net.OpError{Op: "read", Err: context.DeadlineExceeded}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sends := 0
			transport := timeoutTestTransport(func(r *http.Request) (*http.Response, error) {
				sends++
				<-r.Context().Done()
				return nil, tc.err
			})
			c, attempts := timeoutTestContainer(t, transport, policy.RetryOptions{
				MaxRetries: 3, TryTimeout: 30 * time.Millisecond,
				RetryDelay: time.Millisecond, ShouldRetry: func(*http.Response, error) bool { return true },
			}, true)
			err := timeoutTestCall(context.Background(), c, "create")
			require.ErrorIs(t, err, context.DeadlineExceeded)
			assert.ErrorIs(t, err, tc.err, "the original error must remain in the stopped chain")
			assert.Equal(t, 1, sends, "even a permissive outer predicate cannot replay an ambiguous write")
			assert.Equal(t, 1, attempts.attempts)
			var got *timeoutTestVeto
			if errors.As(tc.err, &got) {
				var retained *timeoutTestVeto
				require.ErrorAs(t, err, &retained)
				assert.Same(t, got, retained)
			}
		})
	}
}

func TestWriteAttemptTimeoutBudgetsAndCaller(t *testing.T) {
	for _, mode := range []string{
		"no-outer", "outer-veto", "disabled", "wait-only", "recover-backoff",
		"veto-backoff", "caller-before", "caller-transport", "caller-backoff",
		"caller-outer", "caller-cancel-transport", "caller-cancel-backoff",
		"caller-resumed-backoff", "caller-cancel-resumed-backoff",
	} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			sends := 0
			dial := &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
			veto := &timeoutTestVeto{dial}
			transport := timeoutTestTransport(func(r *http.Request) (*http.Response, error) {
				sends++
				if sends > 1 {
					return timeoutTestResponse(r, http.StatusOK), nil
				}
				switch mode {
				case "recover-backoff", "veto-backoff", "caller-backoff", "caller-cancel-backoff",
					"caller-resumed-backoff", "caller-cancel-resumed-backoff":
					if mode == "veto-backoff" {
						return nil, veto
					}
					return nil, dial
				default:
					<-r.Context().Done()
					return nil, dial
				}
			})
			opts := policy.RetryOptions{MaxRetries: 3, TryTimeout: 100 * time.Millisecond,
				RetryDelay: 1500 * time.Millisecond, MaxRetryDelay: 1500 * time.Millisecond}
			if mode == "no-outer" {
				opts.MaxRetries = -1
			}
			if mode == "outer-veto" {
				opts.ShouldRetry = func(*http.Response, error) bool { return false }
			}
			if mode == "wait-only" || mode == "caller-resumed-backoff" || mode == "caller-cancel-resumed-backoff" {
				opts.RetryDelay = time.Millisecond
				opts.MaxRetryDelay = time.Millisecond
			}
			ctx := context.Background()
			cancel := func() {}
			switch mode {
			case "caller-before":
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "caller-cancel-transport", "caller-cancel-backoff", "caller-cancel-resumed-backoff":
				ctx, cancel = context.WithCancel(ctx)
				delay := 50 * time.Millisecond
				if mode == "caller-cancel-resumed-backoff" {
					delay = 150 * time.Millisecond
				}
				timer := time.AfterFunc(delay, cancel)
				defer timer.Stop()
			case "caller-transport", "caller-backoff":
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
			case "caller-outer":
				ctx, cancel = context.WithTimeout(ctx, 150*time.Millisecond)
			case "caller-resumed-backoff":
				ctx, cancel = context.WithTimeout(ctx, 250*time.Millisecond)
			}
			defer cancel()
			c, attempts := timeoutTestContainer(t, transport, opts, mode != "disabled")
			err := timeoutTestCall(ctx, c, "create")
			switch mode {
			case "recover-backoff":
				require.NoError(t, err)
				assert.Equal(t, 2, sends)
				assert.Equal(t, 2, attempts.attempts)
			case "wait-only":
				require.ErrorIs(t, err, context.DeadlineExceeded)
				assert.ErrorIs(t, err, dial)
				assert.Equal(t, 1, sends)
				assert.Equal(t, 4, attempts.attempts, "attempts during the retained wait must not send")
			case "caller-resumed-backoff", "caller-cancel-resumed-backoff":
				require.ErrorIs(t, err, ctx.Err())
				assert.Equal(t, 1, sends)
				wantAttempts := 3
				if mode == "caller-cancel-resumed-backoff" {
					wantAttempts = 2
				}
				assert.Equal(t, wantAttempts, attempts.attempts)
			default:
				require.Error(t, err)
				assert.Equal(t, 1, sends)
				assert.Equal(t, 1, attempts.attempts)
				if ctx.Err() != nil {
					assert.ErrorIs(t, err, ctx.Err())
				}
				if mode == "veto-backoff" {
					var retained *timeoutTestVeto
					require.ErrorAs(t, err, &retained)
					assert.Same(t, veto, retained)
				}
			}
		})
	}
}

func TestWriteAttemptTimeoutRoutingAndExhaustion(t *testing.T) {
	for _, mode := range []string{"multi-recover", "multi-exhausted", "single-master", "discovery-disabled"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			a, err := url.Parse("https://region-a.invalid/")
			require.NoError(t, err)
			b, err := url.Parse("https://region-b.invalid/")
			require.NoError(t, err)
			lc := CreateMockLC(*a, mode != "single-master")
			lc.disableEndpointDiscovery = mode == "discovery-disabled"
			lc.locationInfo.prefLocations = []regionId{newRegionId("East US"), newRegionId("Central US")}
			lc.locationInfo.availWriteEndpointsByLocation[newRegionId("Central US")] = *b
			lc.locationInfo.writeEndpoints = []url.URL{*a, *b}
			lc.locationInfo.availReadEndpointsByLocation[newRegionId("Central US")] = *b
			lc.locationInfo.readEndpoints = []url.URL{*a, *b}
			gem := &globalEndpointManager{clientEndpoint: a.String(), locationCache: lc}
			hosts := []string{}
			var times []time.Time
			var states []retryContext
			dial := &net.OpError{Op: "dial", Err: context.DeadlineExceeded}
			transport := timeoutTestTransport(func(r *http.Request) (*http.Response, error) {
				hosts = append(hosts, r.URL.Host)
				times = append(times, time.Now())
				if mode == "multi-recover" && len(hosts) == 5 {
					return timeoutTestResponse(r, http.StatusOK), nil
				}
				<-r.Context().Done()
				return nil, dial
			})
			counter := &timeoutTestAttemptCounter{}
			internal, err := azcore.NewClient("azcosmostest", "v1.0.0", azruntime.PipelineOptions{
				PerCall: []policy.Policy{&retryCallerContextPolicy{}},
				PerRetry: []policy.Policy{counter, &clientRetryPolicy{gem: gem},
					timeoutTestRetryStates{states: &states}},
			}, &policy.ClientOptions{Transport: transport, Retry: policy.RetryOptions{
				MaxRetries: 10, TryTimeout: 100 * time.Millisecond,
				RetryDelay: 1500 * time.Millisecond, MaxRetryDelay: 1500 * time.Millisecond,
			}})
			require.NoError(t, err)
			client := &Client{endpoint: a.String(), endpointUrl: a, internal: internal, gem: gem}
			c, err := client.NewContainer("db", "coll")
			require.NoError(t, err)
			err = timeoutTestCall(context.Background(), c, "create")
			want := []string{a.Host, a.Host, a.Host, a.Host}
			if mode == "multi-recover" || mode == "multi-exhausted" {
				want = append(want, b.Host)
			}
			if mode == "multi-recover" {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				assert.ErrorIs(t, err, dial)
			}
			assert.Equal(t, want, hosts)
			assert.Equal(t, len(want), counter.attempts, "exhausted internal retries must not start a fresh outer loop")
			for i := 1; i < len(times); i++ {
				assert.GreaterOrEqual(t, times[i].Sub(times[i-1]), time.Second)
				if i < 4 {
					assert.Equal(t, i, states[i].sameRegionRetryCount)
				}
			}
			if len(states) == 5 {
				assert.True(t, states[4].crossRegionFailoverDone)
				assert.True(t, states[4].resolveFromHead)
			}
		})
	}
}

type timeoutTestRetryStates struct{ states *[]retryContext }

func (c timeoutTestRetryStates) Do(req *policy.Request) (*http.Response, error) {
	var state retryContext
	req.OperationValue(&state)
	*c.states = append(*c.states, state)
	return req.Next()
}

func TestWriteAttemptTimeoutEvidenceDoesNotChangeReadClassification(t *testing.T) {
	dial := &net.OpError{Op: "dial", Err: context.DeadlineExceeded}
	assert.True(t, hasNotSentWriteEvidence(dial, false))
	assert.Equal(t, connectionErrorAmbiguous, classifyNetworkError(dial),
		"the narrow write handoff must not change the existing read classifier")
	assert.False(t, hasNotSentWriteEvidence(errors.Join(dial, context.DeadlineExceeded), false))
	assert.False(t, hasNotSentWriteEvidence(nil, false))
}
