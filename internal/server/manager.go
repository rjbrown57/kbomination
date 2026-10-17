package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rjbrown57/kbomination/internal/collect"
	"github.com/rjbrown57/kbomination/internal/model"
	"github.com/rjbrown57/kbomination/internal/store"
	"go.uber.org/zap"
)

var ErrOverlap = errors.New("this profile already has an active collection")
var ErrMaintenance = errors.New("collection maintenance is in progress")

type scheduled struct {
	fingerprint string
	next        time.Time
}
type Manager struct {
	Store       *store.Store
	Collector   collect.Collector
	Discover    func(model.Profile) ([]model.Cluster, error)
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	active      map[string]bool
	maintenance bool
	next        map[string]scheduled
	workers     chan struct{}
	wg          sync.WaitGroup
	scheduler   sync.WaitGroup
}

func NewManager(s *store.Store) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{Store: s, Collector: collect.Trivy{}, Discover: collect.Contexts, ctx: ctx, cancel: cancel, active: map[string]bool{}, next: map[string]scheduled{}, workers: make(chan struct{}, 2)}
}
func (m *Manager) Recover(ctx context.Context) error {
	if err := m.Store.Exec(ctx, "UPDATE run_results SET status='interrupted',error='Server stopped before collection completed' WHERE status IN ('queued','running')"); err != nil {
		return err
	}
	return m.Store.Exec(ctx, "UPDATE runs SET status='interrupted',finished_at=current_timestamp WHERE status='running'")
}
func (m *Manager) Close()          { m.cancel(); m.scheduler.Wait(); m.wg.Wait() }
func (m *Manager) HasActive() bool { m.mu.Lock(); defer m.mu.Unlock(); return len(m.active) > 0 }
func (m *Manager) Restore(ctx context.Context, r io.Reader) (map[string]int, error) {
	m.mu.Lock()
	if len(m.active) > 0 {
		m.mu.Unlock()
		return nil, ErrOverlap
	}
	if m.maintenance {
		m.mu.Unlock()
		return nil, ErrMaintenance
	}
	m.maintenance = true
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.maintenance = false; m.mu.Unlock() }()
	return m.Store.Restore(ctx, r)
}
func (m *Manager) Schedule() {
	m.scheduler.Add(1)
	go func() {
		defer m.scheduler.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-m.ctx.Done():
				return
			case now := <-ticker.C:
				if err := m.Tick(now.UTC()); err != nil {
					zap.L().Error("scheduler", zap.Error(err))
				}
			}
		}
	}()
}

func (m *Manager) Tick(now time.Time) error {
	settings, err := m.Store.Settings(m.ctx)
	if err != nil {
		return err
	}
	if settings["scheduler_paused"] == "true" {
		return nil
	}
	profiles, err := m.Store.Profiles(m.ctx)
	if err != nil {
		return err
	}
	for _, p := range profiles {
		if !p.Enabled {
			delete(m.next, p.ID)
			continue
		}
		b, _ := json.Marshal(p)
		fingerprint := string(b)
		schedule, err := model.ParseSchedule(p.Cron)
		if err != nil {
			return err
		}
		n, ok := m.next[p.ID]
		if !ok || n.fingerprint != fingerprint {
			m.next[p.ID] = scheduled{fingerprint, schedule.Next(now)}
			continue
		}
		if !now.Before(n.next) {
			m.next[p.ID] = scheduled{fingerprint, schedule.Next(now)}
			if _, err = m.Start(p); err != nil && !errors.Is(err, ErrOverlap) {
				zap.L().Error("scheduled collection failed", zap.String("profile", p.ID), zap.Error(err))
			}
		}
	}
	return nil
}

func (m *Manager) Start(p model.Profile) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	if p.ID == "" {
		p.ID = model.Key(p.Kubeconfig, p.ContextRegex, model.Scope(p.Namespaces))
	}
	m.mu.Lock()
	if m.ctx.Err() != nil {
		m.mu.Unlock()
		return "", fmt.Errorf("server is stopping")
	}
	if m.maintenance {
		m.mu.Unlock()
		return "", ErrMaintenance
	}
	if m.active[p.ID] {
		m.mu.Unlock()
		return "", ErrOverlap
	}
	m.active[p.ID] = true
	m.wg.Add(1)
	m.mu.Unlock()
	release := func() { m.mu.Lock(); delete(m.active, p.ID); m.mu.Unlock(); m.wg.Done() }
	clusters, err := m.Discover(p)
	if err != nil {
		release()
		return "", err
	}
	id := uuid.NewString()
	if err = m.Store.Exec(m.ctx, "INSERT INTO runs(id,profile_id,profile_name,started_at,status) VALUES (?,?,?,?,'running')", id, p.ID, p.Name, time.Now().UTC()); err != nil {
		release()
		return "", err
	}
	for _, c := range clusters {
		if err = m.Store.Exec(m.ctx, "INSERT INTO run_results(run_id,cluster_id,cluster_name,status) VALUES (?,?,?,'queued')", id, c.ID, c.Name); err != nil {
			_ = m.Store.Exec(context.Background(), "UPDATE runs SET status='failed',finished_at=current_timestamp WHERE id=?", id)
			release()
			return "", err
		}
	}
	go func() { defer release(); m.run(id, p, clusters) }()
	return id, nil
}
func (m *Manager) run(id string, p model.Profile, clusters []model.Cluster) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	failures := 0
	for _, c := range clusters {
		wg.Add(1)
		go func(c model.Cluster) {
			defer wg.Done()
			var err error
			var snapshot string
			select {
			case m.workers <- struct{}{}:
				defer func() { <-m.workers }()
			case <-m.ctx.Done():
				err = m.ctx.Err()
			}
			if err == nil {
				err = m.Store.Exec(m.ctx, "UPDATE run_results SET status='running' WHERE run_id=? AND cluster_id=?", id, c.ID)
			}
			if err == nil {
				var a model.Artifact
				a, err = m.Collector.Collect(m.ctx, p, c)
				if err == nil {
					snapshot, err = m.Store.Import(m.ctx, a)
				}
			}
			status := "succeeded"
			message := ""
			if err != nil {
				status = "failed"
				message = err.Error()
				mu.Lock()
				failures++
				mu.Unlock()
			}
			if e := m.Store.Exec(context.Background(), "UPDATE run_results SET status=?,error=?,snapshot_id=? WHERE run_id=? AND cluster_id=?", status, message, snapshot, id, c.ID); e != nil {
				zap.L().Error("persist collection result", zap.Error(e))
			}
		}(c)
	}
	wg.Wait()
	status := "succeeded"
	if failures == len(clusters) {
		status = "failed"
	} else if failures > 0 {
		status = "partial"
	}
	if m.ctx.Err() != nil {
		status = "interrupted"
	}
	if err := m.Store.Exec(context.Background(), "UPDATE runs SET status=?,finished_at=current_timestamp WHERE id=?", status, id); err != nil {
		zap.L().Error("finish run", zap.Error(err))
	}
}
