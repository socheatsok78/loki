package dockerswarm

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	docker_types "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
	"go.uber.org/atomic"

	"github.com/grafana/loki/clients/pkg/promtail/api"
	"github.com/grafana/loki/clients/pkg/promtail/positions"
	"github.com/grafana/loki/clients/pkg/promtail/targets/target"

	"github.com/grafana/loki/pkg/logproto"
)

type Target struct {
	logger        log.Logger
	handler       api.EntryHandler
	since         int64
	positions     positions.Positions
	taskID        string
	labels        model.LabelSet
	relabelConfig []*relabel.Config
	metrics       *Metrics

	cancel  context.CancelFunc
	client  client.APIClient
	wg      sync.WaitGroup
	running *atomic.Bool
	err     error
}

func NewTarget(
	metrics *Metrics,
	logger log.Logger,
	handler api.EntryHandler,
	position positions.Positions,
	taskID string,
	labels model.LabelSet,
	relabelConfig []*relabel.Config,
	client client.APIClient,
) (*Target, error) {

	pos, err := position.Get(positions.CursorKey(taskID))
	if err != nil {
		return nil, err
	}
	var since int64
	if pos != 0 {
		since = pos
	}

	t := &Target{
		logger:        logger,
		handler:       handler,
		since:         since,
		positions:     position,
		taskID:        taskID,
		labels:        labels,
		relabelConfig: relabelConfig,
		metrics:       metrics,

		client:  client,
		running: atomic.NewBool(false),
	}
	t.startIfNotRunning()
	return t, nil
}

func (t *Target) processLoop(ctx context.Context) {
	t.running.Store(true)
	defer t.running.Store(false)

	t.wg.Add(1)
	defer t.wg.Done()

	opts := docker_types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Timestamps: true,
		Since:      strconv.FormatInt(t.since, 10),
	}
	taskInspect, _, err := t.client.TaskInspectWithRaw(ctx, t.taskID)
	if err != nil {
		level.Error(t.logger).Log("msg", "could not inspect task info", "task", t.taskID, "err", err)
		t.err = err
		return
	}
	logs, err := t.client.TaskLogs(ctx, t.taskID, opts)
	if err != nil {
		level.Error(t.logger).Log("msg", "could not fetch logs for task", "task", t.taskID, "err", err)
		t.err = err
		return
	}

	// Start transferring
	rstdout, wstdout := io.Pipe()
	rstderr, wstderr := io.Pipe()
	t.wg.Add(1)
	go func() {
		defer func() {
			t.wg.Done()
			wstdout.Close()
			wstderr.Close()
			t.Stop()
		}()
		var written int64
		var err error
		inspectInfo := taskInspect.Spec
		if inspectInfo.ContainerSpec.TTY {
			written, err = io.Copy(wstdout, logs)
		} else {
			written, err = stdcopy.StdCopy(wstdout, wstderr, logs)
		}
		if err != nil {
			level.Warn(t.logger).Log("msg", "could not transfer logs", "written", written, "task", t.taskID, "err", err)
		} else {
			level.Info(t.logger).Log("msg", "finished transferring logs", "written", written, "task", t.taskID)
		}
	}()

	// Start processing
	t.wg.Add(2)
	go t.process(rstdout, "stdout")
	go t.process(rstderr, "stderr")

	// Wait until done
	<-ctx.Done()
	logs.Close()
	level.Debug(t.logger).Log("msg", "done processing Docker logs", "task", t.taskID)
}

// extractTs tries for read the timestamp from the beginning of the log line.
// It's expected to follow the format 2006-01-02T15:04:05.999999999Z07:00.
func extractTs(line string) (time.Time, string, error) {
	pair := strings.SplitN(line, " ", 2)
	if len(pair) != 2 {
		return time.Now(), line, fmt.Errorf("Could not find timestamp in '%s'", line)
	}
	ts, err := time.Parse("2006-01-02T15:04:05.999999999Z07:00", pair[0])
	if err != nil {
		return time.Now(), line, fmt.Errorf("Could not parse timestamp from '%s': %w", pair[0], err)
	}
	return ts, pair[1], nil
}

// https://devmarkpro.com/working-big-files-golang
func readLine(r *bufio.Reader) (string, error) {
	var (
		isPrefix = true
		err      error
		line, ln []byte
	)

	for isPrefix && err == nil {
		line, isPrefix, err = r.ReadLine()
		ln = append(ln, line...)
	}

	return string(ln), err
}

func (t *Target) process(r io.Reader, logStream string) {
	defer func() {
		t.wg.Done()
	}()

	reader := bufio.NewReader(r)
	for {
		line, err := readLine(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			level.Error(t.logger).Log("msg", "error reading docker log line, skipping line", "err", err)
			t.metrics.dockerErrors.Inc()
		}

		ts, line, err := extractTs(line)
		if err != nil {
			level.Error(t.logger).Log("msg", "could not extract timestamp, skipping line", "err", err)
			t.metrics.dockerErrors.Inc()
			continue
		}

		// Add all labels from the config, relabel and filter them.
		lb := labels.NewBuilder(nil)
		for k, v := range t.labels {
			lb.Set(string(k), string(v))
		}
		lb.Set(dockerLabelLogStream, logStream)
		processed, _ := relabel.Process(lb.Labels(), t.relabelConfig...)

		filtered := make(model.LabelSet)
		for _, lbl := range processed {
			if strings.HasPrefix(lbl.Name, "__") {
				continue
			}
			filtered[model.LabelName(lbl.Name)] = model.LabelValue(lbl.Value)
		}

		t.handler.Chan() <- api.Entry{
			Labels: filtered,
			Entry: logproto.Entry{
				Timestamp: ts,
				Line:      line,
			},
		}
		t.metrics.dockerEntries.Inc()
		t.positions.Put(positions.CursorKey(t.taskID), ts.Unix())
	}
}

// startIfNotRunning starts processing task logs. The operation is idempotent , i.e. the processing cannot be started twice.
func (t *Target) startIfNotRunning() {
	if t.running.CompareAndSwap(false, true) {
		level.Debug(t.logger).Log("msg", "starting process loop", "task", t.taskID)
		ctx, cancel := context.WithCancel(context.Background())
		t.cancel = cancel
		go t.processLoop(ctx)
	} else {
		level.Debug(t.logger).Log("msg", "attempted to start process loop but it's already running", "task", t.taskID)
	}
}

func (t *Target) Stop() {
	t.cancel()
	t.wg.Wait()
	level.Debug(t.logger).Log("msg", "stopped Docker target", "task", t.taskID)
}

func (t *Target) Type() target.TargetType {
	return target.DockerTargetType
}

func (t *Target) Ready() bool {
	return t.running.Load()
}

func (t *Target) DiscoveredLabels() model.LabelSet {
	return t.labels
}

func (t *Target) Labels() model.LabelSet {
	return t.labels
}

// Details returns target-specific details.
func (t *Target) Details() interface{} {
	var errMsg string
	if t.err != nil {
		errMsg = t.err.Error()
	}
	return map[string]string{
		"id":       t.taskID,
		"error":    errMsg,
		"position": t.positions.GetString(positions.CursorKey(t.taskID)),
		"running":  strconv.FormatBool(t.running.Load()),
	}
}
