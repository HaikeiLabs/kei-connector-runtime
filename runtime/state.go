package runtime

import (
	"encoding/json"
	"fmt"
	"os"
)

type collectorState struct {
	Segment      uint64    `json:"segment"`
	LinesSent    int       `json:"lines_sent"`
	ReportedLoss spoolLoss `json:"reported_loss"`
}

func readCollectorState(path string) (*collectorState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &collectorState{}, nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}
	var st collectorState
	if err := json.Unmarshal(data, &st); err != nil {
		return &collectorState{}, nil
	}
	return &st, nil
}

func writeCollectorState(path string, st *collectorState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
