package runtime

import (
	"encoding/json"
)

func WriteJSON(w interface{ Write([]byte) (int, error) }, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}
