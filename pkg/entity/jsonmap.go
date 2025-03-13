package entity

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// JSONMap is a custom map type for Ent.
type JSONMap map[string]any // @name JSONMap

// Scan implements the sql.Scanner interface.
func (m *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*m = make(JSONMap)
		return nil
	}

	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("unexpected type for JSONMap: %T", value)
	}

	return json.Unmarshal(data, m)
}

// MarshalJSON implements the json.Marshaler interface.
func (m JSONMap) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(map[string]interface{}(m))
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (m *JSONMap) UnmarshalJSON(data []byte) error {
	if m == nil {
		*m = make(JSONMap)
	}
	return json.Unmarshal(data, (*map[string]interface{})(m))
}

// Value implements the driver.Valuer interface.
func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

// JSONMapString is a custom map type for Ent.
type JSONMapString map[string]string // @name JSONMapString

// Scan implements the sql.Scanner interface.
func (m *JSONMapString) Scan(value interface{}) error {
	if value == nil {
		*m = make(JSONMapString)
		return nil
	}

	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("unexpected type for JSONMapString: %T", value)
	}

	return json.Unmarshal(data, m)
}

// MarshalJSON implements the json.Marshaler interface.
func (m JSONMapString) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(m)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (m *JSONMapString) UnmarshalJSON(data []byte) error {
	if m == nil {
		*m = make(JSONMapString)
	}
	return json.Unmarshal(data, m)
}

// Value implements the driver.Valuer interface.
func (m JSONMapString) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

// // Annotations for JSONMap tell EntOAS how to represent this field.
// func (JSONMap) Annotations() []schema.Annotation {
// 	return []schema.Annotation{
// 		entoas.("object"), // Mark this map type as a JSON object in OAS
// 	}
// }
