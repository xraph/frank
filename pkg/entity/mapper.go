package entity

import (
	"entgo.io/contrib/entoas"
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/field"
	"github.com/ogen-go/ogen"
)

// JSONMapField returns a field descriptor for a map field,
// which will be stored as JSON in the database.
func JSONMapField(name string, optional bool) ent.Field {
	f := field.JSON(name, map[string]any{}).
		SchemaType(map[string]string{
			dialect.MySQL:    "json",
			dialect.SQLite:   "text",
			dialect.Postgres: "jsonb",
		}).
		Annotations(
			entoas.Schema(&ogen.Schema{
				Type: "object",
				AdditionalProperties: &ogen.AdditionalProperties{
					Schema: ogen.Schema{
						Type: "object",
					},
				},
			}),
		)

	if optional {
		f = f.Optional()
	}

	return f
}

// JSONMapStringField returns a field descriptor for a map[string]string field,
// which will be stored as JSON in the database.
func JSONMapStringField(name string, optional bool) ent.Field {
	f := field.JSON(name, map[string]string{}).
		SchemaType(map[string]string{
			dialect.MySQL:    "json",
			dialect.SQLite:   "text",
			dialect.Postgres: "jsonb",
		}).
		Annotations(
			entoas.Schema(&ogen.Schema{
				Type: "object",
				AdditionalProperties: &ogen.AdditionalProperties{
					Schema: ogen.Schema{
						Type: "string",
					},
				},
			}),
		)
	if optional {
		f = f.Optional()
	}
	return f
}

// JSONMapIntField returns a field descriptor for a map[string]int field,
// which will be stored as JSON in the database.
func JSONMapIntField(name string, optional bool) ent.Field {
	f := field.Other(name, &JSONMap{}).
		SchemaType(map[string]string{
			dialect.MySQL:    "json",
			dialect.SQLite:   "text",
			dialect.Postgres: "jsonb",
		}).
		Annotations(
			entoas.Schema(&ogen.Schema{
				Type: "object",
				AdditionalProperties: &ogen.AdditionalProperties{
					Schema: ogen.Schema{
						Type:   "integer",
						Format: "int64",
					},
				},
			}),
		)
	if optional {
		f = f.Optional()
	}
	return f
}

// JSONMapFloatField returns a field descriptor for a map[string]float64 field,
// which will be stored as JSON in the database.
func JSONMapFloatField(name string, optional bool) ent.Field {
	f := field.Other(name, &JSONMap{}).
		SchemaType(map[string]string{
			dialect.MySQL:    "json",
			dialect.SQLite:   "text",
			dialect.Postgres: "jsonb",
		}).
		Annotations(
			entoas.Schema(&ogen.Schema{
				Type: "object",
				AdditionalProperties: &ogen.AdditionalProperties{
					Schema: ogen.Schema{
						Type:   "number",
						Format: "double",
					},
				},
			}),
		)
	if optional {
		f = f.Optional()
	}
	return f
}

// JSONMapBoolField returns a field descriptor for a map[string]bool field,
// which will be stored as JSON in the database.
func JSONMapBoolField(name string, optional bool) ent.Field {
	f := field.Other(name, &JSONMap{}).
		SchemaType(map[string]string{
			dialect.MySQL:    "json",
			dialect.SQLite:   "text",
			dialect.Postgres: "jsonb",
		}).
		Annotations(
			entoas.Schema(&ogen.Schema{
				Type: "object",
				AdditionalProperties: &ogen.AdditionalProperties{
					Schema: ogen.Schema{
						Type: "boolean",
					},
				},
			}),
		)
	if optional {
		f = f.Optional()
	}
	return f
}
