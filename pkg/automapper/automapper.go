package automapper

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// MapperFunc is a generic function type for custom field mapping
type MapperFunc[S any, D any] func(src S) D

// FieldMapConfig defines the configuration for mapping a field
type FieldMapConfig struct {
	SrcField  string        // Source field name
	DstField  string        // Destination field name
	Converter reflect.Value // Converter function as reflect.Value
}

// TypeMapper represents a mapper between two specific types
type TypeMapper[S any, D any] struct {
	fieldMappings map[string]FieldMapConfig
	ignored       map[string]bool
}

// Mapper manages all type mappings
type Mapper struct {
	mappings map[string]interface{}
}

// NewMapper creates a new Mapper instance
func NewMapper() *Mapper {
	return &Mapper{
		mappings: make(map[string]interface{}),
	}
}

// CreateMap creates a mapping configuration between source and destination types
func CreateMap[S any, D any]() *TypeMapper[S, D] {
	return &TypeMapper[S, D]{
		fieldMappings: make(map[string]FieldMapConfig),
		ignored:       make(map[string]bool),
	}
}

// ForMember configures a mapping for a specific destination field
func (tm *TypeMapper[S, D]) ForMember(dstField string, mapFunc MapperFunc[S, any]) *TypeMapper[S, D] {
	tm.fieldMappings[dstField] = FieldMapConfig{
		DstField:  dstField,
		Converter: reflect.ValueOf(mapFunc),
	}
	return tm
}

// Ignore marks a destination field to be ignored during mapping
func (tm *TypeMapper[S, D]) Ignore(field string) *TypeMapper[S, D] {
	tm.ignored[field] = true
	delete(tm.fieldMappings, field)
	return tm
}

// RegisterMapper registers a type mapper with the global mapper
func (m *Mapper) RegisterMapper(typeMapper interface{}) {
	// For this to work, we need the caller to also pass the specific types
	// Unfortunately, Go's reflection doesn't provide direct access to type parameters of generic types

	// Get the type name which will contain type information
	// typeMapperVal := reflect.ValueOf(typeMapper)
	// typeMapperType := typeMapperVal.Type()

	// We need to examine the methods to extract type information
	// This is a workaround as Go's reflection doesn't directly expose generic type parameters

	// For user convenience, require ForMember or Ignore to be called at least once
	// so we can extract type information from method calls

	// Extract source and destination types by examining the mapper's internal state
	// We can use reflection to access fieldMappings or other fields of the TypeMapper

	// A more practical approach is to require explicit type registration
	// Requiring users to register S and D types alongside the mapper

	// This is why we add a separate registration method that takes explicit types
}

// RegisterExplicit explicitly registers a type mapper with source and destination types
func (m *Mapper) RegisterExplicit(srcType, dstType reflect.Type, typeMapper interface{}) {
	key := fmt.Sprintf("%s->%s", srcType.String(), dstType.String())
	m.mappings[key] = typeMapper

	// Also register for pointer types
	ptrSrcType := reflect.PtrTo(srcType)
	ptrDstType := reflect.PtrTo(dstType)

	ptrKey := fmt.Sprintf("%s->%s", ptrSrcType.String(), ptrDstType.String())
	m.mappings[ptrKey] = typeMapper
}

// RegisterWithTypes registers a TypeMapper with explicit source and destination types
func RegisterWithTypes[S any, D any](m *Mapper, typeMapper *TypeMapper[S, D]) {
	// Get type information using reflection from zero values
	var src S
	var dst D

	srcType := reflect.TypeOf(src)
	dstType := reflect.TypeOf(dst)

	// Register with explicit types
	m.RegisterExplicit(srcType, dstType, typeMapper)
}

// MapFunc stores a mapping function with its type information for use with reflection
type MapFunc struct {
	Function interface{}
	SrcType  reflect.Type
	DstType  reflect.Type
}

// Register mapping functions for specific types
var mapFuncs = make(map[string]MapFunc)

// RegisterMapFunc registers a mapping function for specific source and destination types
func RegisterMapFunc[S any, D any](mapper *TypeMapper[S, D]) {
	var src S
	var dst D

	srcType := reflect.TypeOf(src)
	dstType := reflect.TypeOf(dst)

	key := fmt.Sprintf("%s->%s", srcType.String(), dstType.String())

	// Create a non-generic closure that captures the mapper
	mapFunc := func(src interface{}, dst interface{}) {
		typedSrc := src.(S)
		typedDst := dst.(*D)

		result := Map(typedSrc, mapper)
		// Copy the result to the destination
		reflect.ValueOf(typedDst).Elem().Set(reflect.ValueOf(result))
	}

	mapFuncs[key] = MapFunc{
		Function: mapFunc,
		SrcType:  srcType,
		DstType:  dstType,
	}
}

// MapWithRegistered performs mapping using a registered mapper
func (m *Mapper) MapWithRegistered(src interface{}, dst interface{}) error {
	srcType := reflect.TypeOf(src)
	dstVal := reflect.ValueOf(dst)

	// dst must be a pointer
	if dstVal.Kind() != reflect.Ptr {
		return errors.New("destination must be a pointer")
	}

	dstType := dstVal.Elem().Type()
	key := fmt.Sprintf("%s->%s", srcType.String(), dstType.String())

	// Look up the mapping function
	mapFunc, exists := mapFuncs[key]
	if !exists {
		return fmt.Errorf("no mapper registered for %s -> %s", srcType.String(), dstType.String())
	}

	// Call the mapping function
	fn := reflect.ValueOf(mapFunc.Function)
	fn.Call([]reflect.Value{reflect.ValueOf(src), reflect.ValueOf(dst)})

	return nil
}

// Map performs the mapping from source to destination
func Map[S any, D any](src S, typeMapper *TypeMapper[S, D]) D {
	var dst D

	srcVal := reflect.ValueOf(src)
	dstVal := reflect.ValueOf(&dst).Elem()

	// Discover and map fields automatically
	autoMap(srcVal, dstVal, typeMapper)

	return dst
}

// autoMap handles the automatic mapping between two values
func autoMap[S any, D any](srcVal reflect.Value, dstVal reflect.Value, typeMapper *TypeMapper[S, D]) {
	// Handle pointer indirection
	if srcVal.Kind() == reflect.Ptr {
		if srcVal.IsNil() {
			return // Nothing to map from nil
		}
		srcVal = srcVal.Elem()
	}

	if srcVal.Kind() != reflect.Struct || dstVal.Kind() != reflect.Struct {
		return // Only structs are supported
	}

	// First apply automatic mapping for fields with matching names
	// srcType := srcVal.Type()
	dstType := dstVal.Type()

	for i := 0; i < dstType.NumField(); i++ {
		dstField := dstType.Field(i)

		// Skip unexported fields
		if !isExported(dstField.Name) {
			continue
		}

		// Skip ignored fields
		if typeMapper.ignored[dstField.Name] {
			continue
		}

		// Skip fields with custom mappers
		if _, hasCustomMapper := typeMapper.fieldMappings[dstField.Name]; hasCustomMapper {
			continue
		}

		dstFieldVal := dstVal.Field(i)
		if !dstFieldVal.CanSet() {
			continue
		}

		// Try to find a matching field in the source
		srcFieldVal := srcVal.FieldByName(dstField.Name)
		if !srcFieldVal.IsValid() {
			continue
		}

		// Perform the assignment if types are compatible
		if srcFieldVal.Type().AssignableTo(dstFieldVal.Type()) {
			dstFieldVal.Set(srcFieldVal)
		}
	}

	// Apply custom mappings
	for dstFieldName, config := range typeMapper.fieldMappings {
		if typeMapper.ignored[dstFieldName] {
			continue
		}

		dstFieldVal := dstVal.FieldByName(dstFieldName)
		if !dstFieldVal.IsValid() || !dstFieldVal.CanSet() {
			continue
		}

		// Create args for the converter function
		args := []reflect.Value{srcVal}

		// Call the converter function
		result := config.Converter.Call(args)[0]

		// Set the result if types are compatible
		if result.Type().AssignableTo(dstFieldVal.Type()) {
			dstFieldVal.Set(result)
		}
	}
}

// isExported checks if a field name represents an exported field
func isExported(fieldName string) bool {
	if fieldName == "" {
		return false
	}
	return strings.ToUpper(fieldName[:1]) == fieldName[:1]
}

// BatchMap maps a slice of source objects to destination objects
func BatchMap[S any, D any](src []S, typeMapper *TypeMapper[S, D]) []D {
	result := make([]D, len(src))
	for i, item := range src {
		result[i] = Map(item, typeMapper)
	}
	return result
}

// MapTo maps source to an existing destination instance
func MapTo[S any, D any](src S, dst *D, typeMapper *TypeMapper[S, D]) {
	srcVal := reflect.ValueOf(src)
	dstVal := reflect.ValueOf(dst).Elem()

	autoMap(srcVal, dstVal, typeMapper)
}
