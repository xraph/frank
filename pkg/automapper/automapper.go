package automapper

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
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

// ForMemberToPtr creates a mapping that automatically converts a value type to a pointer type
func (tm *TypeMapper[S, D]) ForMemberToPtr(dstField string, srcField string) *TypeMapper[S, D] {
	tm.fieldMappings[dstField] = FieldMapConfig{
		DstField: dstField,
		SrcField: srcField,
		Converter: reflect.ValueOf(func(src S) any {
			srcVal := reflect.ValueOf(src)

			// Handle both value and pointer source types
			if srcVal.Kind() == reflect.Ptr {
				if srcVal.IsNil() {
					return nil
				}
				srcVal = srcVal.Elem()
			}

			// Get the field value by name
			fieldVal := srcVal.FieldByName(srcField)
			if !fieldVal.IsValid() {
				return nil
			}

			// Skip if zero value
			if isZeroValue(fieldVal) {
				return nil
			}

			// Create a pointer to the value
			ptrVal := reflect.New(fieldVal.Type())
			ptrVal.Elem().Set(fieldVal)
			return ptrVal.Interface()
		}),
	}
	return tm
}

// ForFormat creates a mapping for formatting a value (especially useful for time.Time)
func (tm *TypeMapper[S, D]) ForFormat(dstField string, srcField string, format string) *TypeMapper[S, D] {
	tm.fieldMappings[dstField] = FieldMapConfig{
		DstField: dstField,
		SrcField: srcField,
		Converter: reflect.ValueOf(func(src S) any {
			srcVal := reflect.ValueOf(src)
			if srcVal.Kind() == reflect.Ptr {
				srcVal = srcVal.Elem()
			}

			// Get the field value
			fieldVal := srcVal.FieldByName(srcField)
			if !fieldVal.IsValid() {
				return ""
			}

			// Handle time.Time specifically
			if t, ok := fieldVal.Interface().(time.Time); ok {
				return t.Format(format)
			}

			// Default to string conversion
			return valueToString(fieldVal)
		}),
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

	dstType := reflect.TypeOf(dst)
	dstVal := reflect.New(dstType).Elem()
	// dstVal := reflect.ValueOf(dst).Elem()

	// Ensure we have consistent handling regardless of whether src is a value or pointer
	if reflect.TypeOf(src).Kind() != reflect.Ptr && reflect.TypeOf((*S)(nil)).Elem().Kind() == reflect.Ptr {
		// If S is a pointer type but src is a value, we need to create a pointer
		srcPtr := reflect.New(srcVal.Type())
		srcPtr.Elem().Set(srcVal)
		srcVal = srcPtr
	}

	// Discover and map fields automatically
	autoMap(srcVal, dstVal, typeMapper)

	return dstVal.Interface().(D)
}

// autoMapElements is a non-generic helper function for mapping array/slice elements
// It's used internally by autoMap to handle recursive mapping of elements without type inference issues
func autoMapElements(srcVal reflect.Value, dstVal reflect.Value, mapper interface{}) {
	// Use reflection to access the autoMap method
	// This is a workaround for type parameter inference limitations
	// mapperVal := reflect.ValueOf(mapper)

	// Create a simple struct field-by-field copy since we can't call autoMap directly due to type inference
	if srcVal.Kind() == reflect.Struct && dstVal.Kind() == reflect.Struct {
		// srcType := srcVal.Type()
		dstType := dstVal.Type()

		// Map fields by name
		for i := 0; i < dstType.NumField(); i++ {
			dstField := dstType.Field(i)
			if !isExported(dstField.Name) {
				continue
			}

			dstFieldVal := dstVal.Field(i)
			if !dstFieldVal.CanSet() {
				continue
			}

			// Try to find field in source
			srcFieldVal := srcVal.FieldByName(dstField.Name)
			if srcFieldVal.IsValid() {
				// Attempt to set the value with appropriate type conversion
				if srcFieldVal.Type().AssignableTo(dstFieldVal.Type()) {
					dstFieldVal.Set(srcFieldVal)
				} else if srcFieldVal.Type().ConvertibleTo(dstFieldVal.Type()) {
					dstFieldVal.Set(srcFieldVal.Convert(dstFieldVal.Type()))
				}
			}
		}
	}
}

// autoMap handles the automatic mapping between two values
func autoMap[S any, D any](srcVal reflect.Value, dstVal reflect.Value, typeMapper *TypeMapper[S, D]) { // Save original srcVal for custom mappers
	// Save original srcVal for custom mappers
	originalSrcVal := srcVal

	// Handle pointer indirection
	if srcVal.Kind() == reflect.Ptr {
		if srcVal.IsNil() {
			return // Nothing to map from nil
		}
		srcVal = srcVal.Elem()
	}

	// Special handling for arrays and slices
	if (srcVal.Kind() == reflect.Slice || srcVal.Kind() == reflect.Array) &&
		(dstVal.Kind() == reflect.Slice || dstVal.Kind() == reflect.Array) {
		// Get the element types
		srcElemType := srcVal.Type().Elem()
		dstElemType := dstVal.Type().Elem()

		// Only proceed if we can potentially map between these element types
		if srcElemType.Kind() == reflect.Struct || dstElemType.Kind() == reflect.Struct ||
			(srcElemType.Kind() == reflect.Ptr && srcElemType.Elem().Kind() == reflect.Struct) ||
			(dstElemType.Kind() == reflect.Ptr && dstElemType.Elem().Kind() == reflect.Struct) {

			length := srcVal.Len()

			// If destination is a slice, resize it
			if dstVal.Kind() == reflect.Slice {
				dstVal.Set(reflect.MakeSlice(dstVal.Type(), length, length))
			} else if length > dstVal.Len() {
				// If destination is an array and smaller than source, only map what fits
				length = dstVal.Len()
			}

			// Map each element individually
			for i := 0; i < length; i++ {
				srcElemVal := srcVal.Index(i)
				dstElemVal := dstVal.Index(i)

				// If the element is a struct or a pointer to a struct, recursively map it
				if srcElemVal.Kind() == reflect.Struct && dstElemVal.Kind() == reflect.Struct {
					// We need to create a new mapper for the element types
					// This is a bit of a hack, but necessary since Go doesn't allow us to easily
					// extract the element types from the generic parameter
					elemMapper := &TypeMapper[S, D]{
						fieldMappings: typeMapper.fieldMappings,
						ignored:       typeMapper.ignored,
					}
					autoMapElements(srcElemVal, dstElemVal, elemMapper)
				} else if srcElemVal.Kind() == reflect.Ptr && dstElemVal.CanSet() {
					// Handle nil pointers
					if srcElemVal.IsNil() {
						// Set zero value if the destination can be set
						if dstElemVal.Kind() == reflect.Ptr {
							dstElemVal.Set(reflect.Zero(dstElemVal.Type()))
						}
						continue
					}

					// If both are pointers, we need to ensure destination has a valid object
					if dstElemVal.Kind() == reflect.Ptr {
						if dstElemVal.IsNil() {
							dstElemVal.Set(reflect.New(dstElemVal.Type().Elem()))
						}
						elemMapper := &TypeMapper[S, D]{
							fieldMappings: typeMapper.fieldMappings,
							ignored:       typeMapper.ignored,
						}
						autoMapElements(srcElemVal, dstElemVal.Elem(), elemMapper)
					} else {
						// Source is pointer, destination is value
						elemMapper := &TypeMapper[S, D]{
							fieldMappings: typeMapper.fieldMappings,
							ignored:       typeMapper.ignored,
						}
						autoMapElements(srcElemVal.Elem(), dstElemVal, elemMapper)
					}
				} else if dstElemVal.Kind() == reflect.Ptr && dstElemVal.CanSet() {
					// Destination is a pointer, source is a value
					if dstElemVal.IsNil() {
						dstElemVal.Set(reflect.New(dstElemVal.Type().Elem()))
					}
					elemMapper := &TypeMapper[S, D]{
						fieldMappings: typeMapper.fieldMappings,
						ignored:       typeMapper.ignored,
					}
					autoMapElements(srcElemVal, dstElemVal.Elem(), elemMapper)
				} else if srcElemVal.Type().AssignableTo(dstElemVal.Type()) && dstElemVal.CanSet() {
					// Direct assignment for compatible types
					dstElemVal.Set(srcElemVal)
				} else if srcElemVal.Type().ConvertibleTo(dstElemVal.Type()) && dstElemVal.CanSet() {
					// Type conversion for compatible types
					dstElemVal.Set(srcElemVal.Convert(dstElemVal.Type()))
				}
			}

			// After handling array/slice mapping, return since we don't need field-by-field mapping
			return
		}
	}

	if srcVal.Kind() != reflect.Struct || dstVal.Kind() != reflect.Struct {
		return // Only structs are supported
	}

	// Get types for source and destination
	srcType := srcVal.Type()
	dstType := dstVal.Type()

	// Build a map of source field names and JSON names for quick lookup
	srcFieldMap := make(map[string]int)
	for i := 0; i < srcType.NumField(); i++ {
		field := srcType.Field(i)
		srcFieldMap[field.Name] = i

		// Also map the lowercase version for case-insensitive matching
		srcFieldMap[strings.ToLower(field.Name)] = i

		// Map JSON tag name if present
		jsonName := getJSONFieldName(field)
		if jsonName != "" && jsonName != field.Name {
			srcFieldMap[jsonName] = i
			srcFieldMap[strings.ToLower(jsonName)] = i
		}
	}

	// Process destination fields
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

		// Skip fields with custom mappers (will be handled later)
		if _, hasCustomMapper := typeMapper.fieldMappings[dstField.Name]; hasCustomMapper {
			continue
		}

		dstFieldVal := dstVal.Field(i)
		if !dstFieldVal.CanSet() {
			continue
		}

		// Get JSON name for destination field
		dstJSONName := getJSONFieldName(dstField)

		// Try to find matching field in source by various names
		var srcFieldVal reflect.Value
		var srcFieldIndex int
		var found bool

		// Try exact name matches first
		if idx, exists := srcFieldMap[dstField.Name]; exists {
			srcFieldIndex = idx
			found = true
		} else if dstJSONName != "" && dstJSONName != dstField.Name {
			// Try JSON tag name
			if idx, exists := srcFieldMap[dstJSONName]; exists {
				srcFieldIndex = idx
				found = true
			}
		}

		// Try case-insensitive matches if no exact match found
		if !found {
			lowerName := strings.ToLower(dstField.Name)
			if idx, exists := srcFieldMap[lowerName]; exists {
				srcFieldIndex = idx
				found = true
			} else if dstJSONName != "" {
				lowerJSON := strings.ToLower(dstJSONName)
				if idx, exists := srcFieldMap[lowerJSON]; exists {
					srcFieldIndex = idx
					found = true
				}
			}
		}

		if found {
			srcFieldVal = srcVal.Field(srcFieldIndex)

			// Handle type conversions
			if srcFieldVal.Type().AssignableTo(dstFieldVal.Type()) {
				// Direct assignment if types match
				dstFieldVal.Set(srcFieldVal)
			} else if srcFieldVal.Kind() != reflect.Ptr && dstFieldVal.Kind() == reflect.Ptr {
				// Non-pointer to pointer conversion
				if dstFieldVal.Type().Elem().Kind() == srcFieldVal.Kind() {
					// Skip empty strings/zero values when converting to pointers
					if !isZeroValue(srcFieldVal) {
						newPtr := reflect.New(srcFieldVal.Type())
						newPtr.Elem().Set(srcFieldVal)
						dstFieldVal.Set(newPtr)
					}
				}
			} else if srcFieldVal.Kind() == reflect.Ptr && dstFieldVal.Kind() != reflect.Ptr {
				// Pointer to non-pointer conversion
				if !srcFieldVal.IsNil() && srcFieldVal.Elem().Type().AssignableTo(dstFieldVal.Type()) {
					dstFieldVal.Set(srcFieldVal.Elem())
				}
			} else if srcFieldVal.Type().ConvertibleTo(dstFieldVal.Type()) {
				// Try standard Go type conversion
				dstFieldVal.Set(srcFieldVal.Convert(dstFieldVal.Type()))
			} else if dstFieldVal.Kind() == reflect.String {
				// Special case for converting various types to string
				dstFieldVal.SetString(valueToString(srcFieldVal))
			} else if srcFieldVal.Kind() == reflect.String &&
				(dstFieldVal.Kind() >= reflect.Int && dstFieldVal.Kind() <= reflect.Int64) {
				// String to integer conversion
				if i, err := strconv.ParseInt(srcFieldVal.String(), 10, 64); err == nil {
					dstFieldVal.SetInt(i)
				}
			} else if srcFieldVal.Kind() == reflect.String &&
				(dstFieldVal.Kind() >= reflect.Float32 && dstFieldVal.Kind() <= reflect.Float64) {
				// String to float conversion
				if f, err := strconv.ParseFloat(srcFieldVal.String(), 64); err == nil {
					dstFieldVal.SetFloat(f)
				}
			}
			// Could add more type conversion cases as needed
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
		args := []reflect.Value{originalSrcVal}

		// Call the converter function with panic recovery
		var result reflect.Value
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Just log the error and continue with other fields
					fmt.Printf("Error mapping field %s: %v\n", dstFieldName, r)
				}
			}()

			results := config.Converter.Call(args)
			if len(results) > 0 {
				result = results[0]
			}
		}()

		// Set the result if types are compatible and it's not nil
		if result.IsValid() && !result.IsZero() {
			if result.Type().AssignableTo(dstFieldVal.Type()) {
				dstFieldVal.Set(result)
			} else if result.Kind() != reflect.Ptr && dstFieldVal.Kind() == reflect.Ptr {
				// Convert non-pointer to pointer
				if dstFieldVal.Type().Elem().Kind() == result.Kind() {
					newPtr := reflect.New(result.Type())
					newPtr.Elem().Set(result)
					dstFieldVal.Set(newPtr)
				}
			}
		}
	}
}

// Find field by case-insensitive match
func findFieldCaseInsensitive(structVal reflect.Value, fieldName string) (reflect.Value, bool) {
	structType := structVal.Type()
	lowerName := strings.ToLower(fieldName)

	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		if strings.ToLower(field.Name) == lowerName {
			return structVal.Field(i), true
		}

		// Also check JSON tag
		jsonName := getJSONFieldName(field)
		if strings.ToLower(jsonName) == lowerName {
			return structVal.Field(i), true
		}
	}

	return reflect.Value{}, false
}

// Add this function to extract field name from JSON tag
func getJSONFieldName(field reflect.StructField) string {
	tag := field.Tag.Get("json")
	if tag == "" {
		return field.Name
	}

	parts := strings.Split(tag, ",")
	if parts[0] == "-" {
		return "" // Skip this field
	}
	return parts[0]
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

	// Ensure we have consistent handling regardless of whether src is a value or pointer
	if reflect.TypeOf(src).Kind() != reflect.Ptr && reflect.TypeOf((*S)(nil)).Elem().Kind() == reflect.Ptr {
		// If S is a pointer type but src is a value, we need to create a pointer
		srcPtr := reflect.New(srcVal.Type())
		srcPtr.Elem().Set(srcVal)
		srcVal = srcPtr
	}

	autoMap(srcVal, dstVal, typeMapper)
}

// MapArray maps a source array to a new destination array
func MapArray[S any, D any](src []S, typeMapper *TypeMapper[S, D]) []D {
	result := make([]D, len(src))
	for i, item := range src {
		result[i] = Map(item, typeMapper)
	}
	return result
}

// MapArrayTo maps source array to an existing destination array pointer
func MapArrayTo[S any, D any](src []S, dst *[]D, typeMapper *TypeMapper[S, D]) {
	// Create a new array with mapped elements
	result := MapArray(src, typeMapper)

	// Assign to destination
	*dst = result
}

// MapToArray maps source array to an existing destination array pointer
func MapToArray[S any, D any](src []S, typeMapper *TypeMapper[S, D]) []D {
	result := make([]D, len(src))
	for i, item := range src {
		result[i] = Map(item, typeMapper)
	}

	return result
}

// MapSlice handles mapping between interface{} slices/arrays
func MapSlice[S any, D any](src interface{}, typeMapper *TypeMapper[S, D]) interface{} {
	srcVal := reflect.ValueOf(src)

	// Handle nil input
	if src == nil || (srcVal.Kind() == reflect.Ptr && srcVal.IsNil()) {
		return nil
	}

	// If src is a pointer to a slice, dereference it
	if srcVal.Kind() == reflect.Ptr {
		if srcVal.Elem().Kind() != reflect.Slice && srcVal.Elem().Kind() != reflect.Array {
			// Not a slice or array pointer
			return nil
		}
		srcVal = srcVal.Elem()
	}

	// Ensure we're dealing with a slice or array
	if srcVal.Kind() != reflect.Slice && srcVal.Kind() != reflect.Array {
		return nil
	}

	// Get the destination type by examining D
	var dstSample D
	dstType := reflect.TypeOf(dstSample)

	// Create a new slice of the destination element type
	length := srcVal.Len()
	dstSlice := reflect.MakeSlice(reflect.SliceOf(dstType), length, length)

	// Map each element
	for i := 0; i < length; i++ {
		srcElem := srcVal.Index(i).Interface().(S)
		dstElem := Map(srcElem, typeMapper)
		dstSlice.Index(i).Set(reflect.ValueOf(dstElem))
	}

	return dstSlice.Interface()
}

// MapSliceTo maps a source interface{} slice to a destination interface{} slice
func MapSliceTo[S any, D any](src interface{}, dst interface{}, typeMapper *TypeMapper[S, D]) {
	srcVal := reflect.ValueOf(src)
	dstVal := reflect.ValueOf(dst)

	// Handle nil input or invalid destination
	if src == nil || dst == nil || !dstVal.IsValid() || dstVal.Kind() != reflect.Ptr {
		return
	}

	// If src is a pointer to a slice, dereference it
	if srcVal.Kind() == reflect.Ptr {
		if srcVal.IsNil() {
			return
		}
		srcVal = srcVal.Elem()
	}

	// Ensure we're dealing with a slice or array on the source
	if srcVal.Kind() != reflect.Slice && srcVal.Kind() != reflect.Array {
		return
	}

	// Destination must be a pointer to a slice or array
	dstElem := dstVal.Elem()
	if dstElem.Kind() != reflect.Slice && dstElem.Kind() != reflect.Array {
		return
	}

	// Get the length of the source slice/array
	length := srcVal.Len()

	// If destination is a slice, resize it to match source length
	if dstElem.Kind() == reflect.Slice {
		// Create a new slice of the appropriate size
		newSlice := reflect.MakeSlice(dstElem.Type(), length, length)
		dstElem.Set(newSlice)
	} else if length > dstElem.Len() {
		// If destination is an array and smaller than source, only map what fits
		length = dstElem.Len()
	}

	// Map each element from source to destination
	for i := 0; i < length; i++ {
		// Get source element
		srcElemVal := srcVal.Index(i)

		// Convert to the expected source type
		srcElem := srcElemVal.Interface().(S)

		// Map the element
		mappedElem := Map(srcElem, typeMapper)

		// Set the element in the destination slice/array
		dstElem.Index(i).Set(reflect.ValueOf(mappedElem))
	}
}

// Helper to check for zero values
func isZeroValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return v.String() == ""
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Slice, reflect.Map, reflect.Array:
		return v.Len() == 0
	default:
		return false
	}
}

// Helper to convert various types to string
func valueToString(v reflect.Value) string {
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(v.Float(), 'f', -1, 64)
	case reflect.Bool:
		return strconv.FormatBool(v.Bool())
	case reflect.Struct:
		if t, ok := v.Interface().(time.Time); ok {
			return t.Format(time.RFC3339)
		}
		return fmt.Sprintf("%v", v.Interface())
	default:
		return fmt.Sprintf("%v", v.Interface())
	}
}
