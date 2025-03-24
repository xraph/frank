//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"entgo.io/contrib/entoas"
	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
)

func main() {
	oas, err := entoas.NewExtension()
	if err != nil {
		log.Fatalf("creating entoas extension: %v", err)
	}

	err = entc.Generate("./schema",
		&gen.Config{},
		entc.Extensions(
			oas,
			NewSwaggoExtension(),
		),
	)
	if err != nil {
		log.Fatal("running ent codegen:", err)
	}
}

// SwaggoExtension provides the name comment extension for Ent models.
type SwaggoExtension struct {
	entc.DefaultExtension
}

// Templates of the SwaggoExtension.
func (n *SwaggoExtension) Templates() []*gen.Template {
	return []*gen.Template{
		gen.MustParse(gen.NewTemplate("model/comment").
			Parse("{{define \"model/comment\"}}// {{.Name}} holds the schema definition for the {{.Name}} entity.\n//@name {{.Name}}\n{{end}}")),
	}
}

// Hooks of the SwaggoExtension.
func (n *SwaggoExtension) Hooks() []gen.Hook {
	return []gen.Hook{
		func(next gen.Generator) gen.Generator {
			return gen.GenerateFunc(func(g *gen.Graph) error {
				err := next.Generate(g)
				if err != nil {
					return err
				}

				// Post-process generated files to add the name comment if not already added
				for _, node := range g.Nodes {
					modelFilePath := filepath.Join(g.Config.Target, fmt.Sprintf("%s.go", node.Package()))
					if err := processModelFile(modelFilePath, node.Name); err != nil {
						return fmt.Errorf("failed to process model file for %s: %w", node.Name, err)
					}
				}
				return nil
			})
		},
	}
}

// processModelFile adds the //@name comment at the end of the struct definition
// and removes any existing //@name comment that might be at the top
func processModelFile(filePath, modelName string) error {
	// Read the file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// Convert to string for easier processing
	fileContent := string(content)

	// First, remove any existing //@name comment that might be at the top
	existingNamePattern := regexp.MustCompile(fmt.Sprintf(`(?m)^//@name %s\s*\n`, modelName))
	fileContent = existingNamePattern.ReplaceAllString(fileContent, "")

	// Clean up any empty lines that might result from removing the comment
	fileContent = regexp.MustCompile(`\n\s*\n\s*\n`).ReplaceAllString(fileContent, "\n\n")

	// Now find the struct definition
	structPattern := fmt.Sprintf(`type\s+%s\s+struct\s+{`, modelName)
	re := regexp.MustCompile(structPattern)

	if loc := re.FindStringIndex(fileContent); loc != nil {
		// We found the start of the struct definition
		startPos := loc[0]

		// Now find the matching closing brace
		// We need to keep track of opening and closing braces
		braceCount := 0
		foundOpening := false
		endPos := -1

		for i := startPos; i < len(fileContent); i++ {
			if fileContent[i] == '{' {
				braceCount++
				foundOpening = true
			} else if fileContent[i] == '}' {
				braceCount--
				if foundOpening && braceCount == 0 {
					endPos = i + 1 // Position after the closing brace
					break
				}
			}
		}

		if endPos != -1 {
			// Check if the name comment already exists at the end of the struct
			structEndPattern := regexp.MustCompile(`}\s*//@name\s+` + modelName)
			if structEndPattern.MatchString(fileContent[startPos : endPos+30]) {
				// The comment already exists in the right place, nothing to do
				return os.WriteFile(filePath, []byte(fileContent), 0644)
			}

			// Insert the name comment after the closing brace
			updatedContent := fileContent[:endPos] + " //@name " + modelName + "\n" + fileContent[endPos:]

			// Write the updated content back to the file
			if err := os.WriteFile(filePath, []byte(updatedContent), 0644); err != nil {
				return fmt.Errorf("failed to write updated content to %s: %w", filePath, err)
			}
		}
	}

	return nil
}

// NewSwaggoExtension returns a new SwaggoExtension.
func NewSwaggoExtension() *SwaggoExtension {
	return &SwaggoExtension{}
}
