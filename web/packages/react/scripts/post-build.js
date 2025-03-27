// This script runs after the build to replace path aliases with relative paths
const fs = require("fs");
const path = require("path");
const glob = require("glob");

// Helper to determine relative path between files
function getRelativePath(from, to) {
	let relativePath = path.relative(path.dirname(from), to);
	// Ensure the path starts with ./ if it's not already going up directories
	if (!relativePath.startsWith(".")) {
		relativePath = "./" + relativePath;
	}
	return relativePath;
}

// Function to process a file and replace path aliases
function processFile(filePath) {
	console.log(`Processing: ${filePath}`);
	let content = fs.readFileSync(filePath, "utf8");

	// Replace @/ imports with relative paths
	content = content.replace(/from\s+['"]@\/(.+?)['"]/g, (match, importPath) => {
		// Map from the aliased import to the actual file path
		const targetPath = path.resolve(__dirname, "../", importPath);
		// Get relative path from current file to target
		const relativePath = getRelativePath(filePath, targetPath);
		// Create the new import statement
		return `from '${relativePath}'`;
	});

	// Replace require('@/...') with relative paths
	content = content.replace(
		/require\(['"]@\/(.+?)['"]\)/g,
		(match, importPath) => {
			// Map from the aliased import to the actual file path
			const targetPath = path.resolve(__dirname, "../", importPath);
			// Get relative path from current file to target
			const relativePath = getRelativePath(filePath, targetPath);
			// Create the new require statement
			return `require('${relativePath}')`;
		},
	);

	fs.writeFileSync(filePath, content, "utf8");
}

// Process all JS files in the dist directory
function processDirectory(dir) {
	const files = glob.sync(`${dir}/**/*.js`);
	files.forEach((file) => {
		processFile(file);
	});
}

// Main execution
console.log("Starting post-build processing...");
processDirectory("./dist/cjs");
processDirectory("./dist/esm");
console.log("Post-build processing completed!");
