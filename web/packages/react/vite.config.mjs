import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';
import {resolve} from 'path';
import dts from 'vite-plugin-dts';
import tailwindcss from "@tailwindcss/vite";
import {readFileSync} from 'fs';

const pkg = JSON.parse(readFileSync('./package.json', 'utf8'));

// External dependencies that should not be bundled
const external = [
	...Object.keys(pkg.peerDependencies || {}),
	'react/jsx-runtime',
	'react/jsx-dev-runtime',
];

// Make dependencies external too (they should be installed by consumers)
const makeExternalPredicate = (externalArr) => {
	if (externalArr.length === 0) {
		return () => false;
	}
	const pattern = new RegExp(`^(${externalArr.join('|')})($|/)`);
	return (id) => pattern.test(id);
};

// Files that need 'use client' directive
const clientFiles = [
	'use-permissions',
	'use-auth',
	'provider',
	'components'
];

// Check if file needs 'use client' directive
const needsUseClient = (filename) => {
	return clientFiles.some(clientFile => filename.includes(clientFile));
};

// Custom plugin to preserve 'use client' directives
function preserveUseClient() {
	return {
		name: 'preserve-use-client',
		generateBundle(options, bundle) {
			Object.keys(bundle).forEach(fileName => {
				const chunk = bundle[fileName];
				if (chunk.type === 'chunk') {
					// Check if this chunk needs 'use client'
					const needsClient = needsUseClient(fileName) || needsUseClient(chunk.name || '');

					// Also check if any of the modules in this chunk had 'use client'
					const hasUseClientInModules = chunk.modules && Object.keys(chunk.modules).some(moduleId => {
						// Check if the module path suggests it's a client component
						return needsUseClient(moduleId);
					});

					if (needsClient || hasUseClientInModules) {
						chunk.code = `'use client';\n${chunk.code}`;
					}
				}
			});
		}
	};
}

export default defineConfig(({command, mode}) => {
	const isProduction = mode === 'production';
	const isBuild = command === 'build';

	return {
		plugins: [
			// React plugin with automatic JSX runtime
			react({
				jsxRuntime: 'automatic',
				jsxImportSource: 'react',
				babel: {
					plugins: [
						// Add any babel plugins needed for your auth components
					],
				},
			}),

			// Custom plugin to preserve 'use client' directives
			preserveUseClient(),

			// Generate TypeScript declaration files
			dts({
				insertTypesEntry: true,
				outDir: 'dist/types',
				tsConfigFilePath: './tsconfig.json',
				include: ['src/**/*'],
				exclude: [
					'**/*.test.ts',
					'**/*.test.tsx',
					'**/*.spec.ts',
					'**/*.spec.tsx',
					'**/*.stories.ts',
					'**/*.stories.tsx',
					'stories/**/*',
				],
				beforeWriteFile: (filePath, content) => {
					// Add 'use client' directive to client component types
					if (needsUseClient(filePath)) {
						content = `'use client';\n\n${content}`;
					}
					return {
						filePath,
						content,
					};
				},
			}),

			tailwindcss()
		],

		// Path resolution
		resolve: {
			alias: {
				'@': resolve(__dirname, './src'),
				'@/components': resolve(__dirname, './src/components'),
				'@/hooks': resolve(__dirname, './src/hooks'),
				'@/utils': resolve(__dirname, './src/utils'),
				'@/config': resolve(__dirname, './src/config'),
				'@/styles': resolve(__dirname, './src/styles'),
				'@/types': resolve(__dirname, './src/types'),
			},
		},

		// // CSS configuration
		css: {
			postcss: './postcss.config.js',
			devSourcemap: true,
		},

		// Build configuration
		build: {
			lib: {
				entry: {
					index: resolve(__dirname, 'src/index.ts'),
					'config/index': resolve(__dirname, 'src/config/index.ts'),
					'components/index': resolve(__dirname, 'src/components/index.ts'),
					'hooks/index': resolve(__dirname, 'src/hooks/index.ts'),
					'utils/index': resolve(__dirname, 'src/utils/index.ts'),
					'styles/index': resolve(__dirname, 'src/styles/index.ts'),
					'next/index': resolve(__dirname, 'src/middleware/index.ts'),
				},
				formats: ['es', 'cjs'],
				fileName: (format, entryName) => {
					const extension = format === 'es' ? 'js' : 'cjs';
					const formatDir = format === 'es' ? 'esm' : 'cjs';

					// Handle nested entry names (like config/index)
					if (entryName.includes('/')) {
						const [dir, file] = entryName.split('/');
						return `${formatDir}/${dir}/${file}.${extension}`;
					}

					return `${formatDir}/${entryName}.${extension}`;
				},
			},

			// Rollup options for advanced configuration
			rollupOptions: {
				// Externalize dependencies
				external: makeExternalPredicate([
					...external,
					...Object.keys(pkg.dependencies || {}),
				]),

				output: [
					// ESM build
					{
						format: 'es',
						dir: 'dist',
						entryFileNames: 'esm/[name].js',
						chunkFileNames: 'esm/chunks/[name]-[hash].js',
						assetFileNames: 'assets/[name][extname]',
						sourcemap: true,
						preserveModules: true,
						preserveModulesRoot: 'src',
						mangleProps: false,
						exports: 'named',
					},
					// CJS build
					{
						format: 'cjs',
						dir: 'dist',
						entryFileNames: 'cjs/[name].cjs',
						chunkFileNames: 'cjs/chunks/[name]-[hash].cjs',
						assetFileNames: 'assets/[name][extname]',
						sourcemap: true,
						preserveModules: true,
						preserveModulesRoot: 'src',
						exports: 'named',
						interop: 'auto',
					},
				],

				// Suppress warnings
				onwarn: (warning, warn) => {
					// Suppress certain warnings
					if (warning.code === 'THIS_IS_UNDEFINED') return;
					if (warning.code === 'CIRCULAR_DEPENDENCY') return;
					if (warning.code === 'UNUSED_EXTERNAL_IMPORT') return;
					if (warning.message?.includes('Use of eval')) return;

					warn(warning);
				},
			},

			// Additional build options
			sourcemap: true,
			minify: isProduction,
			target: 'es2020',

			// Copy assets
			copyPublicDir: false,

			// Emit CSS as separate file
			cssCodeSplit: true,

			// Build optimizations
			reportCompressedSize: isProduction,
			chunkSizeWarningLimit: 1000,
		},

		// Development server configuration
		server: {
			port: 3001,
			open: false,
			cors: true,
			hmr: {
				overlay: true,
			},
		},

		// Preview server configuration
		preview: {
			port: 3002,
			open: false,
			cors: true,
		},

		// Optimization
		optimizeDeps: {
			include: [
				'react',
				'react-dom',
				'react/jsx-runtime',
				'framer-motion',
				'clsx',
			],
			exclude: [
				'@frank-auth/client',
				'@frank-auth/sdk',
			],
		},

		// Environment variables
		define: {
			__DEV__: !isProduction,
			__PROD__: isProduction,
		},

		// ESBuild configuration
		esbuild: {
			logOverride: {'this-is-undefined-in-esm': 'silent'},
			target: 'es2020',
			format: 'esm',
			platform: 'browser',
			treeShaking: true,
			minifyIdentifiers: isProduction,
			minifySyntax: isProduction,
			minifyWhitespace: isProduction,
		},

		// Worker configuration
		worker: {
			format: 'es',
		},
	};
});