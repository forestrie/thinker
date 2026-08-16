// Flat config, shaped after mandate's (packages/apps/ui is the same Svelte 5 +
// Workers-TS mix). Root-only on purpose: flat config resolves plugins relative
// to the config file, so every lint devDependency lives in the root
// package.json and there is exactly one place to change a rule.
import path from 'node:path';
import { includeIgnoreFile } from '@eslint/compat';
import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import svelte from 'eslint-plugin-svelte';
import { defineConfig } from 'eslint/config';
import globals from 'globals';
import ts from 'typescript-eslint';
import svelteConfig from './apps/scribe-ui/svelte.config.js';

const gitignorePath = path.resolve(import.meta.dirname, '.gitignore');

export default defineConfig(
	includeIgnoreFile(gitignorePath),
	js.configs.recommended,
	ts.configs.recommended,
	svelte.configs.recommended,
	prettier,
	svelte.configs.prettier,
	{
		languageOptions: {
			// One global soup for the whole repo: the Workers code uses browser
			// globals (crypto, btoa, Request), scripts/*.mjs use node ones
			// (process, Buffer), the UI uses both. Per-file scoping buys nothing
			// when no-undef is off anyway.
			globals: { ...globals.browser, ...globals.node }
		},
		rules: {
			// typescript-eslint explicitly recommend disabling this on TS projects.
			// Here it is also what keeps the ambient Workers types (Env,
			// DurableObjectNamespace, ExportedHandler) from erroring.
			'no-undef': 'off',

			// `} catch {}` is a deliberate idiom in the live smoke scripts — the
			// failure genuinely has nothing to do. Every other empty block stays
			// an error.
			'no-empty': ['error', { allowEmptyCatch: true }],

			// Underscore = declared on purpose, unused on purpose. caughtErrors
			// is 'none' because typescript-eslint v8 defaults it to 'all', which
			// would fail on any `catch (err)` left deliberately unread.
			'@typescript-eslint/no-unused-vars': [
				'error',
				{ argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' }
			]
		}
	},
	{
		files: ['**/*.svelte', '**/*.svelte.ts', '**/*.svelte.js'],
		languageOptions: {
			parserOptions: {
				projectService: true,
				extraFileExtensions: ['.svelte'],
				parser: ts.parser,
				svelteConfig
			}
		},
		rules: {
			// `pnpm --filter scribe-ui check` (svelte-check) is the authority for
			// compiler diagnostics and a11y warnings. Surfacing them a second
			// time here only creates two places to silence the same finding.
			'svelte/valid-compile': 'off'
		}
	},
	{
		// Operator tooling: it prints, and it is meant to.
		files: ['scripts/**/*.mjs', '**/test/*-smoke.mjs'],
		rules: { 'no-console': 'off' }
	},
	{
		ignores: [
			'**/.svelte-kit/**',
			'**/.wrangler/**',
			'**/worker-configuration.d.ts',
			'**/test/.out/**',
			'.provision*/**'
		]
	}
);
