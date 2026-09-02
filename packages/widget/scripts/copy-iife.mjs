#!/usr/bin/env node
import { copyFileSync, existsSync, unlinkSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { obfuscateFile } from './obfuscate.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const globalSrc = join(root, 'dist', 'w.global.js')
const dest = join(root, 'dist', 'w.js')
const npmDest = join(root, 'dist', 'ravenguard-widget.min.js')

if (existsSync(globalSrc)) {
  copyFileSync(globalSrc, dest)
  unlinkSync(globalSrc)
}

if (!existsSync(dest)) {
  console.error('missing IIFE output dist/w.js')
  process.exit(1)
}

obfuscateFile(dest, dest)
copyFileSync(dest, npmDest)
