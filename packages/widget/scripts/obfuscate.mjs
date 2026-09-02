#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const JavaScriptObfuscator = require('javascript-obfuscator')

export const obfuscatorOptions = {
  compact: true,
  controlFlowFlattening: false,
  deadCodeInjection: false,
  debugProtection: false,
  disableConsoleOutput: false,
  identifierNamesGenerator: 'hexadecimal',
  renameGlobals: false,
  reservedNames: ['RGCheck', 'RavenGuardWidget', '__g__', '__RG__'],
  reservedStrings: ['./workers/sha256.js', './workers/pbkdf2.js'],
  selfDefending: false,
  splitStrings: false,
  stringArray: true,
  stringArrayCallsTransform: false,
  stringArrayEncoding: [],
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayWrappersCount: 1,
  stringArrayThreshold: 0.75,
  target: 'browser',
  transformObjectKeys: false,
  unicodeEscapeSequence: false,
}

export function obfuscateSource(code) {
  return JavaScriptObfuscator.obfuscate(code, obfuscatorOptions).getObfuscatedCode()
}

export function obfuscateFile(input, output) {
  const code = readFileSync(input, 'utf8')
  writeFileSync(output, obfuscateSource(code))
}

const self = fileURLToPath(import.meta.url)
if (process.argv[1] && resolve(process.argv[1]) === self) {
  const input = process.argv[2]
  const output = process.argv[3]
  if (!input || !output) {
    console.error('usage: obfuscate.mjs <input.js> <output.js>')
    process.exit(1)
  }
  obfuscateFile(input, output)
}
