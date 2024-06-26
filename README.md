# @readme/ssri

[`ssri`](https://github.com/npm/ssri), short for Standard Subresource
Integrity, is a Node.js utility for parsing generating, and verifying [Subresource
Integrity](https://w3c.github.io/webappsec/specs/subresourceintegrity/) hashes.

[![Build](https://github.com/readmeio/ssri/workflows/CI/badge.svg)](https://github.com/readmeio/ssri/) [![](https://img.shields.io/npm/v/@readme/ssri)](https://npm.im/@readme/ssri)

## Install

`$ npm install --save @readme/ssri`

## Table of Contents

* [Example](#example)
* [Features](#features)
* [API](#api)
  * [`parse`](#parse)
  * [`create`](#create)
  * [`verify`](#verify)
* [Differences from `ssri`](#differences-from-ssri)

### Example

```javascript
const ssri = require('@readme/ssri')

const integrity = 'sha512-9KhgCRIx/AmzC8xqYJTZRrnO8OW2Pxyl2DIMZSBOr0oDvtEFyht3xpp71j/r/pAe1DM+JI/A+line3jUBgzQ7A==?foo'

// Parsing and serializing
const parsed = ssri.parse(integrity)
parsed.toString() // === integrity

// Sync data functions
ssri.create(fs.readFileSync('./my-file')) // === parsed
ssri.verify(fs.readFileSync('./my-file'), integrity) // => 'sha512'
```

### Features

* Parses and stringifies SRI strings.
* Generates SRI strings from raw data.
* Strict standard compliance.
* `?foo` metadata option support.
* Small footprint: no dependencies, concise implementation.
* Full test coverage.

### API

#### <a name="parse"></a> `> ssri.parse(sri) -> Integrity`

Parses an `sri` string into a `Hash` data structure.

```javascript
{
  source: 'sha512-9KhgCRIx/AmzC8xqYJTZRrnO8OW2Pxyl2DIMZSBOr0oDvtEFyht3xpp71j/r/pAe1DM+JI/A+line3jUBgzQ7A==?foo',
  digest: '9KhgCRIx/AmzC8xqYJTZRrnO8OW2Pxyl2DIMZSBOr0oDvtEFyht3xpp71j/r/pAe1DM+JI/A+line3jUBgzQ7A==',
  algorithm: 'sha512',
  options: ['foo']
}
```

##### Example

```javascript
ssri.parse('sha512-9KhgCRIx/AmzC8xqYJTZRrnO8OW2Pxyl2DIMZSBOr0oDvtEFyht3xpp71j/r/pAe1DM+JI/A+line3jUBgzQ7A==?foo') // -> Hash object
```

#### <a name="from-data"></a> `> ssri.create(data, [opts]) -> Integrity`

Creates an `Integrity` object from either string or `Buffer` data, calculating
all the requested hashes and adding any specified options to the object.

`opts.algorithm` determines which algorithm to generate a hash for. Result will
be contained within a `Hash` object. The default value for
`opts.algorithm` is `sha512`.

`opts.options` may optionally be passed in: it must be an array of option
strings that will be added to all generated integrity hashes generated by
`create`. This is a loosely-specified feature of SRIs, and currently has no
specified semantics besides being `?`-separated. Use at your own risk, and
probably avoid if your integrity strings are meant to be used with browsers.

##### Example

```javascript
const integrityObj = ssri.create('foobarbaz', {
  algorithm: 'sha256'
})
integrity.toString('\n')
// ->
// sha256-l981iLWj8kurw4UbNy8Lpxqdzd7UOxS50Glhv8FwfZ0=
```

#### <a name="verify"></a> `> ssri.verify(data, sri) -> Hash|false`

Verifies `data` integrity against an `sri` argument. `data` may be either a
`String` or a `Buffer`, and `sri` can be any subresource integrity
representation that [`ssri.parse`](#parse) can handle.

If verification succeeds, `verify` will return `true`, otherwise it will return
`false`.

##### Example

```javascript
const data = fs.readFileSync('index.js').toString()
ssri.verify(data, ssri.create(data)) // -> true
ssri.verify(data, 'sha256-l981iLWj8kurw4UbNy8Lpxqdzd7UOxS50Glhv8FwfZ0')
ssri.verify(data, 'sha1-BaDDigEST') // -> false
```

#### <a name="differences-from-ssri"></a> Differences from `ssri`

* TypeScript first.
* Streams are not supported.
* Zero non-`crypto` dependencies.
* Library offerings have been heavily paired down to only three methods.
* `checkData` has been renamed to `verify`.
  * `verify` now only returns a boolean.
* `fromData` has been renamed to to `create`.
  * Generating or parsing multiple integrity hashes is not supported.
* `ssri`'s `strict` mode is now the default and only mode.
* The `Integrity` class is no more and `parse`, `create` will generate a `Hash` object containing your single hash.
