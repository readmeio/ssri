import crypto from 'crypto';
import fs from 'fs';

import { test as tap } from 'tap';

import ssri from '../src';

const TEST_DATA = fs.readFileSync(__filename);

function hash(data: any, algorithm: string) {
  return crypto.createHash(algorithm).update(data).digest('base64');
}

tap('serializes Integrity-likes', t => {
  const sriLike = {
    sha512: [
      {
        digest: 'foo',
        algorithm: 'sha512',
        options: ['ayy', 'woo'],
      },
      {
        digest: 'bar',
        algorithm: 'sha512',
      },
    ],
    whirlpool: [
      {
        digest: 'wut',
        algorithm: 'whirlpool',
      },
    ],
  };
  t.equal(
    ssri.stringify(sriLike),
    'sha512-foo?ayy?woo sha512-bar whirlpool-wut',
    'stringification contains correct data for all entries'
  );
  t.end();
});

tap('serializes Hash-likes', t => {
  const sriLike = {
    digest: 'foo',
    algorithm: 'sha512',
  };
  t.equal(ssri.stringify(sriLike), 'sha512-foo', 'serialization has correct data');
  t.end();
});

tap('serialized plain strings into a valid parsed version', t => {
  const sri = ' \tsha512-foo?bar    \n\n\nsha1-nope\r';
  t.equal(ssri.stringify(sri), 'sha512-foo?bar sha1-nope', 'cleaned-up string with identical contents generated');
  t.end();
});

tap('accepts a separator opt', t => {
  const sriLike = {
    sha512: [
      {
        algorithm: 'sha512',
        digest: 'foo',
      },
      {
        algorithm: 'sha512',
        digest: 'bar',
      },
    ],
  };
  t.equal(ssri.stringify(sriLike, { sep: '\n' }), 'sha512-foo\nsha512-bar');
  t.equal(ssri.stringify(sriLike, { sep: ' | ' }), 'sha512-foo | sha512-bar');
  t.end();
});

tap('support strict serialization', t => {
  const sriLike = {
    // only sha256, sha384, and sha512 are allowed by the spec
    sha1: [
      {
        algorithm: 'sha1',
        digest: 'feh',
      },
    ],
    sha256: [
      {
        algorithm: 'sha256',
        // Must be valid base64
        digest: 'wut!!!??!!??!',
      },
      {
        algorithm: 'sha256',
        digest: hash(TEST_DATA, 'sha256'),
        options: ['foo'],
      },
    ],
    sha512: [
      {
        algorithm: 'sha512',
        digest: hash(TEST_DATA, 'sha512'),
        // Options must use VCHAR
        options: ['\x01'],
      },
    ],
  };
  t.equal(
    ssri.stringify(sriLike, { strict: true }),
    `sha256-${hash(TEST_DATA, 'sha256')}?foo`,
    'entries that do not conform to strict spec interpretation removed'
  );
  t.equal(
    ssri.stringify(
      'sha512-WrLorGiX4iEWOOOaJSiCrmDIamA47exH+Bz7tVwIPb4sCU8w4iNqGCqYuspMMeU5pgz/sU7koP5u8W3RCUojGw== sha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=',
      { sep: ' \r|\n\t', strict: true }
    ),

    'sha512-WrLorGiX4iEWOOOaJSiCrmDIamA47exH+Bz7tVwIPb4sCU8w4iNqGCqYuspMMeU5pgz/sU7koP5u8W3RCUojGw== \r \n\tsha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=',
    'strict mode replaces non-whitespace characters in separator with space'
  );
  t.end();
});
