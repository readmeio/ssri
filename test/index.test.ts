import crypto from 'crypto';
import fs from 'fs';

import { expect } from 'chai';

import * as ssri from '../src';

const TEST_DATA = fs.readFileSync(__filename);

function hash(data, algorithm) {
  return crypto.createHash(algorithm).update(data).digest('base64');
}

describe('ssri', function () {
  describe('#create', function () {
    it('should generate a sha512 hash object from Buffer data', function () {
      expect(ssri.create(TEST_DATA).toString()).to.equal(`sha512-${hash(TEST_DATA, 'sha512')}`);
    });

    it('should generate a sha512 hash object from String data', function () {
      expect(ssri.create(TEST_DATA.toString('utf8')).toString()).to.equal(`sha512-${hash(TEST_DATA, 'sha512')}`);
    });

    it('should generate a sha256 hash object with `opts.algorithm`', function () {
      expect(ssri.create(TEST_DATA, { algorithm: 'sha256' }).toString()).to.equal(
        `sha256-${hash(TEST_DATA, 'sha256')}`
      );
    });

    it('should be able to add options to a hash with `opts.options', function () {
      expect(
        ssri
          .create(TEST_DATA, {
            algorithm: 'sha256',
            options: ['foo', 'bar'],
          })
          .toString()
      ).to.equal(`sha256-${hash(TEST_DATA, 'sha256')}?foo?bar`);
    });

    it('should support transforming a Hash object into a JSON string with `JSON.stringify`', function () {
      expect(JSON.stringify(ssri.create(TEST_DATA))).to.equal(`"sha512-${hash(TEST_DATA, 'sha512')}"`);
    });
  });

  describe('#parse', function () {
    it('should parse an integrity string', function () {
      const sha = hash(TEST_DATA, 'sha512');
      const integrity = `sha512-${sha}`;
      expect(Object.fromEntries(Object.entries(ssri.parse(integrity)))).to.deep.equal({
        source: integrity,
        digest: sha,
        algorithm: 'sha512',
        options: [],
      });
    });

    it('should parse options from integrity string', function () {
      const sha = hash(TEST_DATA, 'sha512');
      const integrity = `sha512-${sha}?one?two?three`;
      expect(Object.fromEntries(Object.entries(ssri.parse(integrity)))).to.deep.equal({
        source: integrity,
        digest: sha,
        algorithm: 'sha512',
        options: ['one', 'two', 'three'],
      });
    });

    it('should omit unsupported algos', function () {
      const xxx = new Array(50).join('x');

      expect(Object.fromEntries(Object.entries(ssri.parse(`foo-${xxx}`)))).to.deep.equal({
        source: `foo-${xxx}`,
        algorithm: '',
        digest: '',
        options: [],
      });

      expect(Object.fromEntries(Object.entries(ssri.parse(`sha512-${xxx}`)))).to.deep.equal({
        source: `sha512-${xxx}`,
        algorithm: 'sha512',
        digest: xxx,
        options: [],
      });
    });

    it('should discard invalid format entries', function () {
      const missingDash = 'thisisbad';
      const missingAlgorithm = '-deadbeef';
      const missingDigest = 'sha512-';

      expect(ssri.parse(missingDash).toString()).to.be.empty;
      expect(ssri.parse(missingAlgorithm).toString()).to.be.empty;
      expect(ssri.parse(missingDigest).toString()).to.be.empty;
    });

    it('should trim whitespace from either end', function () {
      const integrity = `      sha512-${hash(TEST_DATA, 'sha512')}    `;
      expect(Object.fromEntries(Object.entries(ssri.parse(integrity)))).to.deep.equal({
        source: integrity.trim(),
        algorithm: 'sha512',
        digest: hash(TEST_DATA, 'sha512'),
        options: [],
      });
    });

    it('should discard hashes that dont abide by the spec', function () {
      const valid = `sha512-${hash(TEST_DATA, 'sha512')}`;
      const badAlgorithm = `sha1-${hash(TEST_DATA, 'sha1')}`;
      const badBase64 = 'sha512-@#$@%#$';
      const badOpts = `${valid}?\x01\x02`;

      expect(ssri.parse(badAlgorithm).toString()).to.be.empty;
      expect(ssri.parse(badBase64).toString()).to.be.empty;
      expect(ssri.parse(badOpts).toString()).to.be.empty;
    });

    it('should not allow weird stuff in sri', function () {
      const badInt = 'mdc2\u0000/../../../hello_what_am_I_doing_here-Juwtg9UFssfrRfwsXu+n/Q==';

      expect(ssri.parse(badInt).toString()).to.be.empty;
    });
  });

  describe('#verify', function () {
    let sri;

    before(function () {
      sri = ssri.parse(`sha512-${hash(TEST_DATA, 'sha512')}`);
    });

    it('should verify Buffer data', function () {
      expect(ssri.verify(TEST_DATA, sri)).to.be.true;
    });

    it('should verify String data', function () {
      expect(ssri.verify(TEST_DATA.toString('utf8'), sri)).to.be.true;
    });

    it('should return false when verification fails', function () {
      expect(ssri.verify('nope', sri)).to.be.false;
    });

    it('should return false on an invalid sri hash', function () {
      expect(ssri.verify('nope', 'sha512-nope')).to.be.false;
    });

    it('should return false on garbage sri input', function () {
      expect(ssri.verify('nope', 'garbage')).to.be.false;
    });

    it('should return false on empty sri input', function () {
      expect(ssri.verify('nope', '')).to.be.false;
    });
  });
});
