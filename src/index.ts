import crypto from 'node:crypto';

const SPEC_ALGORITHMS = ['sha256', 'sha384', 'sha512'];

// TODO: this should really be a hardcoded list of algorithms we support,
// rather than [a-z0-9].
const BASE64_REGEX = /^[a-z0-9+/]+(?:=?=?)$/i;
const STRICT_SRI_REGEX = /^([a-z0-9]+)-([A-Za-z0-9+/=]{44,88})(\?[\x21-\x7E]*)?$/;
const VCHAR_REGEX = /^[\x21-\x7E]+$/;

const getOptString = (options: string[]) => (!options || !options.length ? '' : `?${options.join('?')}`);

export interface Options {
  algorithm?: string;
  options?: string[];
}

class Hash {
  source: string;

  digest: string;

  algorithm: string;

  options: string[];

  constructor(hash: string) {
    this.source = hash.trim();

    // set default values so that we make V8 happy to
    // always see a familiar object template.
    this.digest = '';
    this.algorithm = '';
    this.options = [];

    // 3.1. Integrity metadata (called "Hash" by ssri)
    // https://w3c.github.io/webappsec-subresource-integrity/#integrity-metadata-description
    const match = this.source.match(STRICT_SRI_REGEX);
    if (!match) {
      return;
    } else if (!SPEC_ALGORITHMS.some(a => a === match[1])) {
      return;
    }

    this.algorithm = match[1];
    this.digest = match[2];

    const rawOpts = match[3];
    if (rawOpts) {
      this.options = rawOpts.slice(1).split('?');
    }
  }

  toJSON() {
    return this.toString();
  }

  toString() {
    if (
      !(
        // The spec has very restricted productions for algorithms.
        // https://www.w3.org/TR/CSP2/#source-list-syntax
        (
          SPEC_ALGORITHMS.some(x => x === this.algorithm) &&
          // Usually, if someone insists on using a "different" base64, we
          // leave it as-is, since there's multiple standards, and the
          // specified is not a URL-safe variant.
          // https://www.w3.org/TR/CSP2/#base64_value
          this.digest.match(BASE64_REGEX) &&
          // Option syntax is strictly visual chars.
          // https://w3c.github.io/webappsec-subresource-integrity/#grammardef-option-expression
          // https://tools.ietf.org/html/rfc5234#appendix-B.1
          this.options.every(opt => opt.match(VCHAR_REGEX))
        )
      )
    ) {
      return '';
    }

    const options = this.options?.length ? `?${this.options.join('?')}` : '';
    return `${this.algorithm}-${this.digest}${options}`;
  }
}

export function parse(sri: string) {
  if (!sri) {
    return null;
  }

  return new Hash(sri);
}

export function create(data: Buffer | string, opts: Options = {}) {
  const algorithm = opts.algorithm || 'sha512';
  const optString = getOptString(opts.options || []);

  const digest = crypto.createHash(algorithm).update(data).digest('base64');
  return new Hash(`${algorithm}-${digest}${optString}`);
}

export function verify(data: Buffer | string, sri: Hash | string) {
  try {
    let currSri: Hash | string = sri;
    if (typeof sri === 'object' && sri instanceof Hash) {
      // eslint-disable-next-line no-param-reassign
      currSri = sri.toString();
    }

    // eslint-disable-next-line no-param-reassign
    currSri = parse(currSri as string);
    if (!currSri) {
      return false;
    }

    const algorithm = currSri.algorithm;
    const digest = crypto.createHash(algorithm).update(data).digest('base64');
    const newSri = parse(`${algorithm}-${digest}`);

    return sri.toString() === newSri.toString();
  } catch {
    // `crypto.createHash()` will throw errors if `algorithm` is invalid which will happen if we're
    // supplied with an invalid or corrupt hash. Since we just want this method to only verify if
    // two given hashes match, we don't want to throw if that happens.
    return false;
  }
}
