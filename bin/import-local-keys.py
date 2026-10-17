#!/usr/bin/env python3
# SmartPGP : import locally generated RSA keys and certificates into the card.
# Reads key material from a local directory (never prints it) and imports:
#   - private keys (PUT DATA 3FFF, CRT format: e/p/q/PQ/DP1/DQ1/n)
#   - PGP v4 fingerprints and generation dates
#   - X.509 certificates (cardholder certificate DO 7F21)
#
# Usage: ./import-local-keys.py --keys ../keys [--reader 1] [--verify]
# PIN source: environment variable SMARTPGP_ADMIN_PIN, or the applet default.

import argparse
import hashlib
import os
import sys

from smartcard.System import readers
from cryptography import x509
from cryptography.hazmat.primitives import serialization

DEFAULT_ADMIN_PIN = "12345678"  # applet factory default (see Constants.java)

ROLES = {
    # role: (CRT tag for key import, fingerprint DO, generation date DO,
    #        SELECT DATA occurrence for certificate DO)
    'sig': (0xB6, 0x00C7, 0x00CE, 0x02),
    'dec': (0xB8, 0x00C8, 0x00CF, 0x01),
    'aut': (0xA4, 0x00C9, 0x00D0, 0x00),
}

SELECT_APPLET = [0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00]
SELECT_DATA_CERT = [0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21]


class CardError(Exception):
    pass


def transmit(conn, apdu, what):
    data, sw1, sw2 = conn.transmit(list(apdu))
    if (sw1, sw2) != (0x90, 0x00):
        raise CardError("%s failed: %02X %02X" % (what, sw1, sw2))
    return data


def get_data(conn, p1, p2):
    data, sw1, sw2 = conn.transmit([0x00, 0xCA, p1, p2, 0x00])
    while sw1 == 0x61:
        more, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
        data = data + more
    if (sw1, sw2) != (0x90, 0x00):
        raise CardError("GET DATA %02X%02X failed: %02X %02X" % (p1, p2, sw1, sw2))
    return data


def put_data(conn, ins, p1, p2, data, what):
    """PUT DATA with command chaining (255-byte chunks)."""
    data = list(data)
    off = 0
    total = len(data)
    while off < total:
        chunk = data[off:off + 255]
        off += 255
        cla = 0x10 if off < total else 0x00
        apdu = [cla, ins, p1, p2, len(chunk)] + chunk
        transmit(conn, apdu, "%s (chunk)" % what)


def der_len(n):
    if n > 0xFF:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    if n > 0x7F:
        return bytes([0x81, n & 0xFF])
    return bytes([n & 0xFF])


def pad_int(v, ln):
    return v.to_bytes((v.bit_length() + 7) // 8, 'big').rjust(ln, b'\x00')


def build_key_blob(priv, crt_tag):
    """OpenPGP key import DO (4D) with RSA CRT components."""
    pn = priv.private_numbers()
    n = pn.public_numbers.n
    e = pn.public_numbers.e
    e_b = pad_int(e, 3)      # attributes require a 17-bit (3-byte) exponent
    p = pad_int(pn.p, 128)
    q = pad_int(pn.q, 128)
    pq = pad_int(pn.iqmp, 128)    # 1/q mod p  -> setPQ
    dp1 = pad_int(pn.dmp1, 128)   # d mod (p-1) -> setDP1
    dq1 = pad_int(pn.dmq1, 128)   # d mod (q-1) -> setDQ1
    n_b = pad_int(n, 256)
    parts = [(0x91, e_b), (0x92, p), (0x93, q), (0x94, pq),
             (0x95, dp1), (0x96, dq1), (0x97, n_b)]
    tmpl = b''.join(bytes([t]) + der_len(len(v)) for t, v in parts)
    blob = b''.join(v for _, v in parts)
    body = (bytes([crt_tag, 0x00]) +
            b'\x7f\x48' + der_len(len(tmpl)) + tmpl +
            b'\x5f\x48' + der_len(len(blob)) + blob)
    return b'\x4d' + der_len(len(body)) + body


def pgp_fingerprint(n, e, created):
    """OpenPGP v4 fingerprint: SHA-1 over 0x99 || len || pubkey packet body."""
    def mpi(v):
        bl = v.bit_length()
        return bl.to_bytes(2, 'big') + v.to_bytes((bl + 7) // 8, 'big')
    body = (b'\x04' + int(created).to_bytes(4, 'big') + b'\x01' +
            mpi(n) + mpi(e))
    return hashlib.sha1(b'\x99' + len(body).to_bytes(2, 'big') + body).digest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--keys', required=True, help='directory with <role>.key.pem / <role>.cert.der')
    ap.add_argument('--reader', type=int, default=1, help='PC/SC reader index (default 1)')
    ap.add_argument('--verify', action='store_true', help='read certificates back and compare')
    args = ap.parse_args()

    kdir = args.keys
    passfile = os.path.join(kdir, 'BACKUP_PASSPHRASE.txt')
    with open(passfile, 'rb') as f:
        passphrase = f.read().strip()
    admin_pin = os.environ.get('SMARTPGP_ADMIN_PIN', DEFAULT_ADMIN_PIN).encode()

    conn = readers()[args.reader].createConnection()
    conn.connect()
    transmit(conn, SELECT_APPLET, 'SELECT applet')
    transmit(conn, [0x00, 0x20, 0x00, 0x83, len(admin_pin)] + list(admin_pin),
             'VERIFY admin PIN')
    print('Connected to reader %d, admin PIN verified.' % args.reader)

    manifest = ['# SmartPGP local key backup manifest (public information only)']

    for role, (crt_tag, fp_tag, date_tag, occ) in ROLES.items():
        with open(os.path.join(kdir, '%s.key.pem' % role), 'rb') as f:
            priv = serialization.load_pem_private_key(f.read(), password=passphrase)
        with open(os.path.join(kdir, '%s.cert.der' % role), 'rb') as f:
            cert_der = f.read()
        cert = x509.load_der_x509_certificate(cert_der)

        pn = priv.private_numbers()
        if pn.public_numbers.n.bit_length() != 2048 or pn.public_numbers.e != 65537:
            raise SystemExit('%s: key is not RSA-2048 with e=65537' % role)

        nb = getattr(cert, 'not_valid_before_utc', None) or cert.not_valid_before
        created = int(nb.timestamp())

        # 1. private key
        blob = build_key_blob(priv, crt_tag)
        put_data(conn, 0xDB, 0x3F, 0xFF, blob, 'import %s key' % role)

        # 2. fingerprint + generation date
        fp = pgp_fingerprint(pn.public_numbers.n, pn.public_numbers.e, created)
        put_data(conn, 0xDA, (fp_tag >> 8) & 0xFF, fp_tag & 0xFF, fp, '%s fingerprint' % role)
        put_data(conn, 0xDA, (date_tag >> 8) & 0xFF, date_tag & 0xFF,
                 int(created).to_bytes(4, 'big'), '%s generation date' % role)

        # 3. certificate
        transmit(conn, [0x00, 0xA5, occ, 0x04, len(SELECT_DATA_CERT)] + SELECT_DATA_CERT,
                 'SELECT DATA %s cert' % role)
        put_data(conn, 0xDA, 0x7F, 0x21, cert_der, '%s certificate' % role)

        fp_hex = fp.hex().upper()
        fp_pretty = ' '.join(fp_hex[i:i + 4] for i in range(0, 40, 4))
        cert_sha = hashlib.sha256(cert_der).hexdigest()
        print('%s: key+cert imported, %d bytes cert, fingerprint %s'
              % (role.upper(), len(cert_der), fp_pretty))

        manifest += [
            '',
            '[%s]' % role,
            'subject       : %s' % cert.subject.rfc4514_string(),
            'serial        : %s' % cert.serial_number,
            'validity       : %s .. %s' % (nb.isoformat(),
                                          (getattr(cert, 'not_valid_after_utc', None) or
                                           cert.not_valid_after).isoformat()),
            'cert sha256   : %s' % cert_sha,
            'pgp fingerprint: %s' % fp_hex,
        ]

        if args.verify:
            transmit(conn, [0x00, 0xA5, occ, 0x04, len(SELECT_DATA_CERT)] + SELECT_DATA_CERT,
                     'SELECT DATA %s cert' % role)
            oncard = bytes(get_data(conn, 0x7F, 0x21))
            status = 'OK' if oncard == cert_der else 'MISMATCH'
            print('    read-back certificate: %s (%d bytes, sha256 %s)'
                  % (status, len(oncard), hashlib.sha256(oncard).hexdigest()))

    mpath = os.path.join(kdir, 'MANIFEST.txt')
    if os.path.exists(mpath):
        os.chmod(mpath, 0o600)
    with open(mpath, 'w') as f:
        f.write('\n'.join(manifest) + '\n')
    os.chmod(mpath, 0o400)
    print('Manifest written to %s' % mpath)


if __name__ == '__main__':
    main()
